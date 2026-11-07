//! Read-only Linux server telemetry over an existing authenticated SSH channel.
//! No shell command contains user input. CPU usage uses counter deltas between
//! polls, so the first poll reports unknown rather than a fabricated percentage.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use linscp_proto::ssh::SshConnection;
use linscp_types::{
    MonitorCpu, MonitorCpuCore, MonitorCpuThread, MonitorDisk, MonitorGpu,
    MonitorMemory, MonitorSample, MonitorSnapshot,
};
use serde_json::Value;

pub const MAX_HOSTS: usize = 32;
pub const DEFAULT_INTERVAL_SECS: f64 = 5.0;
pub const DEFAULT_TIMEOUT_SECS: f64 = 10.0;
pub const MAX_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_CORES: usize = 4096;
const MAX_DEVICES: usize = 256;
const MARKER: &str = "__LINSCP_MONITOR_";

/// Fixed, non-mutating probe. Optional vendor failures do not fail Linux stats.
/// Marker lines let parsers keep empty/error sections separate without trusting
/// a command's exit status (the last optional GPU tool may not be installed).
pub const PROBE_COMMAND: &str = concat!(
    "LC_ALL=C; export LC_ALL; ",
    "printf '\\n__LINSCP_MONITOR_STAT\\n'; cat /proc/stat 2>/dev/null; ",
    "printf '\\n__LINSCP_MONITOR_CPU\\n'; lscpu 2>/dev/null; ",
    "printf '\\n__LINSCP_MONITOR_TOPOLOGY\\n'; lscpu -p=CPU,SOCKET,CORE 2>/dev/null; ",
    "printf '\\n__LINSCP_MONITOR_MEMORY\\n'; cat /proc/meminfo 2>/dev/null; ",
    "printf '\\n__LINSCP_MONITOR_DISK\\n'; df -Pk 2>/dev/null; ",
    "printf '\\n__LINSCP_MONITOR_HOST\\n'; hostname 2>/dev/null; hostname -I 2>/dev/null; ",
    "printf '\\n__LINSCP_MONITOR_UPTIME\\n'; cat /proc/uptime /proc/loadavg 2>/dev/null; ",
    "printf '\\n__LINSCP_MONITOR_NVIDIA\\n'; ",
    "if command -v nvidia-smi >/dev/null 2>&1; then ",
    "nvidia-smi --query-gpu=index,name,memory.total,memory.used,utilization.gpu,power.draw,power.limit,temperature.gpu,temperature.gpu.tlimit,driver_version,pcie.link.gen.current,pcie.link.width.current --format=csv,noheader,nounits 2>/dev/null || ",
    "nvidia-smi --query-gpu=index,name,memory.total,memory.used,utilization.gpu,power.draw,power.limit,temperature.gpu,driver_version,pcie.link.gen.current,pcie.link.width.current --format=csv,noheader,nounits 2>/dev/null; fi; ",
    "printf '\\n__LINSCP_MONITOR_CUDA\\n'; if command -v nvidia-smi >/dev/null 2>&1; then nvidia-smi 2>/dev/null; fi; ",
    "printf '\\n__LINSCP_MONITOR_AMD_STATIC\\n'; if command -v amd-smi >/dev/null 2>&1; then amd-smi static --json 2>/dev/null; fi; ",
    "printf '\\n__LINSCP_MONITOR_AMD_METRIC\\n'; if command -v amd-smi >/dev/null 2>&1; then amd-smi metric --usage --power --temperature --mem-usage --pcie --json 2>/dev/null; ",
    "elif command -v rocm-smi >/dev/null 2>&1; then rocm-smi --showproductname --showmeminfo vram --showuse --showtemp --showpower --showmaxpower --showdriverversion --json 2>/dev/null; fi; ",
    "printf '\\n__LINSCP_MONITOR_END\\n'; true\n",
);

pub fn validate_timeout(value: Option<&Value>) -> Result<Duration, String> {
    let seconds = match value {
        None => DEFAULT_TIMEOUT_SECS,
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        _ => return Err("Monitor timeout must be a number of seconds.".into()),
    };
    if !seconds.is_finite() || !(0.1..=30.0).contains(&seconds) {
        return Err("Monitor timeout must be between 0.1 and 30 seconds.".into());
    }
    Ok(Duration::from_secs_f64(seconds))
}

#[derive(Default)]
struct MonitorRegistry {
    hosts: BTreeMap<u64, Arc<tokio::sync::Mutex<MonitorState>>>,
}

#[derive(Default)]
struct MonitorState {
    connection: Option<Weak<SshConnection>>,
    counters: BTreeMap<u32, CpuTicks>,
    aggregate: Option<CpuTicks>,
}

/// Per-tab state is held across await, but the registry lock is never held
/// across await. A reconnect resets counters; a closed tab is pruned explicitly.
#[derive(Clone, Default)]
pub struct Monitors {
    inner: Arc<Mutex<MonitorRegistry>>,
}

impl Monitors {
    pub fn forget(&self, tab: u64) {
        self.inner.lock().expect("monitor registry").hosts.remove(&tab);
    }

    pub fn retain(&self, live: &BTreeSet<u64>) {
        self.inner.lock().expect("monitor registry").hosts.retain(|id, _| live.contains(id));
    }

    pub async fn sample(
        &self,
        tab: u64,
        name: &str,
        host: &str,
        port: u16,
        protocol: &str,
        ssh: Option<Arc<SshConnection>>,
        connected: bool,
        timeout: Duration,
    ) -> MonitorSample {
        let start = Instant::now();
        let mut sample = MonitorSample {
            tab, name: name.to_string(), host: host.to_string(), port,
            protocol: protocol.to_string(), status: "ok".into(),
            sampled_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
            latency_ms: 0, error: String::new(), snapshot: None,
        };
        let Some(ssh) = ssh else {
            sample.status = if connected { "unsupported" } else { "disconnected" }.into();
            sample.error = if connected {
                "Monitoring needs an SSH, SFTP or SCP session.".into()
            } else {
                "This server is disconnected. Reconnect its session before monitoring.".into()
            };
            sample.sampled_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
            return sample;
        };
        let state = self.inner.lock().expect("monitor registry").hosts.entry(tab).or_default().clone();
        let Ok(mut state) = state.try_lock() else {
            sample.status = "busy".into();
            sample.error = "A monitor sample is already running for this server.".into();
            return sample;
        };
        if !state.connection.as_ref().and_then(Weak::upgrade).is_some_and(|old| Arc::ptr_eq(&old, &ssh)) {
            *state = MonitorState { connection: Some(Arc::downgrade(&ssh)), ..Default::default() };
        }
        match ssh.exec_command_bounded(PROBE_COMMAND, timeout, MAX_OUTPUT_BYTES).await {
            Ok(output) if output.exit_code == Some(0) => {
                match parse_snapshot(&String::from_utf8_lossy(&output.stdout), &mut state) {
                    Ok(snapshot) => sample.snapshot = Some(snapshot),
                    Err(error) => { sample.status = "error".into(); sample.error = error; }
                }
            }
            Ok(output) => {
                state.counters.clear();
                state.aggregate = None;
                sample.status = "error".into();
                sample.error = format!("The Linux monitoring probe failed (exit {:?}).", output.exit_code);
            }
            Err(error) => {
                state.counters.clear();
                state.aggregate = None;
                sample.status = "error".into();
                sample.error = error.to_string();
            }
        }
        sample.latency_ms = start.elapsed().as_millis() as u64;
        sample
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct CpuTicks { total: u64, idle: u64 }

fn cpu_ticks(fields: &[&str]) -> Option<CpuTicks> {
    // guest/guest_nice are already included in user/nice on Linux.
    let values = fields.get(1..9)?.iter().map(|v| v.parse::<u64>().ok()).collect::<Option<Vec<_>>>()?;
    let total = values.iter().try_fold(0u64, |a, b| a.checked_add(*b))?;
    Some(CpuTicks { total, idle: values[3].checked_add(values[4])? })
}

fn delta_percent(old: Option<CpuTicks>, new: CpuTicks) -> Option<f64> {
    let old = old?;
    let total = new.total.checked_sub(old.total)?;
    let idle = new.idle.checked_sub(old.idle)?;
    if total == 0 || idle > total { return None; }
    Some(((total - idle) as f64 * 100.0 / total as f64).clamp(0.0, 100.0))
}

fn sections(output: &str) -> BTreeMap<String, String> {
    let mut result = BTreeMap::<String, String>::new();
    let mut current = String::new();
    for line in output.lines() {
        if let Some(name) = line.trim().strip_prefix(MARKER) {
            current = name.to_string();
            result.entry(current.clone()).or_default();
        } else if !current.is_empty() {
            let text = result.entry(current.clone()).or_default();
            // Bound each parsed section even within the overall exec limit.
            if text.len() < MAX_OUTPUT_BYTES { text.push_str(line); text.push('\n'); }
        }
    }
    result
}

fn parse_snapshot(output: &str, state: &mut MonitorState) -> Result<MonitorSnapshot, String> {
    let sections = sections(output);
    let get = |key: &str| sections.get(key).map(String::as_str).unwrap_or("");
    if !get("END").trim().is_empty() || !sections.contains_key("END") {
        return Err("The monitoring probe returned incomplete output.".into());
    }
    let mut snapshot = MonitorSnapshot::default();
    let mut counters = BTreeMap::new();
    let mut aggregate = None;
    for line in get("STAT").lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let Some(ticks) = cpu_ticks(&fields) else { continue };
        if fields.first() == Some(&"cpu") { aggregate = Some(ticks); }
        else if let Some(id) = fields.first().and_then(|s| s.strip_prefix("cpu")).and_then(|s| s.parse::<u32>().ok()) {
            if counters.len() < MAX_CORES { counters.insert(id, ticks); }
        }
    }
    if counters.is_empty() {
        return Err("Linux /proc/stat CPU counters are unavailable or invalid.".into());
    }
    snapshot.cpu = parse_cpu(get("CPU"), get("TOPOLOGY"), &counters, &state.counters, aggregate, state.aggregate);
    state.counters = counters;
    state.aggregate = aggregate;
    snapshot.memory = parse_memory(get("MEMORY"));
    snapshot.disks = parse_disks(get("DISK"));
    let mut host_lines = get("HOST").lines().map(str::trim).filter(|s| !s.is_empty());
    snapshot.hostname = host_lines.next().unwrap_or("").chars().take(253).collect();
    snapshot.primary_ip = host_lines.next().and_then(|s| s.split_whitespace().next()).unwrap_or("").chars().take(45).collect();
    let uptime = get("UPTIME").lines().filter_map(|line| line.split_whitespace().next()).collect::<Vec<_>>();
    snapshot.uptime_seconds = uptime.first().and_then(|s| s.parse::<f64>().ok()).filter(|n| n.is_finite() && *n >= 0.0);
    snapshot.load_average = get("UPTIME").lines().nth(1).into_iter().flat_map(|s| s.split_whitespace().take(3)).filter_map(|s| s.parse::<f64>().ok()).filter(|n| n.is_finite() && *n >= 0.0).collect();
    snapshot.gpus = parse_nvidia(get("NVIDIA"));
    snapshot.cuda_version = parse_cuda(get("CUDA"));
    let amd = parse_amd(get("AMD_STATIC"), get("AMD_METRIC"));
    if snapshot.gpus.is_empty() { snapshot.gpus = amd; }
    else { snapshot.gpus.extend(amd); }
    if snapshot.memory.is_none() { snapshot.warnings.push("RAM telemetry is unavailable.".into()); }
    if snapshot.disks.is_empty() { snapshot.warnings.push("Disk telemetry is unavailable.".into()); }
    if snapshot.gpus.is_empty() { snapshot.warnings.push("No GPU telemetry: install/vendor-enable nvidia-smi, amd-smi or rocm-smi, or this server has no supported GPU.".into()); }
    Ok(snapshot)
}

fn parse_cpu(info: &str, topology: &str, new: &BTreeMap<u32, CpuTicks>, old: &BTreeMap<u32, CpuTicks>, aggregate: Option<CpuTicks>, old_aggregate: Option<CpuTicks>) -> MonitorCpu {
    let sum = |map: &BTreeMap<u32, CpuTicks>| -> Option<CpuTicks> {
        Some(CpuTicks {
            total: map.values().try_fold(0u64, |n, t| n.checked_add(t.total))?,
            idle: map.values().try_fold(0u64, |n, t| n.checked_add(t.idle))?,
        })
    };
    let (new_total, old_total) = if aggregate.is_some() { (aggregate, old_aggregate) } else { (sum(new), sum(old)) };
    let mut cpu = MonitorCpu {
        logical_count: new.len() as u32,
        percent: new_total.and_then(|new| delta_percent(old_total, new)),
        ..Default::default()
    };
    for line in info.lines() {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim() == "Model name" { cpu.model = value.trim().chars().take(256).collect(); }
        }
    }
    let mut mapping = BTreeMap::new();
    for line in topology.lines().filter(|l| !l.starts_with('#')) {
        let fields = line.split(',').map(str::trim).collect::<Vec<_>>();
        if let (Some(Ok(id)), Some(Ok(socket)), Some(Ok(core))) = (fields.first().map(|s| s.parse::<u32>()), fields.get(1).map(|s| s.parse::<u32>()), fields.get(2).map(|s| s.parse::<u32>())) {
            mapping.insert(id, (Some(socket), core));
        }
    }
    let mut groups = BTreeMap::<(Option<u32>, u32), Vec<MonitorCpuThread>>::new();
    for (id, ticks) in new {
        let (socket, core) = mapping.get(id).copied().unwrap_or((None, *id));
        groups.entry((socket, core)).or_default().push(MonitorCpuThread { id: *id, percent: delta_percent(old.get(id).copied(), *ticks) });
    }
    cpu.cores = groups.into_iter().map(|((socket, core), threads)| MonitorCpuCore { socket, core, threads }).collect();
    cpu
}

fn parse_memory(text: &str) -> Option<MonitorMemory> {
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() >= 2 && fields.get(2).unwrap_or(&"kB") == &"kB" {
            if let Ok(n) = fields[1].parse::<u64>() { values.insert(fields[0].trim_end_matches(':'), n.checked_mul(1024)?); }
        }
    }
    let total = *values.get("MemTotal")?;
    if total == 0 { return None; }
    let available = values.get("MemAvailable").copied().unwrap_or_else(|| values.get("MemFree").copied().unwrap_or(0).saturating_add(values.get("Buffers").copied().unwrap_or(0)).saturating_add(values.get("Cached").copied().unwrap_or(0))).min(total);
    let used = total.saturating_sub(available);
    Some(MonitorMemory { total_bytes: total, used_bytes: used, available_bytes: available, percent: used as f64 * 100.0 / total as f64 })
}

fn df_unescape(text: &str) -> String {
    text.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\")
}

fn parse_disks(text: &str) -> Vec<MonitorDisk> {
    let mut disks = Vec::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        if line.starts_with("Filesystem") { continue; }
        let mut fields = line.split_whitespace().collect::<Vec<_>>();
        // POSIX df -P may wrap a long device name onto its own line.
        if fields.len() == 1 {
            if let Some(next) = lines.next() { fields.extend(next.split_whitespace()); }
        }
        if fields.len() < 6 { continue; }
        let device = df_unescape(fields[0]);
        // Pseudo filesystems are not disk capacity. Keep real /dev devices,
        // ZFS/btrfs pool names and network mounts; do not filter by '/dev/' only.
        if matches!(device.as_str(), "tmpfs" | "devtmpfs" | "udev" | "none" | "proc" | "sysfs" | "cgroup" | "cgroup2" | "overlay" | "squashfs" | "efivarfs" | "securityfs" | "debugfs" | "tracefs") || device.starts_with("/dev/loop") { continue; }
        let Ok(total_kib) = fields[1].parse::<u64>() else { continue };
        let Ok(used_kib) = fields[2].parse::<u64>() else { continue };
        let Ok(available_kib) = fields[3].parse::<u64>() else { continue };
        let percent = fields[4].trim_end_matches('%').parse::<f64>().ok();
        let (Some(total), Some(used), Some(available), Some(percent)) = (total_kib.checked_mul(1024), used_kib.checked_mul(1024), available_kib.checked_mul(1024), percent) else { continue };
        if total == 0 || !percent.is_finite() { continue; }
        disks.push(MonitorDisk { device, mount: df_unescape(&fields[5..].join(" ")), total_bytes: total, used_bytes: used, available_bytes: available, percent: percent.clamp(0.0, 100.0) });
        if disks.len() >= MAX_DEVICES { break; }
    }
    disks
}

fn number(value: &str) -> Option<f64> {
    let value = value.trim();
    if value.is_empty() || value.starts_with('[') || matches!(value.to_ascii_lowercase().as_str(), "n/a" | "[n/a]" | "not supported" | "unknown" | "nan") { return None; }
    value.parse::<f64>().ok().filter(|n| n.is_finite() && *n >= 0.0)
}
fn percent(value: &str) -> Option<f64> { number(value).map(|n| n.clamp(0.0, 100.0)) }
fn mib(value: &str) -> Option<u64> { number(value).map(|n| (n * 1024.0 * 1024.0) as u64) }
fn uint(value: &str) -> Option<u32> { number(value).map(|n| n as u32) }
fn json_number(value: Option<&Value>) -> Option<f64> {
    match value? { Value::Number(n) => n.as_f64(), Value::String(s) => number(s), Value::Object(_) => json_number(value?.get("value")), _ => None }.filter(|n| n.is_finite() && *n >= 0.0)
}
fn json_percent(value: Option<&Value>) -> Option<f64> { json_number(value).map(|n| n.clamp(0.0, 100.0)) }
fn json_memory(value: Option<&Value>) -> Option<u64> {
    let n = json_number(value)?;
    let unit = value.and_then(|v| v.get("unit")).and_then(Value::as_str).unwrap_or("MB");
    let scale = match unit.to_ascii_uppercase().as_str() { "B" => 1.0, "KB" => 1000.0, "KIB" => 1024.0, "GB" => 1e9, "GIB" => 1024.0 * 1024.0 * 1024.0, "TB" => 1e12, "TIB" => 1024.0_f64.powi(4), _ => 1024.0 * 1024.0 };
    Some((n * scale) as u64)
}
fn json_text(value: Option<&Value>) -> String { value.and_then(Value::as_str).unwrap_or("").chars().take(256).collect() }

fn parse_nvidia(text: &str) -> Vec<MonitorGpu> {
    let mut gpus = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let fields = line.split(',').map(str::trim).collect::<Vec<_>>();
        // New drivers include tlimit; older drivers omit that one field.
        if fields.len() != 11 && fields.len() != 12 { continue; }
        let extended = fields.len() == 12;
        let Some(index) = uint(fields[0]) else { continue };
        gpus.push(MonitorGpu {
            index, vendor: "NVIDIA".into(), name: fields[1].chars().take(256).collect(),
            percent: percent(fields[4]), memory_used_bytes: mib(fields[3]), memory_total_bytes: mib(fields[2]),
            power_watts: number(fields[5]), power_limit_watts: number(fields[6]),
            temperature_c: number(fields[7]), temperature_limit_c: extended.then(|| number(fields[8])).flatten(),
            temperature_sensor: "GPU".into(), driver: fields[if extended { 9 } else { 8 }].to_string(),
            pcie_generation: uint(fields[if extended { 10 } else { 9 }]), pcie_width: uint(fields[if extended { 11 } else { 10 }]),
        });
        if gpus.len() >= MAX_DEVICES { break; }
    }
    gpus
}

fn parse_cuda(text: &str) -> String {
    text.lines().find_map(|line| line.split("CUDA Version:").nth(1)).map(|s| s.split_whitespace().next().unwrap_or("").trim_matches('|').chars().take(32).collect()).unwrap_or_default()
}

/// amd-smi has used both a top-level array and {gpu_data: [...]}; some
/// versions key records by GPU number. Match records by ID, never array offset.
fn amd_records(text: &str) -> BTreeMap<u32, Value> {
    let Ok(value) = serde_json::from_str::<Value>(text.trim()) else { return BTreeMap::new() };
    let records = value.get("gpu_data").unwrap_or(&value);
    let mut result = BTreeMap::new();
    let mut insert = |record: &Value, fallback: u32| {
        if let Some(id) = record.get("gpu").and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok()).or(Some(fallback)) {
            if result.len() < MAX_DEVICES { result.insert(id, record.clone()); }
        }
    };
    match records {
        Value::Array(items) => for (i, record) in items.iter().enumerate() { insert(record, i as u32); },
        Value::Object(items) => for (i, (key, record)) in items.iter().enumerate() { insert(record, key.parse().unwrap_or(i as u32)); },
        _ => {}
    }
    result
}

fn pcie_generation(speed: Option<f64>) -> Option<u32> {
    match speed? { s if (s - 2.5).abs() < 0.01 => Some(1), s if (s - 5.0).abs() < 0.01 => Some(2), s if (s - 8.0).abs() < 0.01 => Some(3), s if (s - 16.0).abs() < 0.01 => Some(4), s if (s - 32.0).abs() < 0.01 => Some(5), s if (s - 64.0).abs() < 0.01 => Some(6), _ => None }
}

fn parse_amd(static_text: &str, metric_text: &str) -> Vec<MonitorGpu> {
    let statics = amd_records(static_text);
    let metrics = amd_records(metric_text);
    if !statics.is_empty() || !metrics.is_empty() {
        let ids = statics.keys().chain(metrics.keys()).copied().collect::<BTreeSet<_>>();
        return ids.into_iter().map(|id| {
            let stat = statics.get(id);
            let metric = metrics.get(id);
            let field = |root: Option<&Value>, a: &str, b: &str| root.and_then(|v| v.get(a)).and_then(|v| v.get(b));
            let temp = metric.and_then(|v| v.get("temperature"));
            let hotspot = json_number(temp.and_then(|v| v.get("hotspot")));
            let limit = stat.and_then(|v| v.get("limit"));
            MonitorGpu {
                index: id, vendor: "AMD".into(), name: json_text(field(stat, "asic", "market_name")),
                percent: json_percent(field(metric, "usage", "gfx_activity")),
                memory_used_bytes: json_memory(field(metric, "mem_usage", "used_vram")),
                memory_total_bytes: json_memory(field(metric, "mem_usage", "total_vram")).or_else(|| json_memory(field(stat, "vram", "size"))),
                power_watts: json_number(field(metric, "power", "socket_power")),
                power_limit_watts: json_number(limit.and_then(|v| v.get("ppt0")).and_then(|v| v.get("socket_power_limit"))),
                temperature_c: hotspot.or_else(|| json_number(temp.and_then(|v| v.get("edge")))),
                temperature_limit_c: json_number(limit.and_then(|v| v.get(if hotspot.is_some() { "slowdown_hotspot_temperature" } else { "slowdown_edge_temperature" }))),
                temperature_sensor: if hotspot.is_some() { "Hotspot" } else { "Edge" }.into(),
                driver: json_text(field(stat, "driver", "version")),
                pcie_generation: pcie_generation(json_number(field(metric, "pcie", "speed"))),
                pcie_width: uint(&json_number(field(metric, "pcie", "width")).map(|n| n.to_string()).unwrap_or_default()),
            }
        }).collect();
    }
    parse_rocm(metric_text)
}

fn parse_rocm(text: &str) -> Vec<MonitorGpu> {
    let Ok(Value::Object(records)) = serde_json::from_str::<Value>(text.trim()) else { return Vec::new() };
    let mut result = Vec::new();
    for (key, record) in records.iter().filter(|(key, _)| key.starts_with("card")).take(MAX_DEVICES) {
        let Some(index) = key.trim_start_matches("card").parse::<u32>().ok() else { continue };
        let field = |prefix: &str| record.as_object().and_then(|obj| obj.iter().find(|(k, _)| k.starts_with(prefix))).and_then(|(_, v)| v.as_str()).and_then(number);
        let hotspot = field("Temperature (Sensor hotspot)");
        let bytes = |prefix: &str| record.as_object().and_then(|obj| obj.iter().find(|(k, _)| k.starts_with(prefix))).and_then(|(_, v)| v.as_str()).and_then(|s| s.parse::<u64>().ok());
        let text_field = |prefix: &str| record.as_object().and_then(|obj| obj.iter().find(|(k, _)| k.starts_with(prefix))).and_then(|(_, v)| v.as_str()).unwrap_or("").chars().take(256).collect();
        result.push(MonitorGpu {
            index, vendor: "AMD".into(), name: text_field("Card series"),
            percent: field("GPU use (%)").map(|n| n.clamp(0.0, 100.0)),
            memory_used_bytes: bytes("VRAM Total Used Memory (B)"), memory_total_bytes: bytes("VRAM Total Memory (B)"),
            power_watts: field("Average Graphics Package Power (W)").or_else(|| field("Current Graphics Package Power (W)")),
            power_limit_watts: field("Max Graphics Package Power (W)"),
            temperature_c: hotspot.or_else(|| field("Temperature (Sensor edge)")), temperature_limit_c: None,
            temperature_sensor: if hotspot.is_some() { "Hotspot" } else { "Edge" }.into(),
            driver: text_field("Driver version"), pcie_generation: None, pcie_width: None,
        });
    }
    result.sort_by_key(|gpu| gpu.index);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAT: &str = "cpu 100 0 100 800 0 0 0 0\n\ncpu0 50 0 50 400 0 0 0 0\n\ncpu1 50 0 50 400 0 0 0 0\nintr 1\n";
    const STAT2: &str = "cpu 200 0 200 1600 0 0 0 0\n\ncpu0 150 0 50 800 0 0 0 0\n\ncpu1 50 0 150 800 0 0 0 0\n";
    fn probe(stat: &str, nvidia: &str) -> String {
        format!("{MARKER}STAT\n{stat}\n{MARKER}CPU\nModel name: Test CPU\nCPU(s): 2\n{MARKER}TOPOLOGY\n0,0,0\n1,0,0\n{MARKER}MEMORY\nMemTotal: 1024 kB\nMemAvailable: 256 kB\n{MARKER}DISK\nFilesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 1000 400 600 40% /data\\040disk\ntmpfs 100 0 100 0% /run\n{MARKER}HOST\nworker\n10.0.0.2 192.168.1.2\n{MARKER}UPTIME\n123.4 50.0\n0.25 0.5 1.0 1/20 33\n{MARKER}NVIDIA\n{nvidia}\n{MARKER}END\n")
    }

    #[test]
    fn cpu_deltas_topology_and_reconnect_reset() {
        let mut state = MonitorState::default();
        let first = parse_snapshot(&probe(STAT, ""), &mut state).unwrap();
        assert_eq!(first.cpu.percent, None);
        assert_eq!(first.cpu.cores.len(), 1);
        assert_eq!(first.cpu.cores[0].threads.len(), 2);
        let second = parse_snapshot(&probe(STAT2, ""), &mut state).unwrap();
        assert_eq!(second.cpu.percent, Some(20.0));
        assert_eq!(second.cpu.cores[0].threads[0].percent, Some(20.0));
        assert_eq!(second.cpu.cores[0].threads[1].percent, Some(20.0));
        assert_eq!(second.memory.as_ref().unwrap().used_bytes, 768 * 1024);
        assert_eq!(second.disks[0].mount, "/data disk");
        assert_eq!(second.primary_ip, "10.0.0.2");
        assert!(parse_snapshot(&probe(STAT, ""), &mut MonitorState::default()).unwrap().cpu.percent.is_none());
    }

    #[test]
    fn nvidia_old_and_new_driver_fields_do_not_shift() {
        let old = "0,Test GPU,24576,1024,42,80.5,300,55,550.54,4,16";
        let new = "0,Test GPU,24576,1024,42,80.5,300,55,90,550.54,4,16";
        for text in [old, new] {
            let gpu = &parse_nvidia(text)[0];
            assert_eq!(gpu.driver, "550.54");
            assert_eq!(gpu.pcie_generation, Some(4));
            assert_eq!(gpu.pcie_width, Some(16));
            assert_eq!(gpu.memory_total_bytes, Some(24 * 1024 * 1024 * 1024));
        }
        assert_eq!(parse_nvidia(new)[0].temperature_limit_c, Some(90.0));
        assert_eq!(parse_nvidia(old)[0].temperature_limit_c, None);
        assert_eq!(parse_nvidia("0,X,N/A,10,50,70,300,50,90,driver,1,4")[0].memory_total_bytes, None);
        assert_eq!(parse_cuda("| NVIDIA-SMI 550 Driver Version: 550 CUDA Version: 12.4 |"), "12.4");
    }

    #[test]
    fn amd_records_match_by_id_and_use_real_limits() {
        let stat = r#"{"gpu_data":[{"gpu":1,"asic":{"market_name":"AMD GPU"},"driver":{"version":"6.8"},"limit":{"ppt0":{"socket_power_limit":{"value":250,"unit":"W"}},"slowdown_hotspot_temperature":{"value":95,"unit":"C"}}}]}"#;
        let metric = r#"{"gpu_data":[{"gpu":0,"usage":{"gfx_activity":{"value":20}}},{"gpu":1,"usage":{"gfx_activity":{"value":80}},"mem_usage":{"total_vram":{"value":16384,"unit":"MB"},"used_vram":{"value":1024,"unit":"MB"}},"power":{"socket_power":{"value":120,"unit":"W"}},"temperature":{"hotspot":{"value":70,"unit":"C"}},"pcie":{"width":16,"speed":{"value":16,"unit":"GT/s"}}}]}"#;
        let gpus = parse_amd(stat, metric);
        assert_eq!(gpus.len(), 2);
        assert_eq!(gpus[1].name, "AMD GPU");
        assert_eq!(gpus[1].percent, Some(80.0));
        assert_eq!(gpus[1].power_limit_watts, Some(250.0));
        assert_eq!(gpus[1].temperature_limit_c, Some(95.0));
        assert_eq!(gpus[1].memory_total_bytes, Some(16 * 1024 * 1024 * 1024));
        assert_eq!(gpus[0].power_limit_watts, None);
        assert_eq!(gpus[1].pcie_generation, Some(4));
        assert_eq!(gpus[1].pcie_width, Some(16));
    }

    #[test]
    fn rocm_json_uses_bytes_not_usage_as_capacity() {
        let text = r#"{"card0":{"Card series":"Radeon","GPU use (%)":"25","VRAM Total Memory (B)":"8589934592","VRAM Total Used Memory (B)":"1073741824","Temperature (Sensor edge) (C)":"50","Average Graphics Package Power (W)":"45","Max Graphics Package Power (W)":"200"}}"#;
        let gpu = &parse_rocm(text)[0];
        assert_eq!(gpu.memory_total_bytes, Some(8 * 1024 * 1024 * 1024));
        assert_eq!(gpu.memory_used_bytes, Some(1024 * 1024 * 1024));
        assert_eq!(gpu.power_limit_watts, Some(200.0));
        assert!(parse_rocm("not json").is_empty());
    }

    #[test]
    fn malformed_missing_and_wrapped_output_are_not_success() {
        let mut state = MonitorState::default();
        assert!(parse_snapshot("", &mut state).is_err());
        assert!(parse_snapshot(&probe("garbage\n", ""), &mut state).is_err());
        let wrapped = format!("{MARKER}STAT\n{STAT}\n{MARKER}MEMORY\nMemTotal: 100 kB\nMemAvailable: 50 kB\n{MARKER}DISK\n/dev/mapper/very-long\n100 25 75 25% /srv\n{MARKER}END\n");
        let snapshot = parse_snapshot(&wrapped, &mut state).unwrap();
        assert_eq!(snapshot.disks[0].device, "/dev/mapper/very-long");
        assert!(snapshot.memory.is_some());
        let overflow = "cpu 18446744073709551615 1 0 0 0 0 0 0\n";
        assert!(parse_snapshot(&probe(overflow, ""), &mut state).is_err());
    }

    #[test]
    fn timeout_and_probe_safety() {
        for value in [json!(0), json!(-1), json!(31), json!("5"), json!(null)] {
            assert!(validate_timeout(Some(&value)).is_err());
        }
        assert_eq!(validate_timeout(Some(&json!(0.1))).unwrap(), Duration::from_millis(100));
        assert_eq!(validate_timeout(None).unwrap(), Duration::from_secs(10));
        assert!(!PROBE_COMMAND.contains("sudo"));
        assert!(!PROBE_COMMAND.contains("rm "));
    }
}
