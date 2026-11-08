//! Linux server telemetry over an existing authenticated SSH channel.
//! The built-in probe is fixed and read-only. User-approved custom metrics are
//! isolated in subshells and delimited by a per-poll nonce. CPU and network
//! rates use counter deltas, so the first poll reports unknown rather than a
//! fabricated percentage.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use linscp_platform::write_private_file_atomic;
use linscp_proto::ssh::SshConnection;
use linscp_types::{
    MonitorCpu, MonitorCpuCore, MonitorCpuThread, MonitorCustomMetric, MonitorCustomReading,
    MonitorDisk, MonitorGpu, MonitorHostConfig, MonitorMemory, MonitorMetricDisplay,
    MonitorMetricParse, MonitorNetwork, MonitorSample, MonitorSettingsDocument, MonitorSnapshot,
    MonitorSwap,
};
use rand::Rng;
use serde_json::Value;

pub const MAX_HOSTS: usize = 32;
pub const DEFAULT_INTERVAL_SECS: f64 = 5.0;
pub const DEFAULT_TIMEOUT_SECS: f64 = 10.0;
pub const MAX_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_CORES: usize = 4096;
const MAX_DEVICES: usize = 256;
const MARKER: &str = "__LINSCP_MONITOR_";
const CUSTOM_BEGIN: &str = "__LINSCP_MONITOR_CUSTOM_BEGIN_";
const CUSTOM_END: &str = "__LINSCP_MONITOR_CUSTOM_END_";
pub const MAX_CUSTOM_METRICS: usize = 8;
const MAX_CUSTOM_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_CUSTOM_TEXT_CHARS: usize = 4096;

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
    "printf '\\n__LINSCP_MONITOR_NETWORK\\n'; cat /proc/net/dev 2>/dev/null; ",
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

pub fn config_key_for_session(site: Option<&str>, host: &str, port: u16) -> String {
    match site.filter(|name| !name.is_empty()) {
        Some(name) => format!("site:{name}"),
        // deliberately omit the login name: monitor host lists stay credential-free
        None => format!("ssh:{host}:{port}"),
    }
}

pub fn load_settings(config_root: &Path) -> MonitorSettingsDocument {
    let path = config_root.join("monitor.json");
    let Ok(raw) = std::fs::read_to_string(path) else { return MonitorSettingsDocument::default() };
    serde_json::from_str::<MonitorSettingsDocument>(&raw)
        .ok()
        .and_then(|doc| validate_settings(doc).ok())
        .unwrap_or_default()
}

pub fn save_settings(config_root: &Path, doc: MonitorSettingsDocument) -> Result<MonitorSettingsDocument, String> {
    let doc = validate_settings(doc)?;
    let mut rendered = serde_json::to_vec_pretty(&doc).map_err(|e| e.to_string())?;
    rendered.push(b'\n');
    write_private_file_atomic(&config_root.join("monitor.json"), &rendered).map_err(|e| e.to_string())?;
    Ok(doc)
}

pub fn validate_settings(mut doc: MonitorSettingsDocument) -> Result<MonitorSettingsDocument, String> {
    if doc.version != 1 { return Err("Unsupported monitor settings version.".into()); }
    let s = &doc.settings;
    if !s.interval_secs.is_finite() || !(0.1..=60.0).contains(&s.interval_secs) {
        return Err("Monitor interval must be between 0.1 and 60 seconds.".into());
    }
    if !s.connect_timeout_secs.is_finite() || !(1.0..=60.0).contains(&s.connect_timeout_secs) {
        return Err("Monitor connect timeout must be between 1 and 60 seconds.".into());
    }
    if !s.poll_timeout_secs.is_finite() || !(0.1..=30.0).contains(&s.poll_timeout_secs) {
        return Err("Monitor poll timeout must be between 0.1 and 30 seconds.".into());
    }
    if !(1..=100).contains(&s.outage_threshold) { return Err("Outage threshold must be between 1 and 100 polls.".into()); }
    if s.beep_cooldown_secs > 600 { return Err("Beep cooldown must be between 0 and 600 seconds.".into()); }
    if doc.hosts.len() > 256 { return Err("Too many monitored host configurations.".into()); }
    for (key, host) in &mut doc.hosts {
        if key.is_empty() || key.len() > 256 || key.chars().any(char::is_control) {
            return Err("Invalid monitor host key.".into());
        }
        let mut seen = BTreeSet::new();
        host.enabled_metrics.retain(|metric| matches!(metric.as_str(), "cpu" | "mem" | "swap" | "disk" | "load" | "net" | "gpu") && seen.insert(metric.clone()));
        if host.custom_metrics.len() > MAX_CUSTOM_METRICS {
            return Err(format!("At most {MAX_CUSTOM_METRICS} custom metrics are allowed per server."));
        }
        let mut ids = BTreeSet::new();
        for metric in &mut host.custom_metrics {
            metric.id = metric.id.trim().to_string();
            metric.name = metric.name.trim().chars().take(80).collect();
            metric.command = metric.command.replace('\r', "").trim().to_string();
            metric.unit = metric.unit.trim().chars().take(16).collect();
            if metric.id.is_empty() || metric.id.len() > 64 || !metric.id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') || !ids.insert(metric.id.clone()) {
                return Err("Custom metric IDs must be unique, 1-64 ASCII letters, digits, '-' or '_'.".into());
            }
            if metric.name.is_empty() { return Err("A custom metric name is required.".into()); }
            if metric.command.is_empty() || metric.command.len() > 4096 || metric.command.contains('\0') {
                return Err("A custom metric command must be 1-4096 characters and contain no NUL.".into());
            }
            if metric.unit.chars().any(char::is_control) { return Err("Custom metric units cannot contain control characters.".into()); }
            if metric.parse == MonitorMetricParse::Regex {
                let pattern = metric.regex.as_deref().unwrap_or("").trim();
                if pattern.is_empty() || pattern.len() > 256 { return Err("A regex custom metric needs a pattern of 1-256 characters.".into()); }
                regex::Regex::new(pattern).map_err(|e| format!("Invalid custom metric regex: {e}"))?;
                metric.regex = Some(pattern.to_string());
            } else {
                metric.regex = None;
            }
            if metric.parse == MonitorMetricParse::Text { metric.display = MonitorMetricDisplay::Text; }
        }
    }
    Ok(doc)
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

fn probe_nonce() -> String {
    let mut rng = rand::thread_rng();
    format!("{:016x}{:016x}", rng.gen::<u64>(), rng.gen::<u64>())
}

pub fn build_probe_command(customs: &[MonitorCustomMetric], nonce: &str) -> String {
    let mut script = String::from(PROBE_COMMAND);
    for (idx, metric) in customs.iter().take(MAX_CUSTOM_METRICS).enumerate() {
        let command = metric.command.replace('\r', "");
        script.push_str(&format!(
            "\nprintf '\\n%s\\n' '{CUSTOM_BEGIN}{nonce}_{idx}'\n(\n{command}\n) 2>/dev/null | command dd bs=1024 count={} 2>/dev/null\nprintf '\\n%s\\n' '{CUSTOM_END}{nonce}_{idx}'\n",
            MAX_CUSTOM_OUTPUT_BYTES / 1024,
        ));
    }
    script
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
    network: Option<NetworkCounters>,
    last_sample_ms: Option<u64>,
    consecutive_failures: u32,
    outage_since_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct NetworkCounters { rx: u64, tx: u64 }

pub struct MonitorRequest<'a> {
    pub tab: u64,
    pub key: &'a str,
    pub name: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub protocol: &'a str,
    pub ssh: Option<Arc<SshConnection>>,
    pub connected: bool,
    pub timeout: Duration,
    pub custom_metrics: &'a [MonitorCustomMetric],
    pub outage_threshold: u32,
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

    pub async fn sample(&self, request: MonitorRequest<'_>) -> MonitorSample {
        let start = Instant::now();
        let sampled_at = now_ms();
        let mut sample = MonitorSample {
            tab: request.tab, key: request.key.to_string(), name: request.name.to_string(),
            host: request.host.to_string(), port: request.port, protocol: request.protocol.to_string(),
            status: "ok".into(), sampled_at, latency_ms: 0, error: String::new(), snapshot: None,
            consecutive_failures: 0, outage_since_ms: None, outage: false, outage_started: false, recovered: false,
        };
        let state = self.inner.lock().expect("monitor registry").hosts.entry(request.tab).or_default().clone();
        let Ok(mut state) = state.try_lock() else {
            sample.status = "busy".into();
            sample.error = "A monitor sample is already running for this server.".into();
            return sample;
        };
        let Some(ssh) = request.ssh else {
            sample.status = if request.connected { "unsupported" } else { "disconnected" }.into();
            sample.error = if request.connected {
                "Monitoring needs an SSH, SFTP or SCP session.".into()
            } else {
                "This server is disconnected. Reconnect its session before monitoring.".into()
            };
            if !request.connected { record_failure(&mut state, &mut sample, request.outage_threshold, sampled_at); }
            sample.sampled_at = now_ms();
            return sample;
        };
        if !state.connection.as_ref().and_then(Weak::upgrade).is_some_and(|old| Arc::ptr_eq(&old, &ssh)) {
            *state = MonitorState { connection: Some(Arc::downgrade(&ssh)), ..Default::default() };
        }
        let nonce = probe_nonce();
        let command = build_probe_command(request.custom_metrics, &nonce);
        match ssh.exec_command_bounded(&command, request.timeout, MAX_OUTPUT_BYTES).await {
            Ok(output) if output.exit_code == Some(0) => {
                match parse_snapshot_with_customs(&String::from_utf8_lossy(&output.stdout), &mut state, request.custom_metrics, &nonce, sampled_at) {
                    Ok(snapshot) => {
                        sample.snapshot = Some(snapshot);
                        record_recovery(&mut state, &mut sample, request.outage_threshold);
                    }
                    Err(error) => {
                        reset_rates(&mut state);
                        record_failure(&mut state, &mut sample, request.outage_threshold, sampled_at);
                        sample.status = "error".into(); sample.error = error;
                    }
                }
            }
            Ok(output) => {
                reset_rates(&mut state);
                record_failure(&mut state, &mut sample, request.outage_threshold, sampled_at);
                sample.status = "error".into();
                sample.error = format!("The Linux monitoring probe failed (exit {:?}).", output.exit_code);
            }
            Err(error) => {
                reset_rates(&mut state);
                record_failure(&mut state, &mut sample, request.outage_threshold, sampled_at);
                sample.status = "error".into();
                sample.error = error.to_string();
            }
        }
        sample.latency_ms = start.elapsed().as_millis() as u64;
        sample
    }
}

fn reset_rates(state: &mut MonitorState) {
    state.counters.clear();
    state.aggregate = None;
    state.network = None;
    state.last_sample_ms = None;
}

fn record_failure(state: &mut MonitorState, sample: &mut MonitorSample, threshold: u32, at_ms: u64) {
    let previous = state.consecutive_failures;
    let threshold = threshold.max(1);
    state.consecutive_failures = previous.saturating_add(1);
    let since = *state.outage_since_ms.get_or_insert(at_ms);
    sample.consecutive_failures = state.consecutive_failures;
    sample.outage_since_ms = Some(since);
    sample.outage = state.consecutive_failures >= threshold;
    sample.outage_started = previous < threshold && state.consecutive_failures >= threshold;
}

fn record_recovery(state: &mut MonitorState, sample: &mut MonitorSample, threshold: u32) {
    sample.recovered = state.outage_since_ms.is_some() && state.consecutive_failures >= threshold.max(1);
    state.consecutive_failures = 0;
    state.outage_since_ms = None;
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

fn split_custom_sections<'a>(output: &'a str, nonce: &str, customs: &[MonitorCustomMetric]) -> (&'a str, BTreeMap<usize, String>) {
    let begin_prefix = format!("{CUSTOM_BEGIN}{nonce}_");
    let end_prefix = format!("{CUSTOM_END}{nonce}_");
    let base_end = output.find(&begin_prefix).unwrap_or(output.len());
    let base = &output[..base_end];
    let mut blocks = BTreeMap::new();
    let mut next = 0usize;
    let mut open: Option<usize> = None;
    let mut current = String::new();
    for line in output[base_end..].lines() {
        let trimmed = line.trim();
        if open.is_none() {
            if let Some(rest) = trimmed.strip_prefix(&begin_prefix) {
                if next < customs.len() && rest.parse::<usize>().ok() == Some(next) {
                    open = Some(next); current.clear(); continue;
                }
            }
        } else if let Some(rest) = trimmed.strip_prefix(&end_prefix) {
            if open.is_some_and(|idx| rest.parse::<usize>().ok() == Some(idx)) {
                blocks.insert(open.expect("open block"), current.trim().to_string());
                open = None; next += 1; current.clear(); continue;
            }
        }
        if open.is_some() {
            if !current.is_empty() { current.push('\n'); }
            if current.len() < MAX_CUSTOM_OUTPUT_BYTES { current.push_str(line); }
        }
    }
    (base, blocks)
}

fn parse_snapshot(output: &str, state: &mut MonitorState) -> Result<MonitorSnapshot, String> {
    parse_snapshot_with_customs(output, state, &[], "", now_ms())
}

fn parse_snapshot_with_customs(output: &str, state: &mut MonitorState, customs: &[MonitorCustomMetric], nonce: &str, sampled_at: u64) -> Result<MonitorSnapshot, String> {
    let (builtin_output, custom_blocks) = split_custom_sections(output, nonce, customs);
    let sections = sections(builtin_output);
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
    snapshot.swap = parse_swap(get("MEMORY"));
    snapshot.network = parse_network(get("NETWORK"), state, sampled_at);
    state.last_sample_ms = Some(sampled_at);
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
    snapshot.custom = parse_custom_metrics(customs, &custom_blocks);
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

fn parse_swap(text: &str) -> Option<MonitorSwap> {
    let mut total = None;
    let mut free = None;
    for line in text.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() >= 2 && fields.get(2).unwrap_or(&"kB") == &"kB" {
            let Ok(kib) = fields[1].parse::<u64>() else { continue };
            let Some(bytes) = kib.checked_mul(1024) else { continue };
            match fields[0].trim_end_matches(':') {
                "SwapTotal" => total = Some(bytes),
                "SwapFree" => free = Some(bytes),
                _ => {}
            }
        }
    }
    let total = total?;
    let free = free.unwrap_or(0).min(total);
    let used = total.saturating_sub(free);
    Some(MonitorSwap { total_bytes: total, used_bytes: used, free_bytes: free,
        percent: if total == 0 { 0.0 } else { used as f64 * 100.0 / total as f64 } })
}

fn parse_network(text: &str, state: &mut MonitorState, sampled_at: u64) -> Option<MonitorNetwork> {
    let mut counters = NetworkCounters::default();
    let mut saw_interface = false;
    for line in text.lines() {
        let Some((iface, rest)) = line.split_once(':') else { continue };
        let iface = iface.trim();
        if iface.is_empty() || iface == "lo" { continue; }
        let fields = rest.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 10 { continue; }
        let (Ok(rx), Ok(tx)) = (fields[0].parse::<u64>(), fields[8].parse::<u64>()) else { continue };
        counters.rx = counters.rx.saturating_add(rx);
        counters.tx = counters.tx.saturating_add(tx);
        saw_interface = true;
    }
    if !saw_interface { return None; }
    let elapsed = state.last_sample_ms.and_then(|old| sampled_at.checked_sub(old)).filter(|ms| *ms > 0);
    let previous = state.network;
    let rate = |old: u64, new: u64| -> Option<f64> {
        let ms = elapsed?;
        if new < old { return None; }
        Some((new - old) as f64 * 1000.0 / ms as f64)
    };
    let network = MonitorNetwork {
        rx_bytes_total: counters.rx, tx_bytes_total: counters.tx,
        rx_bytes_per_sec: previous.and_then(|old| rate(old.rx, counters.rx)),
        tx_bytes_per_sec: previous.and_then(|old| rate(old.tx, counters.tx)),
    };
    state.network = Some(counters);
    Some(network)
}

fn extract_number(text: &str) -> Option<f64> {
    let mut token = String::new();
    let mut started = false;
    for c in text.chars() {
        if !started {
            if c == '-' || c == '+' || c.is_ascii_digit() { started = true; token.push(c); }
        } else if c.is_ascii_digit() || c == '.' {
            token.push(c);
        } else { break; }
    }
    token.parse::<f64>().ok().filter(|n| n.is_finite())
}

fn parse_custom_metrics(customs: &[MonitorCustomMetric], blocks: &BTreeMap<usize, String>) -> Vec<MonitorCustomReading> {
    customs.iter().enumerate().map(|(idx, metric)| {
        let mut reading = MonitorCustomReading {
            id: metric.id.clone(), name: metric.name.clone(), parse: metric.parse,
            display: metric.display, unit: metric.unit.clone(), value: None,
            text: String::new(), error: String::new(),
        };
        let Some(raw) = blocks.get(&idx) else {
            reading.error = "The custom command returned no complete output block.".into();
            return reading;
        };
        let raw = raw.trim();
        match metric.parse {
            MonitorMetricParse::Number => match extract_number(raw) {
                Some(value) => reading.value = Some(value),
                None => reading.error = "No finite numeric token in custom command output.".into(),
            },
            MonitorMetricParse::Regex => {
                let pattern = metric.regex.as_deref().unwrap_or("");
                match regex::Regex::new(pattern) {
                    Ok(re) => match re.captures(raw).and_then(|caps| caps.get(1).or_else(|| caps.get(0))) {
                        Some(capture) => match capture.as_str().trim().parse::<f64>().ok().filter(|n| n.is_finite()) {
                            Some(value) => reading.value = Some(value),
                            None => reading.error = "The regex capture is not a finite number.".into(),
                        },
                        None => reading.error = "The custom metric regex did not match.".into(),
                    },
                    Err(error) => reading.error = format!("Invalid custom metric regex: {error}"),
                }
            }
            MonitorMetricParse::Text => {
                reading.text = raw.chars().take(MAX_CUSTOM_TEXT_CHARS).collect();
                if raw.chars().count() > MAX_CUSTOM_TEXT_CHARS { reading.error = "Custom text output was truncated for display.".into(); }
            }
        }
        reading
    }).collect()
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
            let stat = statics.get(&id);
            let metric = metrics.get(&id);
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
    fn swap_and_network_rates_need_two_samples_and_reset_safely() {
        let mut state = MonitorState::default();
        let base = probe(STAT, "");
        let with_net = |rx: u64, tx: u64| base.replace(
            &format!("{MARKER}MEMORY\nMemTotal: 1024 kB\nMemAvailable: 256 kB\n"),
            &format!("{MARKER}MEMORY\nMemTotal: 1024 kB\nMemAvailable: 256 kB\nSwapTotal: 100 kB\nSwapFree: 25 kB\n{MARKER}NETWORK\nInter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo: 100 1 0 0 0 0 0 0 100 1 0 0 0 0 0 0\n  eth0: {rx} 1 0 0 0 0 0 0 {tx} 1 0 0 0 0 0 0\n"),
        );
        let first = parse_snapshot_with_customs(&with_net(1000, 2000), &mut state, &[], "", 1000).unwrap();
        assert_eq!(first.swap.as_ref().unwrap().percent, 75.0);
        assert_eq!(first.network.as_ref().unwrap().rx_bytes_per_sec, None);
        let second = parse_snapshot_with_customs(&with_net(3000, 2500), &mut state, &[], "", 2000).unwrap();
        assert_eq!(second.network.as_ref().unwrap().rx_bytes_per_sec, Some(2000.0));
        assert_eq!(second.network.as_ref().unwrap().tx_bytes_per_sec, Some(500.0));
        let reset = parse_snapshot_with_customs(&with_net(10, 20), &mut state, &[], "", 3000).unwrap();
        assert_eq!(reset.network.as_ref().unwrap().rx_bytes_per_sec, None);
    }

    #[test]
    fn custom_blocks_are_nonced_and_cannot_spoof_builtin_readings() {
        let customs = vec![
            MonitorCustomMetric { id: "n".into(), name: "Number".into(), command: "printf 42".into(),
                parse: MonitorMetricParse::Number, regex: None, display: MonitorMetricDisplay::Sparkline, unit: "%".into() },
            MonitorCustomMetric { id: "r".into(), name: "Regex".into(), command: "printf 'load: 1.25'".into(),
                parse: MonitorMetricParse::Regex, regex: Some("load: ([0-9.]+)".into()), display: MonitorMetricDisplay::BigNumber, unit: String::new() },
            MonitorCustomMetric { id: "t".into(), name: "Text".into(), command: "printf ok".into(),
                parse: MonitorMetricParse::Text, regex: None, display: MonitorMetricDisplay::Text, unit: String::new() },
        ];
        let nonce = "testnonce";
        let script = build_probe_command(&customs, nonce);
        assert!(script.contains("__LINSCP_MONITOR_CUSTOM_BEGIN_testnonce_0"));
        assert!(script.contains("command dd bs=1024 count=64"));
        assert!(!script.contains("sudo"));
        let output = format!("{}\n{CUSTOM_BEGIN}{nonce}_0\n42\n{CUSTOM_END}{nonce}_0\n{CUSTOM_BEGIN}{nonce}_1\nload: 1.25\n{CUSTOM_END}{nonce}_1\n{CUSTOM_BEGIN}{nonce}_2\nok\n{CUSTOM_END}{nonce}_2\n{MARKER}MEMORY\nMemTotal: 1 kB\nMemAvailable: 0 kB\n", probe(STAT, ""));
        let snapshot = parse_snapshot_with_customs(&output, &mut MonitorState::default(), &customs, nonce, 1).unwrap();
        assert_eq!(snapshot.memory.as_ref().unwrap().total_bytes, 1024 * 1024);
        assert_eq!(snapshot.custom[0].value, Some(42.0));
        assert_eq!(snapshot.custom[1].value, Some(1.25));
        assert_eq!(snapshot.custom[2].text, "ok");
        let fake = format!("{}\n{CUSTOM_BEGIN}{nonce}_0\n{MARKER}MEMORY\nMemTotal: 1 kB\nMemAvailable: 0 kB\n{MARKER}END\n", probe(STAT, ""));
        let snapshot = parse_snapshot_with_customs(&fake, &mut MonitorState::default(), &customs, nonce, 1).unwrap();
        assert!(snapshot.custom[0].error.contains("no complete output"));
    }

    #[test]
    fn outage_threshold_fires_once_and_recovery_clears_it() {
        let mut state = MonitorState::default();
        let mut sample = MonitorSample {
            tab: 1, key: String::new(), name: String::new(), host: String::new(), port: 22,
            protocol: "ssh".into(), status: "error".into(), sampled_at: 0, latency_ms: 0,
            error: String::new(), snapshot: None, consecutive_failures: 0, outage_since_ms: None,
            outage: false, outage_started: false, recovered: false,
        };
        for i in 1..=3 {
            sample.outage_started = false;
            record_failure(&mut state, &mut sample, 3, 100 + i);
            assert_eq!(sample.consecutive_failures, i);
            assert_eq!(sample.outage_started, i == 3);
            assert_eq!(sample.outage, i == 3);
        }
        record_recovery(&mut state, &mut sample, 3);
        assert!(sample.recovered);
        assert_eq!(state.consecutive_failures, 0);
        assert_eq!(state.outage_since_ms, None);
    }

    #[test]
    fn monitor_settings_validate_and_round_trip_privately() {
        let root = std::env::temp_dir().join(format!("linscp-monitor-settings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mut doc = MonitorSettingsDocument::default();
        doc.hosts.insert("site:test".into(), MonitorHostConfig {
            enabled_metrics: vec!["cpu".into(), "net".into(), "cpu".into(), "bogus".into()],
            custom_metrics: vec![MonitorCustomMetric {
                id: "users".into(), name: "Users".into(), command: "who | wc -l".into(),
                parse: MonitorMetricParse::Number, regex: None, display: MonitorMetricDisplay::Sparkline, unit: String::new(),
            }],
            paused: false,
        });
        let saved = save_settings(&root, doc).unwrap();
        assert_eq!(saved.hosts["site:test"].enabled_metrics, vec!["cpu", "net"]);
        assert_eq!(load_settings(&root), saved);
        let mut bad = saved.clone();
        bad.hosts.get_mut("site:test").unwrap().custom_metrics[0].command = "rm -rf /".into();
        // Commands are user-approved, but empty/NUL/oversized definitions are refused.
        bad.hosts.get_mut("site:test").unwrap().custom_metrics[0].command = String::new();
        assert!(save_settings(&root, bad).is_err());
        let _ = std::fs::remove_dir_all(&root);
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
