# Multi-server monitor

LinSCP's **Monitor** toolbar button and Commands menu open the same shared
TypeScript display in the native Tauri window and the browser server. Both
hosts call the same Rust service routes:

- `GET /api/monitor/hosts` lists connected SSH/SFTP/SCP tabs and saved SSH
  sites. It returns names, hosts, ports and protocols only; it never returns
  passwords, keys or passphrases.
- `POST /api/monitor/sample` accepts `{ "tabs": [1, 2], "timeout": 10 }` and
  samples up to 32 distinct open tabs concurrently. Timeout is 0.1–30 seconds.

## Using it

1. Open SSH, SFTP or SCP sessions normally, or choose **Monitor → Choose
   servers** and tick open sessions and saved sites. Saved sites connect one
   at a time through LinSCP's normal connection flow. Unknown or changed host
   keys still open the existing verification dialog; cancelling abandons that
   connection. Monitor never accepts a wildcard host key.
2. Select **Monitor selected servers**. The overview shows CPU, RAM, the
   fullest mounted filesystem, GPU usage and reported GPU power per server.
   Click a server name for per-core/thread topology, all parsed mounts, GPU
   memory, temperature, power, driver and current PCIe link details.
3. Set **Refresh every** (0.1–60 seconds, default 5), **Sample timeout**
   (0.1–30 seconds, default 10) and **Connection timeout** (1–60 seconds,
   default 10, applied when the monitor opens a saved site). Invalid values
   are rejected by both UI and service.
4. Use **Pause** to stop polling without disconnecting SSH. **SSH shell**
   opens the existing embedded terminal on the current server and pauses the
   monitor; closing that terminal resumes the same selection. Closing the
   monitor stops polling but leaves sessions and transfers alone.

Shortcuts while the monitor has focus: `t` overview/detail, `n` next server,
`m` compact GPU cards, `c` choose servers, `s` shell, `q` or Escape close.
Shortcuts do not run while typing in a field or while the terminal, editor or
host-key dialog is open. Selection and settings persist while the display is
closed during the page lifetime; they are not written to disk.

## Telemetry and safety

The service runs one fixed, read-only Linux probe over the tab's already
authenticated SSH connection. It reads `/proc/stat`, `/proc/meminfo`, uptime,
load average, `lscpu` topology, POSIX `df -Pk`, hostname/IP and optional vendor
tools. No user-supplied text is interpolated into a shell command. Combined
exec output is capped at 2 MiB and the channel has a total deadline; expired
channels are closed best-effort while the SSH session remains usable. A server
must still stop its child process when its exec channel closes.

CPU percentages are deltas between successful samples on the same SSH
connection. The first sample, a reconnect, or a counter reset reports unknown
rather than a fabricated zero. RAM used is total minus available (with the
older free+buffers+cached fallback). Disk parsing handles wrapped `df -P`
lines and escaped spaces, filters common pseudo filesystems, and caps parsed
devices. CPU topology, disks and GPUs are capped to bound memory use.

GPU support:

- NVIDIA: `nvidia-smi` CSV, including the newer thermal-limit field with an
  older-driver fallback; CUDA version comes from the normal `nvidia-smi`
  header.
- AMD modern: `amd-smi static --json` and
  `amd-smi metric --usage --power --temperature --mem-usage --pcie --json`.
  Records are joined by GPU ID, not array position. Power and thermal limits
  come from reported limit fields; VRAM values are converted from the CLI's
  MiB-sized values. PCIe generation is derived only from recognized current
  GT/s rates.
- AMD legacy: `rocm-smi` JSON for product, VRAM bytes, usage, temperature,
  average/current package power, maximum package power and driver version.

Missing optional tools or sensors remain unknown and produce a warning; they
do not fail the Linux sample or invent a zero. A failed host keeps its last
successful values visibly marked stale while healthy hosts continue updating.
The thermal bar uses a non-linear risk scale (the last quarter of the reported
limit fills quickly); without a reported limit it uses a 100 °C visual ceiling,
not a claimed device limit. PCIe color is a current-link heuristic because the
probe does not know the device's maximum link.

## Scope and limitations

This is Linux server telemetry. Non-SSH protocols and disconnected tabs are
reported as unsupported/disconnected. GPU coverage depends on the vendor CLI
being installed and permitted for the logged-in user; permissions failures are
shown as missing telemetry. The monitor reuses LinSCP's existing saved-site
proxy/tunnel support; OpenSSH import still does not resolve `ProxyJump` chains.
There is no background polling after the display is closed and no separate
credential store.

## Validation

Frontend: `npm --prefix ui test` includes shared component tests and the real
page's monitor/terminal lifecycle in jsdom. Rust: `cargo test -p linscp-service
monitor` covers parsers, validation and route secrecy; `cargo test -p
linscp-proto bounded_exec` covers deadline/output-cap cleanup over the loopback
SSH fixture. Locale and architecture checks: `python3
tools/compile_translations.py --check`, `python3
tools/build_unified_locales.py --check`, `python3 tools/check_repo_hygiene.py`,
`python3 tools/check_shared_frontend.py`.
