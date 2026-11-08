# Multi-server monitor

LinSCP's **Monitor** toolbar button and Commands menu open the same shared
TypeScript display in the native Tauri window and the browser server. Both
hosts call the same Rust service routes:

- `GET /api/monitor/hosts` lists connected SSH/SFTP/SCP tabs and saved SSH
  sites. It returns names, hosts, ports and protocols only; it never returns
  passwords, keys or passphrases.
- `POST /api/monitor/sample` accepts `{ "tabs": [1, 2], "timeout": 10 }` and
  samples up to 32 distinct open tabs concurrently. Timeout is 0.1–30 seconds.
- `GET/POST /api/monitor/settings` reads and validates the device-local
  `monitor.json` document: global interval/timeouts/outage settings and
  per-server enabled metrics, custom metrics and paused state.

## Using it

1. Open SSH, SFTP or SCP sessions normally, or choose **Monitor → Choose
   servers** and tick open sessions and saved sites. Saved sites connect one
   at a time through LinSCP's normal connection flow. Unknown or changed host
   keys still open the existing verification dialog; cancelling abandons that
   connection. Monitor never accepts a wildcard host key.
2. Select **Monitor selected servers**. The overview shows CPU, RAM, swap,
   the fullest mounted filesystem, 1-minute load, network in/out rates, GPU
   usage and reported GPU power per server, with recent sparklines. Click a
   server name for per-core/thread topology, all parsed mounts, GPU memory,
   temperature, power, driver and current PCIe link details.
3. Open **Monitor settings** to set **Refresh every** (0.1–60 seconds,
   default 5), **Sample timeout** (0.1–30 seconds, default 10), **Connection
   timeout** (1–60 seconds, default 10, applied when the monitor opens a saved
   site), **Outage threshold** (1–100 consecutive failed polls, default 3),
   outage/recovery notices, and an optional outage beep with a 0–600 second
   cooldown. Settings are validated by the service and saved in `monitor.json`
   on the device running the backend.
4. Use **Pause** to stop all polling without disconnecting SSH. Each card also
   has **Pause/Resume**, **Configure** and **Remove**. Configure toggles
   built-in metrics and edits up to eight custom metrics for that server.
   **SSH shell** opens the existing embedded terminal on the current server and
   pauses the monitor; closing that terminal resumes the same selection.
   Closing the monitor stops polling but leaves sessions and transfers alone.

Shortcuts while the monitor has focus: `t` overview/detail, `n` next server,
`m` compact GPU cards, `c` choose servers, `s` shell, `q` or Escape close.
Shortcuts do not run while typing in a field or while the terminal, editor or
host-key dialog is open. Selection persists while the display is closed during
the page lifetime. Settings, per-server metric choices, custom commands and
paused state persist in `monitor.json`; sparkline history is an in-memory ring
of the last 60 successful samples per metric (about five minutes at the default
interval) and is not written to disk.

## Telemetry and safety

The service runs one fixed, read-only Linux probe over the tab's already
authenticated SSH connection. It reads `/proc/stat`, `/proc/meminfo` (including
swap), `/proc/net/dev`, uptime, load average, `lscpu` topology, POSIX `df -Pk`,
hostname/IP and optional vendor tools. No user-supplied text is interpolated
into the built-in probe. Combined exec output is capped at 2 MiB and the channel
has a total deadline; expired channels are closed best-effort while the SSH
session remains usable. A server must still stop its child process when its exec
channel closes.

Custom metrics are the explicit exception to the read-only built-in probe: they
are user-approved remote shell commands saved per server and run every poll.
The UI requires an approval checkbox before applying them. Each command runs in
its own subshell with stderr discarded; stdout is capped at 64 KiB with `dd`.
Per-poll nonce markers delimit each custom block, and built-in sections are
parsed only before the first custom block, so custom output cannot spoof a
built-in reading. Number mode extracts the first finite numeric token; regex
mode captures the first group (or whole match) as a finite number; text mode
shows trimmed stdout. Invalid definitions are refused by the service.

CPU percentages and network rates are deltas between successful samples on the
same SSH connection. The first sample, a reconnect, or a counter reset reports
unknown rather than a fabricated zero. Network totals skip loopback and are
shown as bits/s. RAM used is total minus available (with the older
free+buffers+cached fallback); swap without a configured swap area reports 0%.
Disk parsing handles wrapped `df -P` lines and escaped spaces, filters common
pseudo filesystems, and caps parsed devices. CPU topology, disks and GPUs are
capped to bound memory use.

Outage state is tracked per tab. The first failed poll starts an outage streak;
crossing the configured threshold marks the server offline, logs an error, and
can show a notice and beep. The next successful sample clears the streak, logs
recovery and can show a recovery notice. Pausing a server suppresses its display
as an outage; closing the monitor stops polling entirely.

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

## Submarine parity

The shared monitor now covers the monitoring features that prompted comparison
with [SinaXhpm/Submarine](https://github.com/SinaXhpm/Submarine): network in/out
sparklines, swap and load history, per-server metric selection, custom
number/regex/text metrics, persisted monitor settings, per-server pause, and
outage/recovery notices with optional beep cooldown. LinSCP deliberately keeps
its own safety model: it reuses already authenticated LinSCP tabs and the normal
host-key dialog instead of opening a second known-hosts-only SSH client, and it
polls only while the shared display is open rather than running background
per-node pollers after the display is closed.

## Validation

Frontend: `npm --prefix ui test` includes shared component tests and the real
page's monitor/terminal lifecycle in jsdom. Rust: `cargo test -p linscp-service
monitor` covers parsers, validation and route secrecy; `cargo test -p
linscp-proto bounded_exec` covers deadline/output-cap cleanup over the loopback
SSH fixture. Locale and architecture checks: `python3
tools/compile_translations.py --check`, `python3
tools/build_unified_locales.py --check`, `python3 tools/check_repo_hygiene.py`,
`python3 tools/check_shared_frontend.py`.
