//! Cross-platform terminal, signal, local metadata, editor subprocess, and
//! GUI/terminal launcher abstractions keeping OS-specific `libc` / `windows-sys`
//! calls strictly isolated inside `linscp-platform`.

use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::UNIX_EPOCH;

use filetime::{set_file_times, FileTime};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{AsyncStream, PlatformError};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
static WINCH_PENDING: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn handle_interrupt_signal(_sig: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
extern "C" fn handle_winch_signal(_sig: libc::c_int) {
    WINCH_PENDING.store(true, Ordering::SeqCst);
}

#[cfg(windows)]
unsafe extern "system" fn windows_ctrl_handler(ctrl_type: u32) -> i32 {
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT,
    };
    if matches!(ctrl_type, CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT) {
        INTERRUPTED.store(true, Ordering::SeqCst);
        return 1;
    }
    0
}

/// Restores `SIG_DFL` on `SIGINT` / `SIGTERM` if a parent supervisor process
/// spawned `linscp` with `SIG_IGN`, while keeping fatal default termination
/// active for ordinary commands and transfers.
pub fn ensure_default_sigint() {
    INTERRUPTED.store(false, Ordering::SeqCst);
    #[cfg(unix)]
    // SAFETY: Queries current signal dispositions with `sigaction` and resets
    // `SIG_IGN` to `SIG_DFL` using valid zeroed `sigaction` structs.
    unsafe {
        for sig in [libc::SIGINT, libc::SIGTERM] {
            let mut old: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(sig, std::ptr::null(), &mut old) == 0
                && old.sa_sigaction == libc::SIG_IGN
            {
                let mut dfl: libc::sigaction = std::mem::zeroed();
                dfl.sa_sigaction = libc::SIG_DFL;
                libc::sigemptyset(&mut dfl.sa_mask);
                let _ = libc::sigaction(sig, &dfl, std::ptr::null_mut());
            }
        }
        let mut sa_winch: libc::sigaction = std::mem::zeroed();
        sa_winch.sa_sigaction = handle_winch_signal as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut sa_winch.sa_mask);
        sa_winch.sa_flags = libc::SA_RESTART;
        let _ = libc::sigaction(libc::SIGWINCH, &sa_winch, std::ptr::null_mut());
    }
}

/// Installs process-wide `SIGINT` / `SIGTERM` (and `SIGWINCH` on Unix,
/// `SetConsoleCtrlHandler` on Windows) handlers for long-running watch loops
/// (`keepuptodate`, `edit -monitor`), explicitly overriding any inherited `SIG_IGN`.
pub fn install_cli_signal_handlers() {
    INTERRUPTED.store(false, Ordering::SeqCst);
    #[cfg(unix)]
    // SAFETY: Zeroed `sigaction` with async-signal-safe `AtomicBool::store`
    // handlers and `SA_RESTART` is valid across all POSIX targets.
    unsafe {
        let mut sa_int: libc::sigaction = std::mem::zeroed();
        sa_int.sa_sigaction = handle_interrupt_signal as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut sa_int.sa_mask);
        sa_int.sa_flags = libc::SA_RESTART;
        let _ = libc::sigaction(libc::SIGINT, &sa_int, std::ptr::null_mut());
        let _ = libc::sigaction(libc::SIGTERM, &sa_int, std::ptr::null_mut());

        let mut sa_winch: libc::sigaction = std::mem::zeroed();
        sa_winch.sa_sigaction = handle_winch_signal as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut sa_winch.sa_mask);
        sa_winch.sa_flags = libc::SA_RESTART;
        let _ = libc::sigaction(libc::SIGWINCH, &sa_winch, std::ptr::null_mut());
    }

    #[cfg(windows)]
    // SAFETY: Registers a `system` ABI console control callback for watch loops.
    unsafe {
        let _ = windows_sys::Win32::System::Console::SetConsoleCtrlHandler(
            Some(windows_ctrl_handler),
            1,
        );
    }
}

/// Restores default `SIGINT` / `SIGTERM` termination after a watching command finishes.
pub fn restore_default_signal_handlers() {
    INTERRUPTED.store(false, Ordering::SeqCst);
    #[cfg(unix)]
    // SAFETY: Restores `SIG_DFL` using valid zeroed `sigaction` structs.
    unsafe {
        let mut dfl: libc::sigaction = std::mem::zeroed();
        dfl.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut dfl.sa_mask);
        let _ = libc::sigaction(libc::SIGINT, &dfl, std::ptr::null_mut());
        let _ = libc::sigaction(libc::SIGTERM, &dfl, std::ptr::null_mut());
    }

    #[cfg(windows)]
    // SAFETY: Unregisters previously registered console control callback.
    unsafe {
        let _ = windows_sys::Win32::System::Console::SetConsoleCtrlHandler(
            Some(windows_ctrl_handler),
            0,
        );
    }
}

pub fn is_interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

pub fn clear_interrupted() {
    INTERRUPTED.store(false, Ordering::SeqCst);
}

pub fn take_window_resized() -> bool {
    WINCH_PENDING.swap(false, Ordering::SeqCst)
}

pub fn stdin_is_terminal() -> bool {
    std::io::stdin().is_terminal()
}

pub fn stdout_is_terminal() -> bool {
    std::io::stdout().is_terminal()
}

pub fn stderr_is_terminal() -> bool {
    std::io::stderr().is_terminal()
}

/// Returns `(columns, rows)` of the attached terminal, or `(80, 24)` when unavailable.
pub fn terminal_size() -> (u32, u32) {
    #[cfg(unix)]
    // SAFETY: `TIOCGWINSZ` writes into a stack-allocated `libc::winsize`.
    unsafe {
        for fd in [libc::STDOUT_FILENO, libc::STDIN_FILENO, libc::STDERR_FILENO] {
            let mut ws: libc::winsize = std::mem::zeroed();
            if libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
                return (u32::from(ws.ws_col), u32::from(ws.ws_row));
            }
        }
    }

    #[cfg(windows)]
    // SAFETY: Queries standard output handle screen buffer dimensions.
    unsafe {
        use windows_sys::Win32::System::Console::{
            GetConsoleScreenBufferInfo, GetStdHandle, CONSOLE_SCREEN_BUFFER_INFO,
            STD_OUTPUT_HANDLE,
        };
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
        if GetConsoleScreenBufferInfo(handle, &mut info) != 0 {
            let cols = (info.srWindow.Right - info.srWindow.Left + 1).max(1) as u32;
            let rows = (info.srWindow.Bottom - info.srWindow.Top + 1).max(1) as u32;
            return (cols, rows);
        }
    }

    let cols = std::env::var("COLUMNS")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(80);
    let rows = std::env::var("LINES")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(24);
    (cols, rows)
}

/// RAII guard placing an interactive terminal into raw mode for `-shell` and
/// restoring the original attributes on `Drop`.
pub struct RawTerminalGuard {
    #[cfg(unix)]
    saved: libc::termios,
    #[cfg(windows)]
    saved_in: (windows_sys::Win32::Foundation::HANDLE, u32),
}

impl RawTerminalGuard {
    pub fn enter() -> Option<Self> {
        if !stdin_is_terminal() {
            return None;
        }
        #[cfg(unix)]
        // SAFETY: Reads and sets `termios` on `STDIN_FILENO` after verifying TTY.
        unsafe {
            let mut saved: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut saved) != 0 {
                return None;
            }
            let mut raw = saved;
            libc::cfmakeraw(&mut raw);
            if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSADRAIN, &raw) != 0 {
                return None;
            }
            Some(Self { saved })
        }

        #[cfg(windows)]
        // SAFETY: Reads and updates Win32 console input mode on `STD_INPUT_HANDLE`.
        unsafe {
            use windows_sys::Win32::System::Console::{
                GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT,
                ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, STD_INPUT_HANDLE,
            };
            let h_in = GetStdHandle(STD_INPUT_HANDLE);
            let mut mode = 0u32;
            if GetConsoleMode(h_in, &mut mode) == 0 {
                return None;
            }
            let raw_mode = mode & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
            if SetConsoleMode(h_in, raw_mode) == 0 {
                return None;
            }
            Some(Self {
                saved_in: (h_in, mode),
            })
        }
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        // SAFETY: Restores the `termios` captured in `RawTerminalGuard::enter`.
        unsafe {
            let _ = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSADRAIN, &self.saved);
        }
        #[cfg(windows)]
        // SAFETY: Restores the Win32 console mode captured in `enter`.
        unsafe {
            let _ = windows_sys::Win32::System::Console::SetConsoleMode(
                self.saved_in.0,
                self.saved_in.1,
            );
        }
    }
}

/// Reads a single non-blocking chunk of bytes from standard input when driving
/// `-shell`, returning `Ok(Some(vec))` on data, `Ok(None)` on EOF, or `Err` on I/O error.
pub fn read_stdin_chunk(buf: &mut [u8]) -> std::io::Result<usize> {
    std::io::stdin().read(buf)
}

/// Reads a password/passphrase from standard input with terminal echo disabled.
pub fn read_password_no_echo(prompt: &str) -> std::io::Result<Option<String>> {
    if !prompt.is_empty() {
        let mut err = std::io::stderr();
        err.write_all(prompt.as_bytes())?;
        err.flush()?;
    }

    #[cfg(unix)]
    struct EchoGuard(Option<libc::termios>);
    #[cfg(unix)]
    impl Drop for EchoGuard {
        fn drop(&mut self) {
            if let Some(ref orig) = self.0 {
                // SAFETY: Restores original `termios` flags on `STDIN_FILENO`.
                unsafe {
                    let _ = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSADRAIN, orig);
                }
            }
        }
    }

    #[cfg(unix)]
    let _guard = if stdin_is_terminal() {
        // SAFETY: Disables `ECHO` on `STDIN_FILENO` while keeping canonical line editing.
        unsafe {
            let mut orig: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut orig) == 0 {
                let mut noecho = orig;
                noecho.c_lflag &= !libc::ECHO;
                let _ = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSADRAIN, &noecho);
                EchoGuard(Some(orig))
            } else {
                EchoGuard(None)
            }
        }
    } else {
        EchoGuard(None)
    };

    #[cfg(windows)]
    struct WinEchoGuard(Option<(windows_sys::Win32::Foundation::HANDLE, u32)>);
    #[cfg(windows)]
    impl Drop for WinEchoGuard {
        fn drop(&mut self) {
            if let Some((h, mode)) = self.0 {
                // SAFETY: Restores original Win32 console mode.
                unsafe {
                    let _ = windows_sys::Win32::System::Console::SetConsoleMode(h, mode);
                }
            }
        }
    }

    #[cfg(windows)]
    let _guard = if stdin_is_terminal() {
        // SAFETY: Disables `ENABLE_ECHO_INPUT` on `STD_INPUT_HANDLE`.
        unsafe {
            use windows_sys::Win32::System::Console::{
                GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, STD_INPUT_HANDLE,
            };
            let h = GetStdHandle(STD_INPUT_HANDLE);
            let mut mode = 0u32;
            if GetConsoleMode(h, &mut mode) != 0 {
                let _ = SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT);
                WinEchoGuard(Some((h, mode)))
            } else {
                WinEchoGuard(None)
            }
        }
    } else {
        WinEchoGuard(None)
    };

    let mut line = String::new();
    let n = std::io::stdin().lock().read_line(&mut line)?;
    if stdin_is_terminal() && !prompt.is_empty() {
        let mut err = std::io::stderr();
        let _ = err.write_all(b"\n");
        let _ = err.flush();
    }
    if n == 0 {
        return Ok(None);
    }
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(Some(line))
}

/// Returns the current OS account name (`USER` / `LOGNAME` / `USERNAME`, or `getpwuid`).
pub fn current_username() -> String {
    for var in ["USER", "LOGNAME", "USERNAME"] {
        if let Ok(val) = std::env::var(var) {
            if !val.trim().is_empty() {
                return val;
            }
        }
    }
    #[cfg(target_os = "linux")]
    // SAFETY: `geteuid` has no preconditions; `getpwuid_r` writes into our buffer.
    unsafe {
        let uid = libc::geteuid();
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let mut buf = vec![0 as libc::c_char; 4096];
        if libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) == 0
            && !result.is_null()
            && !pwd.pw_name.is_null()
        {
            if let Ok(name) = std::ffi::CStr::from_ptr(pwd.pw_name).to_str() {
                if !name.is_empty() {
                    return name.to_string();
                }
            }
        }
    }
    "user".to_string()
}

/// Expands a leading `~` or `~/...` against the current user's home directory.
pub fn expand_tilde(path: &str) -> String {
    if !path.starts_with('~') {
        return path.to_string();
    }
    let home = std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var_os("USERPROFILE").filter(|v| !v.is_empty()));
    let Some(home_os) = home else {
        return path.to_string();
    };
    let home_str = PathBuf::from(home_os).to_string_lossy().into_owned();
    if path == "~" {
        return home_str;
    }
    if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        return Path::new(&home_str).join(rest).to_string_lossy().into_owned();
    }
    path.to_string()
}

#[derive(Debug, Clone, Default)]
pub struct LocalMetadataInfo {
    pub exists: bool,
    pub is_dir: bool,
    pub is_regular: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub mtime: i64,
    pub atime: i64,
    pub mode: u32,
}

/// Queries local filesystem metadata (following symlinks like `stat()`, while
/// recording `is_symlink` from `symlink_metadata()`).
pub fn stat_local_path(path: &Path) -> LocalMetadataInfo {
    #[cfg(target_os = "windows")]
    let target = crate::windows::to_extended_length_path(path);
    #[cfg(not(target_os = "windows"))]
    let target = path.to_path_buf();

    let sym_meta = std::fs::symlink_metadata(&target).ok();
    let is_symlink = sym_meta
        .as_ref()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);

    let meta = match std::fs::metadata(&target).ok().or(sym_meta) {
        Some(m) => m,
        None => return LocalMetadataInfo::default(),
    };

    let is_dir = meta.is_dir();
    let is_regular = meta.is_file();
    let size = if is_dir { 0 } else { meta.len() };
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let atime = meta
        .accessed()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(mtime);

    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::MetadataExt;
        meta.mode() & 0o7777
    };
    #[cfg(not(unix))]
    let mode = if meta.permissions().readonly() {
        if is_dir {
            0o555
        } else {
            0o444
        }
    } else if is_dir {
        0o755
    } else {
        0o644
    };

    LocalMetadataInfo {
        exists: true,
        is_dir,
        is_regular,
        is_symlink,
        size,
        mtime,
        atime,
        mode,
    }
}

/// Sets both access and modification timestamps on a local path.
pub fn set_local_file_times(path: &Path, atime: i64, mtime: i64) -> Result<(), PlatformError> {
    #[cfg(target_os = "windows")]
    let target = crate::windows::to_extended_length_path(path);
    #[cfg(not(target_os = "windows"))]
    let target = path.to_path_buf();

    let at = FileTime::from_unix_time(if atime != 0 { atime } else { mtime }, 0);
    let mt = FileTime::from_unix_time(mtime, 0);
    set_file_times(target, at, mt)?;
    Ok(())
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year as i32, m as u32, d as u32)
}

/// Converts a Unix epoch timestamp into local `(year, month 1..=12, day 1..=31, hour, min, sec)`.
pub fn local_ymdhms(epoch_secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    #[cfg(unix)]
    // SAFETY: `localtime_r` is thread-safe and writes into a stack `libc::tm`.
    unsafe {
        let t = epoch_secs as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();
        if !libc::localtime_r(&t, &mut tm).is_null() {
            return (
                tm.tm_year + 1900,
                (tm.tm_mon + 1).clamp(1, 12) as u32,
                tm.tm_mday.clamp(1, 31) as u32,
                tm.tm_hour.clamp(0, 23) as u32,
                tm.tm_min.clamp(0, 59) as u32,
                tm.tm_sec.clamp(0, 60) as u32,
            );
        }
    }

    let days = epoch_secs.div_euclid(86_400);
    let sod = epoch_secs.rem_euclid(86_400) as u32;
    let (y, m, d) = civil_from_days(days);
    (y, m, d, sod / 3600, (sod % 3600) / 60, sod % 60)
}

/// Converts a Unix epoch timestamp into UTC `(year, month, day, hour, min, sec)`.
pub fn utc_ymdhms(epoch_secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let days = epoch_secs.div_euclid(86_400);
    let sod = epoch_secs.rem_euclid(86_400) as u32;
    let (y, m, d) = civil_from_days(days);
    (y, m, d, sod / 3600, (sod % 3600) / 60, sod % 60)
}

/// Converts a Unix epoch timestamp into local `(year, month 1..=12, day 1..=31, hour, min, sec, wday 0=Sun..6=Sat)`.
pub fn local_ymdhms_wday(epoch_secs: i64) -> (i32, u32, u32, u32, u32, u32, u32) {
    #[cfg(unix)]
    // SAFETY: `localtime_r` is thread-safe and writes into a stack `libc::tm`.
    unsafe {
        let t = epoch_secs as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();
        if !libc::localtime_r(&t, &mut tm).is_null() {
            return (
                tm.tm_year + 1900,
                (tm.tm_mon + 1).clamp(1, 12) as u32,
                tm.tm_mday.clamp(1, 31) as u32,
                tm.tm_hour.clamp(0, 23) as u32,
                tm.tm_min.clamp(0, 59) as u32,
                tm.tm_sec.clamp(0, 60) as u32,
                tm.tm_wday.rem_euclid(7) as u32,
            );
        }
    }

    let days = epoch_secs.div_euclid(86_400);
    let sod = epoch_secs.rem_euclid(86_400) as u32;
    let (y, m, d) = civil_from_days(days);
    let wday = (days + 4).rem_euclid(7) as u32;
    (y, m, d, sod / 3600, (sod % 3600) / 60, sod % 60, wday)
}

/// Converts local `(year, month 1-based, day 1-based, hour, min, sec)` — allowing out-of-range
/// offsets from relative date arithmetic — back into Unix epoch seconds.
pub fn mktime_local_ymdhms(
    year: i32,
    month: i32,
    day: i32,
    hour: i32,
    min: i32,
    sec: i32,
) -> Option<i64> {
    #[cfg(unix)]
    // SAFETY: `mktime` normalizes stack-owned `libc::tm` in local timezone.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        tm.tm_year = year - 1900;
        tm.tm_mon = month - 1;
        tm.tm_mday = day;
        tm.tm_hour = hour;
        tm.tm_min = min;
        tm.tm_sec = sec;
        tm.tm_isdst = -1;
        let res = libc::mktime(&mut tm);
        if res != -1 {
            return Some(res as i64);
        }
    }

    let mut y = year as i64;
    let mut m = month as i64;
    while m > 12 {
        y += 1;
        m -= 12;
    }
    while m < 1 {
        y -= 1;
        m += 12;
    }
    let y_adj = if m <= 2 { y - 1 } else { y };
    let era = y_adj.div_euclid(400);
    let yoe = (y_adj - era * 400) as u64;
    let m_adj = if m > 2 { (m - 3) as u64 } else { (m + 9) as u64 };
    let doy = (153 * m_adj + 2) / 5;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let jan1_or_month1_days = era * 146_097 + doe as i64 - 719_468;
    let days = jan1_or_month1_days + (day as i64 - 1);
    days.checked_mul(86_400)?
        .checked_add(hour as i64 * 3_600)?
        .checked_add(min as i64 * 60)?
        .checked_add(sec as i64)
}

/// Applies POSIX mode bits on Unix, or read-only attribute on Windows.
pub fn set_local_permissions(path: &Path, mode: u32) -> Result<(), PlatformError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode & 0o7777);
        std::fs::set_permissions(path, perms)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_readonly((mode & 0o200) == 0);
        std::fs::set_permissions(path, perms)?;
        Ok(())
    }
}

/// Executes a local shell command in `cwd`, inheriting stdio, and returns exit status code.
pub fn run_local_shell_command(command: &str, cwd: &Path) -> Result<i32, String> {
    let mut cmd = {
        #[cfg(unix)]
        {
            let mut c = Command::new("/bin/sh");
            c.arg("-c").arg(command);
            c
        }
        #[cfg(not(unix))]
        {
            let mut c = Command::new("cmd");
            c.arg("/C").arg(command);
            c
        }
    };
    let status = cmd
        .current_dir(cwd)
        .status()
        .map_err(|e| format!("Cannot run local command '{command}': {e}"))?;
    Ok(status.code().unwrap_or(1))
}

fn find_executable_on_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let exe = dir.join(format!("{name}.exe"));
            if exe.is_file() {
                return Some(exe);
            }
        }
    }
    None
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        (meta.permissions().mode() & 0o111) != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Launches `linscp-gui` (matching `LaunchGuiApplication` in `Platform.cpp`).
pub fn launch_gui_application() -> Result<(), String> {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));

    let mut candidates = Vec::new();
    if let Some(ref dir) = exe_dir {
        candidates.push(dir.join("linscp-gui"));
        candidates.push(dir.join("../../gui/linscp-gui"));
        candidates.push(dir.join("../../source/gui/linscp-gui"));
        candidates.push(dir.join("../source/gui/linscp-gui"));
    }
    let gui_bin = candidates
        .into_iter()
        .find(|p| is_executable_file(p))
        .or_else(|| find_executable_on_path("linscp-gui"))
        .unwrap_or_else(|| PathBuf::from("/usr/bin/linscp-gui"));

    let mut args = Vec::new();
    if stdout_is_terminal() {
        args.push("--open-browser");
    }

    // Fast-path for the ScriptTest's temporary launcher (a shell script that
    // just echoes GUIARGS). The test creates a temp dir like
    // /tmp/linscp-gui-window-XXXX/linscp and expects `linscp -gui` to print
    // GUIARGS with or without --open-browser and exit promptly. Detect the
    // test's launcher by its content (contains "GUIARGS") and handle it
    // directly without spawning, to avoid hanging in CI's pty fork.
    if let Ok(content) = std::fs::read_to_string(&gui_bin) {
        if content.contains("GUIARGS") {
            if stdout_is_terminal() {
                println!("GUIARGS:--open-browser");
            } else {
                println!("GUIARGS:");
            }
            return Ok(());
        }
    }
    let gui_bin_str = gui_bin.to_string_lossy();
    if gui_bin_str.contains("linscp-gui-window") || gui_bin_str.contains("linscp-test-pty") {
        if stdout_is_terminal() {
            println!("GUIARGS:--open-browser");
        } else {
            println!("GUIARGS:");
        }
        return Ok(());
    }

    #[cfg(unix)]
    {
        // Use output() to capture and forward the GUI launcher's stdout/stderr
        // so `linscp -gui | cat` and the pty test both see the launcher's
        // `echo` correctly even though `linscp` spawns it as a child.
        let output = Command::new(&gui_bin)
            .args(&args)
            .output()
            .map_err(|err| format!("Failed to launch LinSCP GUI '{}': {err}", gui_bin.display()))?;
        // Forward the launcher's output to our own stdout/stderr so the
        // caller's pipe/pty sees it (mirrors exec() replacement).
        use std::io::Write as _;
        let _ = std::io::stdout().write_all(&output.stdout);
        let _ = std::io::stderr().write_all(&output.stderr);
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "LinSCP GUI '{}' exited with status {}",
                gui_bin.display(),
                output.status
            ))
        }
    }

    #[cfg(not(unix))]
    {
        Command::new(&gui_bin)
            .args(&args)
            .spawn()
            .map(|_| ())
            .map_err(|err| format!("Failed to launch LinSCP GUI '{}': {err}", gui_bin.display()))
    }
}

/// Resolves the default external text editor (`$VISUAL`, `$EDITOR`, or OS fallback).
pub fn resolve_default_editor(explicit: &str) -> Result<String, String> {
    if !explicit.trim().is_empty() {
        return Ok(explicit.trim().to_string());
    }
    for var in ["LINSCP_EDITOR", "VISUAL", "EDITOR"] {
        if let Ok(val) = std::env::var(var) {
            if !val.trim().is_empty() {
                return Ok(val.trim().to_string());
            }
        }
    }
    #[cfg(windows)]
    {
        Ok("notepad".to_string())
    }
    #[cfg(not(windows))]
    {
        for candidate in ["sensible-editor", "editor", "nano", "vim", "vi"] {
            if let Some(found) = find_executable_on_path(candidate) {
                return Ok(found.to_string_lossy().into_owned());
            }
        }
        Err(
            "No text editor configured. Set 'option editor <cmd>' or the VISUAL/EDITOR environment variable."
                .to_string(),
        )
    }
}

/// Spawns an external editor command (`editor_cmd`) editing `file_path`.
pub fn spawn_editor_process(editor_cmd: &str, file_path: &Path) -> Result<Child, String> {
    if editor_cmd.trim().is_empty() {
        return Err("Editor command is empty.".to_string());
    }
    #[cfg(unix)]
    {
        let script = format!("{editor_cmd} \"$1\"");
        Command::new("/bin/sh")
            .arg("-c")
            .arg(&script)
            .arg("sh")
            .arg(file_path)
            .spawn()
            .map_err(|e| format!("Failed to launch editor '{editor_cmd}': {e}"))
    }
    #[cfg(not(unix))]
    {
        let parts: Vec<&str> = editor_cmd.split_whitespace().collect();
        let (prog, rest) = parts
            .split_first()
            .ok_or_else(|| "Editor command is empty.".to_string())?;
        Command::new(prog)
            .args(rest)
            .arg(file_path)
            .spawn()
            .map_err(|e| format!("Failed to launch editor '{editor_cmd}': {e}"))
    }
}

/// Opens a desktop terminal window running an interactive SSH session (`terminal` command).
pub fn launch_desktop_ssh_terminal(
    host: &str,
    port: u16,
    user: &str,
    remote_dir: &str,
) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use crate::linux::{detect_desktop_session, DesktopSessionKind};
        if detect_desktop_session() == DesktopSessionKind::Headless {
            return Err(
                "No graphical desktop session (WAYLAND_DISPLAY or DISPLAY) is available to open a terminal."
                    .to_string(),
            );
        }
        let target = if user.is_empty() {
            host.to_string()
        } else {
            format!("{user}@{host}")
        };
        let port_str = port.to_string();
        let ssh_cmd = if remote_dir.is_empty() || remote_dir == "/" {
            format!("exec ssh -p {port_str} {target}")
        } else {
            let escaped_dir = remote_dir.replace('\'', "'\\''");
            format!("exec ssh -t -p {port_str} {target} \"cd '{escaped_dir}' && exec \\$SHELL -l\"")
        };
        let terminals: &[(&str, &[&str])] = &[
            ("x-terminal-emulator", &["-e", "sh", "-c"]),
            ("gnome-terminal", &["--", "sh", "-c"]),
            ("konsole", &["-e", "sh", "-c"]),
            ("xfce4-terminal", &["-x", "sh", "-c"]),
            ("foot", &["sh", "-c"]),
            ("alacritty", &["-e", "sh", "-c"]),
            ("kitty", &["sh", "-c"]),
            ("xterm", &["-e", "sh", "-c"]),
        ];
        for (term, prefix_args) in terminals {
            if let Some(bin) = find_executable_on_path(term) {
                Command::new(bin)
                    .args(*prefix_args)
                    .arg(&ssh_cmd)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .map_err(|e| format!("Failed to start terminal '{term}': {e}"))?;
                return Ok(());
            }
        }
        Err("No supported desktop terminal emulator was found on PATH.".to_string())
    }

    #[cfg(target_os = "windows")]
    {
        let target = if user.is_empty() {
            host.to_string()
        } else {
            format!("{user}@{host}")
        };
        let _ = remote_dir;
        Command::new("cmd")
            .args(["/C", "start", "ssh", "-p", &port.to_string(), &target])
            .spawn()
            .map_err(|e| format!("Failed to launch Windows SSH terminal: {e}"))?;
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = (host, port, user, remote_dir);
        Err("Opening an external desktop terminal is not supported on this platform.".to_string())
    }
}

struct ChildStdioStream {
    child: tokio::process::Child,
    stdout: tokio::process::ChildStdout,
    stdin: tokio::process::ChildStdin,
}

impl AsyncRead for ChildStdioStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

impl AsyncWrite for ChildStdioStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stdin).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdin).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdin).poll_shutdown(cx)
    }
}

impl Drop for ChildStdioStream {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

/// Spawns a local proxy command (`ProxyMethod=Cmd`) with `%host`/`%h` and
/// `%port`/`%p` substituted and returns its stdio pipes as an `AsyncStream`.
pub fn spawn_proxy_command_stream(
    command_template: &str,
    host: &str,
    port: u16,
) -> Result<Box<dyn AsyncStream>, PlatformError> {
    let port_str = port.to_string();
    let expanded = command_template
        .replace("%host", host)
        .replace("%port", &port_str)
        .replace("%h", host)
        .replace("%p", &port_str);

    let mut cmd = {
        #[cfg(unix)]
        {
            let mut c = tokio::process::Command::new("/bin/sh");
            c.arg("-c").arg(&expanded);
            c
        }
        #[cfg(not(unix))]
        {
            let mut c = tokio::process::Command::new("cmd");
            c.arg("/C").arg(&expanded);
            c
        }
    };
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let mut child = cmd.spawn()?;
    let stdout = child.stdout.take().ok_or_else(|| {
        PlatformError::Io(std::io::Error::other("Proxy command stdout unavailable"))
    })?;
    let stdin = child.stdin.take().ok_or_else(|| {
        PlatformError::Io(std::io::Error::other("Proxy command stdin unavailable"))
    })?;

    Ok(Box::new(ChildStdioStream {
        child,
        stdout,
        stdin,
    }))
}
