//! X2Go KDrive session-control primitives.
//!
//! Session-control primitives, guarded startup and best-effort termination for
//! X2Go KDrive. The experimental service route uses these primitives; callers
//! must attach graphics and manage the agent lifecycle.

use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use crate::ssh::SshConnection;
use crate::ProtoError;
use zeroize::{Zeroize, Zeroizing};

const MAX_REPLY_BYTES: usize = 8192;
const MAX_DIMENSION: u16 = 8192;
const MAX_PIXELS: u32 = 16_777_216;

/// Known desktop sessions, chosen only after probing or explicit configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X2GoDesktop {
    Xfce,
    Mate,
    Lxde,
}

impl X2GoDesktop {
    fn argument(self) -> &'static str {
        match self {
            Self::Xfce => "XFCE",
            Self::Mate => "MATE",
            Self::Lxde => "LXDE",
        }
    }
}

/// Documented X2Go network profiles; arbitrary shell fragments are not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X2GoLink {
    Modem,
    Isdn,
    Adsl,
    Wan,
    Lan,
}

impl X2GoLink {
    fn argument(self) -> &'static str {
        match self {
            Self::Modem => "modem",
            Self::Isdn => "isdn",
            Self::Adsl => "adsl",
            Self::Wan => "wan",
            Self::Lan => "lan",
        }
    }
}

/// Creates a fixed-format startup command without interpolating arbitrary strings.
///
/// Clipboard, sound and filesystem sharing must not be enabled implicitly. The
/// command creates a remote agent if executed; this function only constructs it.
/// The K session type requests KDrive rather than the older NX backend. The
/// desktop value is used in the session ID; the actual desktop is started
/// separately after the graphics connection is ready.
pub fn start_command(width: u16, height: u16, desktop: X2GoDesktop, link: X2GoLink) -> Result<String, &'static str> {
    start_command_with_clipboard(width, height, desktop, link, false)
}

/// Clipboard is enabled server-side only after an explicit per-viewer opt-in.
pub fn start_command_with_clipboard(width: u16, height: u16, desktop: X2GoDesktop, link: X2GoLink, allow_clipboard: bool) -> Result<String, &'static str> {
    if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION ||
        u32::from(width) * u32::from(height) > MAX_PIXELS {
        return Err("Invalid X2Go desktop dimensions.");
    }
    Ok(format!(
        "x2gostartagent {width}x{height} {} 16m-jpeg-9 unix-kde-depth_24 us pc105/us 0 K {} {}",
        link.argument(), desktop.argument(), if allow_clipboard { "both" } else { "none" }
    ))
}

/// A successfully validated startup response. The cookie is secret and must not
/// be included in logs, IPC responses, process arguments, or persisted profiles.
pub struct X2GoStartedSession {
    pub display: u16,
    cookie: String,
    pub agent_pid: u32,
    session_id: String,
    graphics_port: u16,
    pub sound_port: u16,
    pub sshfs_port: u16,
    pub telekinesis_ports: Option<(u16, u16)>,
}

impl X2GoStartedSession {
    /// The eventual graphics handshake needs this secret; never log it.
    pub fn cookie(&self) -> &str { &self.cookie }

    /// Validated X11 display number assigned by the server.
    pub fn display(&self) -> u16 { self.display }

    /// Server-assigned session ID, validated for use as a shell argument.
    pub fn session_id(&self) -> &str { &self.session_id }

    /// Server-side graphics listener port from the validated agent response.
    pub fn graphics_port(&self) -> u16 { self.graphics_port }

    /// Build the desktop startup command from a validated session and one of
    /// the supported desktop names. It never contains the graphics cookie or
    /// caller-supplied shell fragments. A successful shell exit only confirms
    /// the command was launched, not that the desktop is usable.
    pub fn desktop_command(&self, desktop: X2GoDesktop) -> String {
        format!("(setsid x2goruncommand {} {} {} {} {} nosnd D </dev/null >/dev/null 2>&1 &)",
            self.display, self.agent_pid, self.session_id, self.sound_port, desktop.argument())
    }

    /// A safe command for explicit cleanup, based on the validated session ID.
    /// Constructing this string does not terminate the session.
    pub fn terminate_command(&self) -> String {
        format!("x2goterminate-session {}", self.session_id)
    }

    /// A safe command to suspend the session without terminating the desktop.
    pub fn suspend_command(&self) -> String {
        format!("x2gosuspend-session {}", self.session_id)
    }
}

/// Public, cookie-free metadata describing an active or suspended X2Go session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X2GoListedSession {
    pub session_id: String,
    pub display: u16,
    pub agent_pid: u32,
    pub status: String,
    pub created_at: String,
    pub desktop: Option<String>,
    pub graphics_port: u16,
}

/// Validates an X2Go session ID before using it as a shell argument.
pub fn validate_session_id(session_id: &str) -> Result<&str, &'static str> {
    if session_id.is_empty() || session_id.len() > 255 || session_id.starts_with('-') ||
        !session_id.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@')) {
        return Err("Invalid X2Go session ID.");
    }
    Ok(session_id)
}

/// Builds a validated `x2goresume-session` command without arbitrary shell input.
pub fn resume_command(session_id: &str, width: u16, height: u16, link: X2GoLink) -> Result<String, &'static str> {
    resume_command_with_clipboard(session_id, width, height, link, false)
}

pub fn resume_command_with_clipboard(session_id: &str, width: u16, height: u16, link: X2GoLink, allow_clipboard: bool) -> Result<String, &'static str> {
    let id = validate_session_id(session_id)?;
    if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION ||
        u32::from(width) * u32::from(height) > MAX_PIXELS {
        return Err("Invalid X2Go desktop dimensions.");
    }
    Ok(format!("x2goresume-session {id} {width}x{height} {} 16m-jpeg-9 us pc105/us 0 {}", link.argument(), if allow_clipboard { "both" } else { "none" }))
}

impl Drop for X2GoStartedSession {
    fn drop(&mut self) { self.cookie.zeroize(); }
}

/// Action requested from the independently running lifecycle task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AgentCleanup { Terminate, Suspend }

/// Owns a validated agent. An abandoned newly started agent is terminated;
/// an abandoned resumed session is suspended to avoid destroying its desktop.
/// Remote state is still unknown if SSH fails, times out, or the runtime exits.
pub struct X2GoAgentGuard {
    session: X2GoStartedSession,
    ssh: Option<Arc<SshConnection>>,
    release: Option<tokio::sync::oneshot::Sender<AgentCleanup>>,
    cleanup: Option<tokio::task::JoinHandle<Result<(), ProtoError>>>,
    on_drop: AgentCleanup,
}

impl X2GoAgentGuard {
    /// Use the same authenticated destination connection that started the agent.
    pub fn new(runtime: &tokio::runtime::Handle, ssh: Arc<SshConnection>, session: X2GoStartedSession) -> Self {
        Self::with_connection(runtime, ssh, session, AgentCleanup::Terminate)
    }

    fn resumed(runtime: &tokio::runtime::Handle, ssh: Arc<SshConnection>, session: X2GoStartedSession) -> Self {
        Self::with_connection(runtime, ssh, session, AgentCleanup::Suspend)
    }

    fn with_connection(runtime: &tokio::runtime::Handle, ssh: Arc<SshConnection>, session: X2GoStartedSession, on_drop: AgentCleanup) -> Self {
        let terminate = session.terminate_command();
        let suspend = session.suspend_command();
        let connection = Arc::clone(&ssh);
        let mut guard = Self::with_actions(runtime, session, on_drop, move |action| async move {
            let (command, failure) = match action {
                AgentCleanup::Terminate => (terminate, "Could not terminate the X2Go agent."),
                AgentCleanup::Suspend => (suspend, "Could not suspend the X2Go session."),
            };
            let output = ssh.exec_command_bounded(&command, Duration::from_secs(10), 8192).await?;
            if output.exit_code != Some(0) { return Err(ProtoError::Transport(failure.into())); }
            Ok(())
        });
        guard.ssh = Some(connection);
        guard
    }

    fn with_actions<C, F>(runtime: &tokio::runtime::Handle, session: X2GoStartedSession, on_drop: AgentCleanup, cleanup: C) -> Self
    where C: FnOnce(AgentCleanup) -> F + Send + 'static,
          F: Future<Output = Result<(), ProtoError>> + Send + 'static {
        let (release, wait) = tokio::sync::oneshot::channel();
        let task = runtime.spawn(async move { cleanup(wait.await.unwrap_or(on_drop)).await });
        Self { session, ssh: None, release: Some(release), cleanup: Some(task), on_drop }
    }

    #[cfg(test)]
    fn with_cleanup<F>(runtime: &tokio::runtime::Handle, session: X2GoStartedSession, cleanup: F) -> Self
    where F: Future<Output = Result<(), ProtoError>> + Send + 'static {
        Self::with_actions(runtime, session, AgentCleanup::Terminate, move |_| cleanup)
    }

    /// The graphics cookie must not be written to logs, IPC, or process arguments.
    pub fn session(&self) -> &X2GoStartedSession { &self.session }
    pub(crate) fn connection(&self) -> Option<&Arc<SshConnection>> { self.ssh.as_ref() }
    /// A resumed desktop should be suspended, not terminated, on unexpected loss.
    pub fn preserves_session_on_failure(&self) -> bool { self.on_drop == AgentCleanup::Suspend }

    async fn finish(mut self, action: AgentCleanup) -> Result<(), ProtoError> {
        if let Some(release) = self.release.take() { let _ = release.send(action); }
        let Some(task) = self.cleanup.take() else {
            return Err(ProtoError::Transport("X2Go cleanup is unavailable.".into()));
        };
        task.await.map_err(|_| ProtoError::Transport("X2Go cleanup task failed.".into()))?
    }

    /// Explicit termination continues in the background if the caller is cancelled.
    pub async fn close(self) -> Result<(), ProtoError> { self.finish(AgentCleanup::Terminate).await }
    /// Explicit suspension also continues if the caller is cancelled.
    pub async fn suspend(self) -> Result<(), ProtoError> { self.finish(AgentCleanup::Suspend).await }
    /// Release after a failed setup without destroying a resumed desktop.
    pub async fn cleanup_after_failure(self) -> Result<(), ProtoError> {
        let action = self.on_drop;
        self.finish(action).await
    }
}

/// Start an agent using the authenticated destination connection, then
/// immediately put its validated response under a cleanup guard. The detached
/// startup task continues if the caller cancels; if its result is no longer
/// wanted, dropping the returned guard schedules termination.
///
/// A timeout, disconnect, malformed reply, or process/runtime shutdown can
/// still leave an unidentifiable remote agent. These errors explicitly warn
/// that cleanup is unconfirmed; the caller must not assume no session exists.
/// The service uses this for experimental viewer startup; it does not itself
/// start a desktop.
pub async fn start_guarded_agent(
    ssh: Arc<SshConnection>, width: u16, height: u16, desktop: X2GoDesktop,
    link: X2GoLink, timeout: Duration,
) -> Result<X2GoAgentGuard, ProtoError> {
    start_guarded_agent_with_clipboard(ssh, width, height, desktop, link, timeout, false).await
}

pub async fn start_guarded_agent_with_clipboard(
    ssh: Arc<SshConnection>, width: u16, height: u16, desktop: X2GoDesktop,
    link: X2GoLink, timeout: Duration, allow_clipboard: bool,
) -> Result<X2GoAgentGuard, ProtoError> {
    let command = start_command_with_clipboard(width, height, desktop, link, allow_clipboard)
        .map_err(|_| ProtoError::Transport("Invalid X2Go startup parameters.".into()))?;
    if timeout.is_zero() || timeout > Duration::from_secs(120) {
        return Err(ProtoError::Transport("Invalid X2Go startup timeout.".into()));
    }
    let runtime = tokio::runtime::Handle::try_current()
        .map_err(|_| ProtoError::Transport("X2Go startup requires an active runtime.".into()))?;
    let task_runtime = runtime.clone();
    detach_startup(&runtime, async move {
        let output = ssh.exec_command_bounded(&command, timeout, MAX_REPLY_BYTES).await
            .map_err(|_| ProtoError::Transport("X2Go agent startup failed; remote cleanup could not be confirmed.".into()))?;
        // Neither stdout (which contains the cookie) nor stderr reaches IPC,
        // logs, error text, or Debug; erase both buffers when finished.
        let stdout = Zeroizing::new(output.stdout);
        let _stderr = Zeroizing::new(output.stderr);
        let session = parse_start_reply(&stdout, output.exit_code)
            .map_err(|_| ProtoError::Transport("Invalid X2Go agent response; remote cleanup could not be confirmed.".into()))?;
        Ok(X2GoAgentGuard::new(&task_runtime, ssh, session))
    }).await
}

async fn detach_startup<F>(runtime: &tokio::runtime::Handle, startup: F) -> Result<X2GoAgentGuard, ProtoError>
where F: Future<Output = Result<X2GoAgentGuard, ProtoError>> + Send + 'static {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    runtime.spawn(async move {
        // If the requester disappeared, the returned guard is dropped here,
        // triggering the same cleanup as an explicitly abandoned session.
        let _ = sender.send(startup.await);
    });
    receiver.await.map_err(|_| ProtoError::Transport("X2Go startup task ended; remote cleanup could not be confirmed.".into()))?
}

impl Drop for X2GoAgentGuard {
    fn drop(&mut self) {
        // Dropping the sender wakes the detached task; dropping a JoinHandle
        // does not abort it. Never wait for SSH while holding service locks.
        self.release.take();
    }
}

impl fmt::Debug for X2GoStartedSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X2GoStartedSession")
            .field("display", &self.display)
            .field("cookie", &"[redacted]")
            .field("agent_pid", &self.agent_pid)
            .field("session_id", &self.session_id)
            .field("graphics_port", &self.graphics_port)
            .field("sound_port", &self.sound_port)
            .field("sshfs_port", &self.sshfs_port)
            .field("telekinesis_ports", &self.telekinesis_ports)
            .finish()
    }
}

fn unsigned(field: &str) -> bool {
    !field.is_empty() && field.bytes().all(|byte| byte.is_ascii_digit())
}

fn port(field: &str) -> Result<u16, &'static str> {
    if !unsigned(field) { return Err("Invalid X2Go port."); }
    field.parse::<u16>().ok().filter(|number| *number != 0).ok_or("Invalid X2Go port.")
}

/// Parses only the documented seven- or nine-line response. Error strings do
/// not contain server output, which includes the secret session cookie.
pub fn parse_start_reply(stdout: &[u8], exit_status: Option<u32>) -> Result<X2GoStartedSession, &'static str> {
    if exit_status != Some(0) { return Err("X2Go agent startup did not succeed."); }
    if stdout.len() > MAX_REPLY_BYTES { return Err("X2Go agent response is too large."); }
    let text = std::str::from_utf8(stdout).map_err(|_| "Invalid X2Go agent response encoding.")?;
    let fields: Vec<&str> = text.lines().collect();
    if fields.len() != 7 && fields.len() != 9 { return Err("Invalid X2Go agent response fields."); }
    let display = port(fields[0]).map_err(|_| "Invalid X2Go display number.")?;
    let cookie = fields[1];
    if cookie.len() != 32 || !cookie.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Invalid X2Go session cookie.");
    }
    if !unsigned(fields[2]) { return Err("Invalid X2Go agent PID."); }
    let agent_pid = fields[2].parse::<u32>().ok().filter(|pid| *pid != 0).ok_or("Invalid X2Go agent PID.")?;
    let session_id = validate_session_id(fields[3])?;
    Ok(X2GoStartedSession {
        display,
        cookie: cookie.to_string(),
        agent_pid,
        session_id: session_id.to_string(),
        graphics_port: port(fields[4])?,
        sound_port: port(fields[5])?,
        sshfs_port: port(fields[6])?,
        telekinesis_ports: if fields.len() == 9 { Some((port(fields[7])?, port(fields[8])?)) } else { None },
    })
}

const MAX_LIST_BYTES: usize = 65536;

fn infer_desktop_from_session_id(session_id: &str) -> Option<String> {
    let upper = session_id.to_ascii_uppercase();
    for candidate in ["XFCE", "MATE", "LXDE"] {
        if upper.contains(candidate) {
            return Some(candidate.to_string());
        }
    }
    None
}

fn sanitize_timestamp(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ':' | '.' | 'T' | ' '))
        .take(64)
        .collect()
}

fn parse_listed_sessions_with_secrets(
    stdout: &[u8],
    exit_status: Option<u32>,
) -> Result<Vec<(X2GoListedSession, X2GoStartedSession)>, &'static str> {
    if exit_status != Some(0) {
        return Err("X2Go session listing did not succeed.");
    }
    if stdout.len() > MAX_LIST_BYTES {
        return Err("X2Go session listing is too large.");
    }
    let text = std::str::from_utf8(stdout).map_err(|_| "Invalid X2Go session listing encoding.")?;
    let mut out = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() < 14 {
            return Err("Invalid X2Go session listing fields.");
        }
        let status = parts[4].trim();
        if status == "F" {
            continue;
        }
        if status != "S" && status != "R" {
            continue;
        }
        if !unsigned(parts[0]) {
            return Err("Invalid X2Go agent PID.");
        }
        let agent_pid = parts[0].parse::<u32>().ok().filter(|pid| *pid != 0).ok_or("Invalid X2Go agent PID.")?;
        let session_id = validate_session_id(parts[1])?;
        let display = port(parts[2]).map_err(|_| "Invalid X2Go display number.")?;
        let cookie = parts[6].trim();
        if cookie.len() != 32 || !cookie.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("Invalid X2Go session cookie.");
        }
        let graphics_port = port(parts[8])?;
        let sound_port = if parts[9].is_empty() || parts[9] == "0" { 1 } else { port(parts[9])? };
        let sshfs_port = if parts[13].is_empty() || parts[13] == "0" { 1 } else { port(parts[13])? };
        let listed = X2GoListedSession {
            session_id: session_id.to_string(),
            display,
            agent_pid,
            status: status.to_string(),
            created_at: sanitize_timestamp(parts[5]),
            desktop: infer_desktop_from_session_id(session_id),
            graphics_port,
        };
        let secret = X2GoStartedSession {
            display,
            cookie: cookie.to_string(),
            agent_pid,
            session_id: session_id.to_string(),
            graphics_port,
            sound_port,
            sshfs_port,
            telekinesis_ports: None,
        };
        out.push((listed, secret));
    }
    Ok(out)
}

/// Parses `x2golistsessions` output into cookie-free session metadata.
pub fn parse_listed_sessions(stdout: &[u8], exit_status: Option<u32>) -> Result<Vec<X2GoListedSession>, &'static str> {
    let entries = parse_listed_sessions_with_secrets(stdout, exit_status)?;
    Ok(entries.into_iter().map(|(listed, _secret_zeroized_on_drop)| listed).collect())
}

/// Lists active and suspended X2Go sessions on the authenticated SSH server.
/// Secret session cookies in `x2golistsessions` stdout are zeroized immediately
/// and never returned.
pub async fn list_sessions(ssh: &SshConnection, timeout: Duration) -> Result<Vec<X2GoListedSession>, ProtoError> {
    if timeout.is_zero() || timeout > Duration::from_secs(60) {
        return Err(ProtoError::Transport("Invalid X2Go session list timeout.".into()));
    }
    let output = ssh.exec_command_bounded("x2golistsessions", timeout, MAX_LIST_BYTES).await?;
    let stdout = Zeroizing::new(output.stdout);
    let _stderr = Zeroizing::new(output.stderr);
    parse_listed_sessions(&stdout, output.exit_code)
        .map_err(|msg| ProtoError::Transport(msg.into()))
}

/// Explicitly terminates a listed session by validated ID.
pub async fn terminate_listed_session(ssh: &SshConnection, session_id: &str, timeout: Duration) -> Result<(), ProtoError> {
    let id = validate_session_id(session_id)
        .map_err(|msg| ProtoError::Transport(msg.into()))?;
    if timeout.is_zero() || timeout > Duration::from_secs(60) {
        return Err(ProtoError::Transport("Invalid X2Go termination timeout.".into()));
    }
    let command = format!("x2goterminate-session {id}");
    let output = ssh.exec_command_bounded(&command, timeout, 8192).await?;
    if output.exit_code != Some(0) {
        return Err(ProtoError::Transport("Could not terminate the X2Go session.".into()));
    }
    Ok(())
}

fn apply_resume_port_overrides(session: &mut X2GoStartedSession, stdout: &[u8]) -> Result<(), &'static str> {
    if stdout.len() > MAX_REPLY_BYTES {
        return Err("X2Go resume response is too large.");
    }
    let text = std::str::from_utf8(stdout).map_err(|_| "Invalid X2Go resume response encoding.")?;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if let Some(rest) = line.strip_prefix("gr_port=") {
            session.graphics_port = port(rest)?;
        } else if let Some(rest) = line.strip_prefix("sound_port=") {
            if !rest.is_empty() && rest != "0" {
                session.sound_port = port(rest)?;
            }
        } else if let Some(rest) = line.strip_prefix("fs_port=") {
            if !rest.is_empty() && rest != "0" {
                session.sshfs_port = port(rest)?;
            }
        }
    }
    Ok(())
}

/// Resumes a suspended X2Go session and wraps it in a cleanup guard.
pub async fn resume_guarded_agent(
    ssh: Arc<SshConnection>,
    session_id: &str,
    width: u16,
    height: u16,
    link: X2GoLink,
    timeout: Duration,
) -> Result<X2GoAgentGuard, ProtoError> {
    resume_guarded_agent_with_clipboard(ssh, session_id, width, height, link, timeout, false).await
}

pub async fn resume_guarded_agent_with_clipboard(
    ssh: Arc<SshConnection>, session_id: &str, width: u16, height: u16,
    link: X2GoLink, timeout: Duration, allow_clipboard: bool,
) -> Result<X2GoAgentGuard, ProtoError> {
    let command = resume_command_with_clipboard(session_id, width, height, link, allow_clipboard)
        .map_err(|msg| ProtoError::Transport(msg.into()))?;
    let target_id = session_id.to_string();
    if timeout.is_zero() || timeout > Duration::from_secs(120) {
        return Err(ProtoError::Transport("Invalid X2Go resume timeout.".into()));
    }
    let runtime = tokio::runtime::Handle::try_current()
        .map_err(|_| ProtoError::Transport("X2Go resume requires an active runtime.".into()))?;
    let task_runtime = runtime.clone();
    detach_startup(&runtime, async move {
        let list_out = ssh.exec_command_bounded("x2golistsessions", Duration::from_secs(15), MAX_LIST_BYTES).await
            .map_err(|_| ProtoError::Transport("Could not inspect suspended X2Go sessions.".into()))?;
        let list_stdout = Zeroizing::new(list_out.stdout);
        let _list_stderr = Zeroizing::new(list_out.stderr);
        let entries = parse_listed_sessions_with_secrets(&list_stdout, list_out.exit_code)
            .map_err(|msg| ProtoError::Transport(msg.into()))?;
        let Some((listed, session)) = entries.into_iter().find(|(l, _)| l.session_id == target_id) else {
            return Err(ProtoError::Transport("The selected X2Go session no longer exists.".into()));
        };
        if listed.status != "S" {
            return Err(ProtoError::Transport("Only suspended X2Go sessions can be resumed.".into()));
        }
        // Once resume is attempted, even a timeout or malformed reply may mean
        // the server resumed the desktop. Hold a suspend-on-drop guard first.
        let mut guard = X2GoAgentGuard::resumed(&task_runtime, ssh.clone(), session);
        let outcome = async {
            let output = ssh.exec_command_bounded(&command, timeout, MAX_REPLY_BYTES).await
                .map_err(|_| "X2Go session resume failed.")?;
            let stdout = Zeroizing::new(output.stdout);
            let _stderr = Zeroizing::new(output.stderr);
            if output.exit_code != Some(0) { return Err("X2Go session resume did not succeed."); }
            apply_resume_port_overrides(&mut guard.session, &stdout)?;
            Ok(())
        }.await;
        if let Err(error) = outcome {
            let suffix = if guard.cleanup_after_failure().await.is_ok() {
                "Suspension was requested; verify the session state on the server."
            } else {
                "Suspension could not be confirmed; verify the session state on the server."
            };
            return Err(ProtoError::Transport(format!("{error} {suffix}")));
        }
        Ok(guard)
    }).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const COOKIE: &str = "0123456789abcdef0123456789abcdef";

    fn reply(id: &str) -> String {
        format!("50\n{COOKIE}\n12345\n{id}\n31001\n31002\n31003\n")
    }

    #[test]
    fn desktop_startup_uses_only_validated_fields_and_never_the_cookie() {
        let session = parse_start_reply(reply("alice-50-test").as_bytes(), Some(0)).unwrap();
        for desktop in [X2GoDesktop::Xfce, X2GoDesktop::Mate, X2GoDesktop::Lxde] {
            let command = session.desktop_command(desktop);
            assert!(command.contains("x2goruncommand 50 12345 alice-50-test 31002"));
            assert!(command.contains(desktop.argument()));
            assert!(!command.contains(COOKIE));
        }
    }

    #[tokio::test]
    async fn abandoned_startup_continues_and_then_cleans_the_guard() {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
        let (cleanup_tx, cleanup_rx) = tokio::sync::oneshot::channel();
        let runtime = tokio::runtime::Handle::current();
        let task_runtime = runtime.clone();
        let caller = tokio::spawn(async move {
            detach_startup(&runtime, async move {
                let _ = ready_tx.send(());
                let _ = resume_rx.await;
                let session = parse_start_reply(reply("alice-50-test").as_bytes(), Some(0)).unwrap();
                Ok(X2GoAgentGuard::with_cleanup(&task_runtime, session, async move {
                    let _ = cleanup_tx.send(());
                    Ok(())
                }))
            }).await
        });
        ready_rx.await.unwrap();
        caller.abort();
        let _ = caller.await;
        resume_tx.send(()).unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(1), cleanup_rx).await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn closing_a_guard_waits_for_cleanup_once() {
        let session = parse_start_reply(reply("alice-50-test").as_bytes(), Some(0)).unwrap();
        let (signal, observed) = tokio::sync::oneshot::channel();
        let guard = X2GoAgentGuard::with_cleanup(&tokio::runtime::Handle::current(), session, async move {
            let _ = signal.send(());
            Ok(())
        });
        assert_eq!(guard.session().session_id(), "alice-50-test");
        assert!(guard.close().await.is_ok());
        assert!(observed.await.is_ok());
    }

    #[tokio::test]
    async fn dropping_a_guard_still_starts_cleanup() {
        let session = parse_start_reply(reply("alice-50-test").as_bytes(), Some(0)).unwrap();
        let (signal, observed) = tokio::sync::oneshot::channel();
        let guard = X2GoAgentGuard::with_cleanup(&tokio::runtime::Handle::current(), session, async move {
            let _ = signal.send(());
            Ok(())
        });
        drop(guard);
        assert!(tokio::time::timeout(Duration::from_secs(1), observed).await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn cancelled_close_does_not_abort_cleanup() {
        let session = parse_start_reply(reply("alice-50-test").as_bytes(), Some(0)).unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let guard = X2GoAgentGuard::with_cleanup(&tokio::runtime::Handle::current(), session, async move {
            let _ = started_tx.send(());
            let _ = finish_rx.await;
            let _ = done_tx.send(());
            Ok(())
        });
        let close = tokio::spawn(guard.close());
        started_rx.await.unwrap();
        close.abort();
        let _ = close.await;
        finish_tx.send(()).unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(1), done_rx).await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn resumed_guard_suspends_on_drop_and_setup_failure_but_close_terminates() {
        for operation in 0..3 {
            let session = parse_start_reply(reply("alice-50-test").as_bytes(), Some(0)).unwrap();
            let (signal, observed) = tokio::sync::oneshot::channel();
            let guard = X2GoAgentGuard::with_actions(&tokio::runtime::Handle::current(), session, AgentCleanup::Suspend, move |action| async move {
                let _ = signal.send(action);
                Ok(())
            });
            match operation {
                0 => drop(guard),
                1 => assert!(crate::x2go_transport::GuardedKDriveSession::attach(guard, 800, 600, Duration::from_secs(1)).await.is_err()),
                _ => assert!(guard.close().await.is_ok()),
            }
            let action = tokio::time::timeout(Duration::from_secs(1), observed).await.unwrap().unwrap();
            assert_eq!(action, if operation == 2 { AgentCleanup::Terminate } else { AgentCleanup::Suspend });
        }
    }

    #[tokio::test]
    async fn cancelled_explicit_suspend_does_not_abort_cleanup() {
        let session = parse_start_reply(reply("alice-50-test").as_bytes(), Some(0)).unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let guard = X2GoAgentGuard::with_actions(&tokio::runtime::Handle::current(), session, AgentCleanup::Terminate, move |action| async move {
            let _ = started_tx.send(action);
            let _ = finish_rx.await;
            let _ = done_tx.send(());
            Ok(())
        });
        let suspend = tokio::spawn(guard.suspend());
        assert_eq!(started_rx.await.unwrap(), AgentCleanup::Suspend);
        suspend.abort();
        let _ = suspend.await;
        finish_tx.send(()).unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(1), done_rx).await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn failed_graphics_attachment_waits_for_agent_cleanup() {
        let session = parse_start_reply(reply("alice-50-test").as_bytes(), Some(0)).unwrap();
        let (signal, observed) = tokio::sync::oneshot::channel();
        let guard = X2GoAgentGuard::with_cleanup(&tokio::runtime::Handle::current(), session, async move {
            let _ = signal.send(());
            Ok(())
        });
        let result = crate::x2go_transport::GuardedKDriveSession::attach(guard, 800, 600, Duration::from_secs(1)).await;
        assert!(result.is_err());
        assert!(observed.await.is_ok());
    }

    #[tokio::test]
    async fn cleanup_failure_is_reported_to_explicit_close() {
        let session = parse_start_reply(reply("alice-50-test").as_bytes(), Some(0)).unwrap();
        let guard = X2GoAgentGuard::with_cleanup(&tokio::runtime::Handle::current(), session, async {
            Err(ProtoError::Transport("cleanup failed".into()))
        });
        assert!(guard.close().await.is_err());
    }

    #[test]
    fn startup_command_is_bounded_and_uses_only_known_arguments() {
        assert_eq!(start_command(1280, 720, X2GoDesktop::Mate, X2GoLink::Adsl).unwrap(),
            "x2gostartagent 1280x720 adsl 16m-jpeg-9 unix-kde-depth_24 us pc105/us 0 K MATE none");
        assert!(start_command_with_clipboard(800, 600, X2GoDesktop::Xfce, X2GoLink::Lan, true).unwrap().ends_with(" XFCE both"));
        assert!(resume_command_with_clipboard("alice-50-test", 800, 600, X2GoLink::Lan, true).unwrap().ends_with(" 0 both"));
        assert!(resume_command_with_clipboard("alice-50-test", 800, 600, X2GoLink::Lan, false).unwrap().ends_with(" 0 none"));
        assert!(start_command(0, 10, X2GoDesktop::Xfce, X2GoLink::Lan).is_err());
        assert!(start_command(8193, 1, X2GoDesktop::Xfce, X2GoLink::Lan).is_err());
        assert!(start_command(8192, 8192, X2GoDesktop::Xfce, X2GoLink::Lan).is_err());
        for link in [X2GoLink::Modem, X2GoLink::Isdn, X2GoLink::Adsl, X2GoLink::Wan, X2GoLink::Lan] {
            for desktop in [X2GoDesktop::Xfce, X2GoDesktop::Mate, X2GoDesktop::Lxde] {
                let command = start_command(800, 600, desktop, link).unwrap();
                assert!(command.contains(&format!(" {} ", link.argument())));
                assert!(command.ends_with(&format!(" {} none", desktop.argument())));
            }
        }
    }

    #[test]
    fn documented_reply_parses_and_cookie_is_redacted() {
        let session = parse_start_reply(reply("alice-50-test_stD@host").as_bytes(), Some(0)).unwrap();
        assert_eq!(session.display, 50);
        assert_eq!(session.cookie(), COOKIE);
        assert_eq!(session.graphics_port, 31001);
        assert_eq!(session.telekinesis_ports, None);
        assert_eq!(session.terminate_command(), "x2goterminate-session alice-50-test_stD@host");
        assert!(!format!("{session:?}").contains(COOKIE));
        let extended = format!("{}31004\n31005\n", reply("alice-50-test"));
        let session = parse_start_reply(extended.replace('\n', "\r\n").as_bytes(), Some(0)).unwrap();
        assert_eq!(session.telekinesis_ports, Some((31004, 31005)));
    }

    #[test]
    fn untrusted_replies_cannot_inject_cleanup_commands_or_expose_cookie() {
        for id in ["", "-option", "../x", "id;touch pwned", "$(id)", "space here"] {
            let input = reply(id);
            let error = parse_start_reply(input.as_bytes(), Some(0)).unwrap_err();
            assert!(!error.contains(COOKIE));
        }
        for output in ["50\n", "invalid", "50\nnot-a-cookie\n1\nid\n1\n2\n3\n"] {
            assert!(parse_start_reply(output.as_bytes(), Some(0)).is_err());
        }
        assert!(parse_start_reply(&vec![b'a'; 8193], Some(0)).is_err());
        assert!(parse_start_reply(reply("safe-id").as_bytes(), None).is_err());
        assert!(parse_start_reply(reply("safe-id").as_bytes(), Some(1)).is_err());
        assert!(parse_start_reply(reply("safe-id").replace("31001", "0").as_bytes(), Some(0)).is_err());
        assert!(parse_start_reply(reply("safe-id").replace("31001", "65536").as_bytes(), Some(0)).is_err());
        assert!(parse_start_reply(format!("{}31004\n", reply("safe-id")).as_bytes(), Some(0)).is_err());
        assert!(parse_start_reply(&[0xff, 0xfe], Some(0)).is_err());
        assert!(parse_start_reply(reply("safe-id").replace(COOKIE, "bad-cookie-with-sensitive-details").as_bytes(), Some(0)).is_err());
    }

    #[test]
    fn listed_sessions_strip_cookies_and_validate_ids() {
        let raw = format!(
            "12345|alice-50-1700000_stDKXFCE_dp24|50|host|S|2026-11-20T10:00:00|{COOKIE}|127.0.0.1|31001|31002|2026-11-20T10:05:00|alice|300|31003\n\
             22222|alice-51-old|51|host|F|2026-11-19|{COOKIE}|127.0.0.1|31011|31012|2026-11-19|alice|900|31013\n"
        );
        let listed = parse_listed_sessions(raw.as_bytes(), Some(0)).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].session_id, "alice-50-1700000_stDKXFCE_dp24");
        assert_eq!(listed[0].status, "S");
        assert_eq!(listed[0].desktop.as_deref(), Some("XFCE"));
        assert_eq!(listed[0].graphics_port, 31001);
        assert!(!format!("{listed:?}").contains(COOKIE));
        assert_eq!(
            resume_command(&listed[0].session_id, 1280, 720, X2GoLink::Lan).unwrap(),
            "x2goresume-session alice-50-1700000_stDKXFCE_dp24 1280x720 lan 16m-jpeg-9 us pc105/us 0 none"
        );
        assert!(resume_command("-bad", 1280, 720, X2GoLink::Lan).is_err());
    }
}
