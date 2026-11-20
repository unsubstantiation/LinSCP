//! X2Go KDrive session-control primitives.
//!
//! Session-control primitives, guarded startup and best-effort termination for
//! X2Go KDrive. The service does not yet expose startup to users. Callers must
//! not start an agent until they can attach graphics and manage its lifecycle.

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
    if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION ||
        u32::from(width) * u32::from(height) > MAX_PIXELS {
        return Err("Invalid X2Go desktop dimensions.");
    }
    Ok(format!(
        "x2gostartagent {width}x{height} {} 16m-jpeg-9 unix-kde-depth_24 us pc105/us 0 K {} none",
        link.argument(), desktop.argument()
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
}

impl Drop for X2GoStartedSession {
    fn drop(&mut self) { self.cookie.zeroize(); }
}

/// Owns an already-started, validated agent. Releasing the guard triggers a
/// single bounded termination attempt over the same authenticated SSH session.
/// This does not start an agent and must be created immediately after a valid
/// startup response, before graphics setup. Explicit `close` reports cleanup
/// failure; dropping schedules best-effort cleanup without blocking.
///
/// Runtime shutdown, process termination, broken SSH, and malformed or missing
/// startup replies can still leave remote agents behind. The caller must expose
/// cleanup failures and must not claim that Drop guarantees remote termination.
pub struct X2GoAgentGuard {
    session: X2GoStartedSession,
    ssh: Option<Arc<SshConnection>>,
    release: Option<tokio::sync::oneshot::Sender<()>>,
    cleanup: Option<tokio::task::JoinHandle<Result<(), ProtoError>>>,
}

impl X2GoAgentGuard {
    /// The handle must be the runtime that owns the SSH connection, and it must
    /// remain running until cleanup finishes. The connection must be the same
    /// destination on which the agent was started, never a new direct session.
    pub fn new(runtime: &tokio::runtime::Handle, ssh: Arc<SshConnection>, session: X2GoStartedSession) -> Self {
        let command = session.terminate_command();
        let connection = Arc::clone(&ssh);
        let cleanup = async move {
            let output = ssh.exec_command_bounded(&command, Duration::from_secs(10), 8192).await?;
            if output.exit_code != Some(0) {
                return Err(ProtoError::Transport("Could not terminate the X2Go agent.".into()));
            }
            Ok(())
        };
        let mut guard = Self::with_cleanup(runtime, session, cleanup);
        guard.ssh = Some(connection);
        guard
    }

    fn with_cleanup<F>(runtime: &tokio::runtime::Handle, session: X2GoStartedSession, cleanup: F) -> Self
    where F: Future<Output = Result<(), ProtoError>> + Send + 'static {
        let (release, wait) = tokio::sync::oneshot::channel();
        let task = runtime.spawn(async move {
            // Receiving either a signal or sender drop means the owner ended.
            let _ = wait.await;
            cleanup.await
        });
        Self { session, ssh: None, release: Some(release), cleanup: Some(task) }
    }

    /// The graphics handshake needs the cookie, but it must never leave the
    /// authenticated channel or be written to logs, IPC, or process arguments.
    pub fn session(&self) -> &X2GoStartedSession { &self.session }

    pub(crate) fn connection(&self) -> Option<&Arc<SshConnection>> { self.ssh.as_ref() }

    /// Trigger cleanup and wait for its result. If this future is cancelled the
    /// detached cleanup task continues while the runtime is still running.
    pub async fn close(mut self) -> Result<(), ProtoError> {
        if let Some(release) = self.release.take() { let _ = release.send(()); }
        let Some(task) = self.cleanup.take() else {
            return Err(ProtoError::Transport("X2Go cleanup is unavailable.".into()));
        };
        match task.await {
            Ok(result) => result,
            Err(_) => Err(ProtoError::Transport("X2Go cleanup task failed.".into())),
        }
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
    let command = start_command(width, height, desktop, link)
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
    let session_id = fields[3];
    if session_id.is_empty() || session_id.len() > 255 || session_id.starts_with('-') ||
        !session_id.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@')) {
        return Err("Invalid X2Go session ID.");
    }
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
}
