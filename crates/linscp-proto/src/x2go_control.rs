//! X2Go KDrive session-control primitives.
//!
//! These construct and parse session-control messages without executing
//! commands. They do not implement the KDrive graphics protocol. Callers must
//! not start an agent until they can attach a graphics transport and reliably
//! clean up the remote session.

use std::fmt;

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

    /// A safe command for explicit cleanup, based on the validated session ID.
    /// Constructing this string does not terminate the session.
    pub fn terminate_command(&self) -> String {
        format!("x2goterminate-session {}", self.session_id)
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
