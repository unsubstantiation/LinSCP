//! SSH graphics transport for the experimental built-in X2Go KDrive viewer.
//!
//! This opens the SSH graphics channel and provides an opt-in KDrive handshake.
//! Agent lifecycle, browser image decoding, and window creation are handled by
//! other modules.

use linscp_platform::AsyncStream;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::kdrive_wire::{Decoder, Handshake, Message};
use crate::ssh::SshConnection;
use crate::x2go_control::{X2GoAgentGuard, X2GoDesktop, X2GoStartedSession};
use crate::ProtoError;

/// Opens the validated agent's graphics port on the SSH server's loopback.
///
/// `ssh` must be the authenticated destination connection on which `session`
/// was created, not a bastion or a newly constructed direct connection. That
/// preserves its host-key, proxy, and jump-host decisions. Failure is returned
/// to the caller; there is no direct TCP or external-viewer fallback. Dropping
/// the returned stream closes its SSH channel, but does not terminate the agent.
///
/// This primitive does not start an agent; the guarded session owner handles
/// startup and cleanup.
pub async fn open_graphics_stream(
    ssh: &SshConnection,
    session: &X2GoStartedSession,
) -> Result<Box<dyn AsyncStream>, ProtoError> {
    let stream = ssh.open_direct_tcpip_stream("127.0.0.1", session.graphics_port()).await?;
    Ok(Box::new(stream))
}

/// A negotiated graphics channel. The decoder retains any bytes received after
/// the server version, so a coalesced first frame is not lost.
pub struct KDriveChannel {
    pub stream: Box<dyn AsyncStream>,
    pub decoder: Decoder,
    pub server_version: u16,
}

/// Write the cookie and version, wait for the server's version, and send an
/// initial one-screen geometry. The timeout covers the entire exchange. Any
/// failure closes this channel by dropping it; it does not suspend or terminate
/// the remote X2Go agent. Callers must arrange lifecycle cleanup independently.
/// Do not call this on a direct TCP connection or before reliable cleanup exists.
pub async fn negotiate_kdrive(
    mut stream: Box<dyn AsyncStream>,
    cookie: &str,
    width: u16,
    height: u16,
    timeout: Duration,
) -> Result<KDriveChannel, ProtoError> {
    let mut handshake = Handshake::new(width, height)
        .map_err(|_| ProtoError::Transport("Invalid KDrive geometry.".into()))?;
    let hello = handshake.hello(cookie)
        .map_err(|_| ProtoError::Transport("Invalid KDrive session cookie.".into()))?;
    let exchange = async {
        stream.write_all(hello.bytes()).await
            .map_err(|_| ProtoError::Transport("Could not send KDrive handshake.".into()))?;
        stream.flush().await
            .map_err(|_| ProtoError::Transport("Could not flush KDrive handshake.".into()))?;
        drop(hello);
        let mut decoder = Decoder::new();
        let mut incoming = [0u8; 8192];
        let mut keepalives = 0u8;
        loop {
            if let Some(message) = decoder.next_message()
                .map_err(|_| ProtoError::Transport("Invalid KDrive handshake response.".into()))? {
                match message {
                    Message::ServerVersion(version) => {
                        let geometry = handshake.accept_version(version)
                            .map_err(|_| ProtoError::Transport("Unsupported KDrive server version.".into()))?;
                        stream.write_all(&geometry).await
                            .map_err(|_| ProtoError::Transport("Could not send KDrive geometry.".into()))?;
                        stream.flush().await
                            .map_err(|_| ProtoError::Transport("Could not flush KDrive geometry.".into()))?;
                        return Ok(KDriveChannel { stream, decoder, server_version: version });
                    }
                    Message::Keepalive if keepalives < 16 => keepalives += 1,
                    _ => return Err(ProtoError::Transport("Unexpected KDrive handshake response.".into())),
                }
            } else {
                let count = stream.read(&mut incoming).await
                    .map_err(|_| ProtoError::Transport("Could not read KDrive handshake.".into()))?;
                if count == 0 { return Err(ProtoError::Transport("KDrive graphics channel closed during handshake.".into())); }
                decoder.feed(&incoming[..count])
                    .map_err(|_| ProtoError::Transport("KDrive handshake response exceeded limits.".into()))?;
            }
        }
    };
    tokio::time::timeout(timeout, exchange).await
        .map_err(|_| ProtoError::Transport("KDrive handshake timed out.".into()))?
}

/// A graphics channel tied to the guard for the agent that created it.
/// Dropping this value closes both stream halves and schedules best-effort
/// termination via the guard. Explicit close reports termination errors.
pub struct GuardedKDriveSession {
    pub reader: KDriveReader,
    pub writer: KDriveWriter,
    agent: X2GoAgentGuard,
    desktop_started: bool,
}

impl GuardedKDriveSession {
    /// Attach only to the connection held by the agent guard, so a bastion or
    /// another host cannot be used for the cookie handshake. The caller must
    /// have obtained and guarded a validated startup response first; this does
    /// not start the agent or the remote desktop environment. On cancellation,
    /// guard drop schedules cleanup. On setup failure, cleanup is awaited.
    pub async fn attach(agent: X2GoAgentGuard, width: u16, height: u16, timeout: Duration) -> Result<Self, ProtoError> {
        let result = tokio::time::timeout(timeout, async {
            let ssh = agent.connection().ok_or_else(|| ProtoError::Transport("Missing X2Go SSH connection.".into()))?;
            let stream = open_graphics_stream(ssh.as_ref(), agent.session()).await?;
            negotiate_kdrive(stream, agent.session().cookie(), width, height, timeout).await
        }).await;
        match result {
            Ok(Ok(channel)) => {
                let (reader, writer) = channel.into_halves();
                Ok(Self { reader, writer, agent, desktop_started: false })
            }
            _ => {
                if agent.cleanup_after_failure().await.is_err() {
                    return Err(ProtoError::Transport("X2Go graphics setup failed and agent cleanup could not be confirmed.".into()));
                }
                Err(ProtoError::Transport("X2Go graphics setup failed; agent cleanup was requested.".into()))
            }
        }
    }

    /// Launch the selected desktop after the graphics handshake. This runs a
    /// fixed command over the same authenticated connection. Shell success is
    /// not proof that the background desktop actually started. If this future
    /// is cancelled or returns an error the owner must close the entire session.
    pub async fn start_desktop(&mut self, desktop: X2GoDesktop) -> Result<(), ProtoError> {
        if self.desktop_started { return Err(ProtoError::Transport("X2Go desktop start was already requested.".into())); }
        self.desktop_started = true;
        let ssh = self.agent.connection().ok_or_else(|| ProtoError::Transport("Missing X2Go SSH connection.".into()))?;
        let command = self.agent.session().desktop_command(desktop);
        let result = ssh.exec_command_bounded(&command, Duration::from_secs(15), 8192).await
            .map_err(|_| ProtoError::Transport("Could not start the X2Go desktop.".into()))?;
        if result.exit_code != Some(0) { return Err(ProtoError::Transport("Could not start the X2Go desktop.".into())); }
        Ok(())
    }

    /// Transfer ownership to a service bridge. The owner must keep the guard
    /// until both halves are dropped and then await its cleanup.
    pub fn into_parts(self) -> (KDriveReader, KDriveWriter, X2GoAgentGuard) {
        (self.reader, self.writer, self.agent)
    }

    pub async fn close(self) -> Result<(), ProtoError> {
        let Self { reader, writer, agent, .. } = self;
        drop(reader);
        drop(writer);
        agent.close().await
    }

    pub async fn suspend(self) -> Result<(), ProtoError> {
        let Self { reader, writer, agent, .. } = self;
        drop(reader);
        drop(writer);
        agent.suspend().await
    }
}

/// Translate parsed graphics messages into the viewer IPC contract. The caller
/// must keep this stream ordered and bound the number of queued replies. Screen
/// contents are sensitive: do not log the JSON or send it to another session.
/// Clipboard, selection and cursor messages are deliberately not forwarded by
/// this minimal helper; see `viewer_message_extended` for cursor and opt-in
/// clipboard forwarding. Rootless windows and UDP fail closed.
pub fn viewer_message(message: Message) -> Result<Option<serde_json::Value>, ProtoError> {
    if matches!(&message, Message::Cursor(_) | Message::DeletedCursors(_) | Message::Selection(_) | Message::DemandSelection(_)) {
        return Ok(None);
    }
    viewer_message_extended(message, false)
}

/// Extended viewer IPC adapter that forwards server cursor shapes/deletions and,
/// when `allow_clipboard` is explicitly enabled, selection/clipboard events.
pub fn viewer_message_extended(
    message: Message,
    allow_clipboard: bool,
) -> Result<Option<serde_json::Value>, ProtoError> {
    use base64::Engine as _;
    use serde_json::json;
    let result = match message {
        Message::Frame(frame) => {
            let regions: Vec<_> = frame.regions.into_iter().map(|r| json!({
                "sourceId": r.source_id, "sourceX": r.source_x, "sourceY": r.source_y,
                "x": r.x, "y": r.y, "width": r.width, "height": r.height,
                "data": base64::engine::general_purpose::STANDARD.encode(&r.data),
            })).collect();
            json!({"type": "frame", "frame": {
                "width": frame.width, "height": frame.height, "x": frame.x, "y": frame.y,
                "cacheId": frame.cache_id, "windowId": frame.window_id, "regions": regions,
            }})
        }
        Message::DeletedFrames(ids) => json!({"type": "deleted-frames", "ids": ids}),
        Message::Cursor(cursor) => {
            if cursor.width == 0 || cursor.width > 256 || cursor.height == 0 || cursor.height > 256
                || cursor.data.len() > 256 * 256 * 4
            {
                return Ok(None);
            }
            json!({"type": "cursor", "cursor": {
                "serial": cursor.serial,
                "width": cursor.width,
                "height": cursor.height,
                "hotX": cursor.hot_x.min(cursor.width.saturating_sub(1)),
                "hotY": cursor.hot_y.min(cursor.height.saturating_sub(1)),
                "foreground": cursor.foreground,
                "background": cursor.background,
                "data": base64::engine::general_purpose::STANDARD.encode(&cursor.data),
            }})
        }
        Message::DeletedCursors(ids) => json!({"type": "deleted-cursors", "ids": ids}),
        Message::Selection(sel) => {
            if !allow_clipboard {
                return Ok(None);
            }
            json!({"type": "selection", "selection": {
                "selection": sel.selection,
                "format": sel.format,
                "chunkSize": sel.chunk_size,
                "first": sel.first,
                "last": sel.last,
                "compressedSize": sel.compressed_size,
                "total": sel.total,
                "data": base64::engine::general_purpose::STANDARD.encode(&sel.data),
            }})
        }
        Message::DemandSelection(selection) => {
            if !allow_clipboard {
                return Ok(None);
            }
            json!({"type": "demand-selection", "selection": selection})
        }
        Message::Reinitialize => json!({"type": "reinitialize"}),
        Message::Keepalive => json!({"type": "keepalive"}),
        Message::Disconnect => json!({"type": "disconnect"}),
        Message::WindowUpdate(_) | Message::UdpOpen | Message::UdpFailed | Message::ServerVersion(_) => {
            return Err(ProtoError::Transport("Unsupported KDrive viewer message.".into()));
        }
    };
    Ok(Some(result))
}

/// Ordered reader and writer halves of a negotiated graphics stream. The owner
/// must drop both on any failure or cancellation, and must terminate the remote
/// X2Go agent separately. They do not spawn tasks or start a remote session.
pub struct KDriveReader {
    stream: tokio::io::ReadHalf<Box<dyn AsyncStream>>,
    decoder: Decoder,
    closed: bool,
}

pub struct KDriveWriter {
    stream: tokio::io::WriteHalf<Box<dyn AsyncStream>>,
    closed: bool,
}

impl KDriveChannel {
    /// Preserve bytes read during negotiation while allowing writes to proceed
    /// independently of a reader waiting for the next server message.
    pub fn into_halves(self) -> (KDriveReader, KDriveWriter) {
        let (reader, writer) = tokio::io::split(self.stream);
        (KDriveReader { stream: reader, decoder: self.decoder, closed: false },
         KDriveWriter { stream: writer, closed: false })
    }
}

impl KDriveReader {
    /// Read the next message in wire order, including messages coalesced with
    /// the version response. Unknown or invalid wire data closes the reader;
    /// callers must not skip a message and continue rendering a stale screen.
    /// This returns compressed images, not decoded pixels. Clipboard and cursor
    /// payloads must not be logged or exposed without explicit authorization.
    pub async fn next_message(&mut self) -> Result<Message, ProtoError> {
        if self.closed { return Err(ProtoError::Transport("KDrive graphics reader is closed.".into())); }
        let mut incoming = [0u8; 8192];
        loop {
            match self.decoder.next_message() {
                Ok(Some(Message::ServerVersion(_))) => {
                    self.closed = true;
                    return Err(ProtoError::Transport("Unexpected KDrive version message.".into()));
                }
                Ok(Some(message)) => {
                    if matches!(&message, Message::Disconnect) { self.closed = true; }
                    return Ok(message);
                }
                Err(_) => {
                    self.closed = true;
                    return Err(ProtoError::Transport("Invalid KDrive graphics message.".into()));
                }
                Ok(None) => {}
            }
            let count = match self.stream.read(&mut incoming).await {
                Ok(n) => n,
                Err(_) => {
                    self.closed = true;
                    return Err(ProtoError::Transport("Could not read KDrive graphics channel.".into()));
                }
            };
            if count == 0 {
                self.closed = true;
                return Err(ProtoError::Transport("KDrive graphics channel closed.".into()));
            }
            if self.decoder.feed(&incoming[..count]).is_err() {
                self.closed = true;
                return Err(ProtoError::Transport("KDrive graphics input exceeded limits.".into()));
            }
        }
    }
}

impl KDriveWriter {
    /// Write exactly one client event. The owner must serialize calls and only
    /// provide protocol-validated events. If this future is cancelled midway,
    /// discard both halves: a partially written packet cannot be resynchronized.
    /// A bounded timeout covers both the write and flush.
    pub async fn write_event(&mut self, event: &[u8; crate::kdrive_wire::CLIENT_EVENT_SIZE], timeout: Duration) -> Result<(), ProtoError> {
        if self.closed { return Err(ProtoError::Transport("KDrive graphics writer is closed.".into())); }
        let write = async {
            self.stream.write_all(event).await?;
            self.stream.flush().await
        };
        match tokio::time::timeout(timeout, write).await {
            Ok(Ok(())) => Ok(()),
            _ => {
                self.closed = true;
                Err(ProtoError::Transport("Could not write KDrive graphics event.".into()))
            }
        }
    }

    /// Write an opt-in UTF-8 text clipboard selection packet (KDrive event 9).
    pub async fn write_selection(&mut self, selection: u32, text: &[u8], timeout: Duration) -> Result<(), ProtoError> {
        const MAX_CLIPBOARD_WRITE: usize = 64 * 1024;
        if self.closed {
            return Err(ProtoError::Transport("KDrive graphics writer is closed.".into()));
        }
        if selection > 1 || text.len() > MAX_CLIPBOARD_WRITE {
            return Err(ProtoError::Transport("Invalid KDrive clipboard selection.".into()));
        }
        let len = text.len() as u32;
        let mut header = [0u8; crate::kdrive_wire::CLIENT_EVENT_SIZE];
        header[0..4].copy_from_slice(&9u32.to_le_bytes());
        header[4..8].copy_from_slice(&selection.to_le_bytes());
        header[8..12].copy_from_slice(&0u32.to_le_bytes()); // format 0 = UTF-8 text
        header[12..16].copy_from_slice(&len.to_le_bytes());
        header[16..20].copy_from_slice(&1u32.to_le_bytes()); // first
        header[20..24].copy_from_slice(&1u32.to_le_bytes()); // last
        header[24..28].copy_from_slice(&0u32.to_le_bytes()); // uncompressed
        header[28..32].copy_from_slice(&len.to_le_bytes()); // total
        let write = async {
            self.stream.write_all(&header).await?;
            if !text.is_empty() {
                self.stream.write_all(text).await?;
            }
            self.stream.flush().await
        };
        match tokio::time::timeout(timeout, write).await {
            Ok(Ok(())) => Ok(()),
            _ => {
                self.closed = true;
                Err(ProtoError::Transport("Could not write KDrive clipboard selection.".into()))
            }
        }
    }
}

#[cfg(test)]
mod handshake_tests {
    use super::*;
    use crate::kdrive_wire::{SERVER_HEADER_SIZE, CLIENT_EVENT_SIZE};

    const COOKIE: &str = "0123456789abcdef0123456789abcdef";

    fn server_header(kind: u32, version: u16) -> [u8; SERVER_HEADER_SIZE] {
        let mut h = [0u8; SERVER_HEADER_SIZE];
        h[..4].copy_from_slice(&kind.to_le_bytes());
        h[4..6].copy_from_slice(&version.to_le_bytes());
        h
    }

    #[test]
    fn viewer_contract_encodes_graphics_but_never_clipboard_or_cursor_data() {
        use crate::kdrive_wire::{Frame, Region, Selection};
        let frame = Frame { width: 2, height: 1, x: -1, y: -1, cache_id: 0, window_id: 0,
            regions: vec![Region { source_id: 0, source_x: 0, source_y: 0, x: 0, y: 0,
                width: 2, height: 1, data: vec![1, 2, 3] }] };
        let value = viewer_message(Message::Frame(frame)).unwrap().unwrap();
        assert_eq!(value["type"], "frame");
        assert_eq!(value["frame"]["cacheId"], 0);
        assert_eq!(value["frame"]["regions"][0]["data"], "AQID");
        let selection = Selection { selection: 0, format: 0, chunk_size: 1, first: true, last: true,
            compressed_size: 0, total: 1, data: vec![42] };
        assert!(viewer_message(Message::Selection(selection)).unwrap().is_none());
        assert!(viewer_message(Message::DemandSelection(0)).unwrap().is_none());
        assert!(viewer_message(Message::WindowUpdate(vec![])).is_err());
    }

    #[tokio::test]
    async fn split_preserves_buffered_messages_and_orders_subsequent_reads() {
        let (client, mut server) = tokio::io::duplex(1024);
        let mut decoder = Decoder::new();
        decoder.feed(&server_header(9, 0)).unwrap(); // keepalive buffered during handshake
        let channel = KDriveChannel { stream: Box::new(client), decoder, server_version: 8 };
        let (mut reader, _writer) = channel.into_halves();
        assert!(matches!(reader.next_message().await.unwrap(), Message::Keepalive));
        let disconnect = server_header(10, 0);
        server.write_all(&disconnect[..17]).await.unwrap();
        server.write_all(&disconnect[17..]).await.unwrap();
        assert!(matches!(reader.next_message().await.unwrap(), Message::Disconnect));
        assert!(reader.next_message().await.is_err());
    }

    #[tokio::test]
    async fn writing_is_independent_of_a_reader_waiting_for_input() {
        let (client, mut server) = tokio::io::duplex(1024);
        let channel = KDriveChannel { stream: Box::new(client), decoder: Decoder::new(), server_version: 8 };
        let (mut reader, mut writer) = channel.into_halves();
        let expected = [42u8; CLIENT_EVENT_SIZE];
        let peer = tokio::spawn(async move {
            let mut sent = [0; CLIENT_EVENT_SIZE];
            server.read_exact(&mut sent).await.unwrap();
            assert_eq!(sent, [42u8; CLIENT_EVENT_SIZE]);
            server.write_all(&server_header(9, 0)).await.unwrap();
        });
        let (message, sent) = tokio::join!(reader.next_message(), writer.write_event(&expected, Duration::from_secs(2)));
        assert!(matches!(message.unwrap(), Message::Keepalive));
        assert!(sent.is_ok());
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_and_duplicate_version_messages_fail_closed() {
        for header in [server_header(5, 8), server_header(0xffffffff, 0)] {
            let (client, mut server) = tokio::io::duplex(1024);
            let channel = KDriveChannel { stream: Box::new(client), decoder: Decoder::new(), server_version: 8 };
            let (mut reader, _writer) = channel.into_halves();
            server.write_all(&header).await.unwrap();
            assert!(reader.next_message().await.is_err());
            assert!(reader.next_message().await.is_err());
        }
    }

    #[tokio::test]
    async fn failed_write_permanently_closes_writer() {
        let (client, server) = tokio::io::duplex(64);
        drop(server);
        let channel = KDriveChannel { stream: Box::new(client), decoder: Decoder::new(), server_version: 8 };
        let (_reader, mut writer) = channel.into_halves();
        let event = [0u8; CLIENT_EVENT_SIZE];
        assert!(writer.write_event(&event, Duration::from_secs(1)).await.is_err());
        assert!(writer.write_event(&event, Duration::from_secs(1)).await.is_err());
    }

    #[tokio::test]
    async fn exchanges_handshake_and_keeps_coalesced_messages() {
        let (client, mut server) = tokio::io::duplex(1024);
        let peer = tokio::spawn(async move {
            let mut hello = [0; 32 + CLIENT_EVENT_SIZE];
            server.read_exact(&mut hello).await.unwrap();
            assert_eq!(&hello[..32], COOKIE.as_bytes());
            assert_eq!(&hello[32..40], &[10, 0, 0, 0, 3, 0, 1, 0]);
            server.write_all(&server_header(9, 0)).await.unwrap();
            let bytes = [server_header(5, 8), server_header(7, 0)].concat();
            server.write_all(&bytes).await.unwrap();
            let mut geometry = [0; CLIENT_EVENT_SIZE];
            server.read_exact(&mut geometry).await.unwrap();
            assert_eq!(&geometry[..13], &[7, 0, 0, 0, 0, 5, 208, 2, 0, 0, 5, 208, 2]);
            server
        });
        let mut conn = negotiate_kdrive(Box::new(client), COOKIE, 1280, 720, Duration::from_secs(2)).await.unwrap();
        assert_eq!(conn.server_version, 8);
        // The version and next message may be coalesced, or the transport may
        // split them; either way no post-version bytes are discarded.
        let mut bytes = [0; 128];
        loop {
            if let Some(message) = conn.decoder.next_message().unwrap() {
                assert!(matches!(message, Message::Reinitialize));
                break;
            }
            let count = conn.stream.read(&mut bytes).await.unwrap();
            assert_ne!(count, 0);
            conn.decoder.feed(&bytes[..count]).unwrap();
        }
        drop(peer.await.unwrap());
    }

    #[tokio::test]
    async fn rejects_old_wrong_and_silent_servers_without_fallback() {
        for (reply, expected) in [
            (Some(server_header(5, 6)), "Unsupported"),
            (Some(server_header(7, 0)), "Unexpected"),
            (None, "timed out"),
        ] {
            let (client, mut server) = tokio::io::duplex(1024);
            let peer = tokio::spawn(async move {
                let mut hello = [0; 32 + CLIENT_EVENT_SIZE];
                server.read_exact(&mut hello).await.unwrap();
                if let Some(bytes) = reply { server.write_all(&bytes).await.unwrap(); }
                tokio::time::sleep(Duration::from_secs(2)).await;
            });
            let result = negotiate_kdrive(Box::new(client), COOKIE, 800, 600, Duration::from_millis(500)).await;
            match result {
                Ok(_) => panic!("unexpected successful handshake"),
                Err(error) => assert!(format!("{error}").contains(expected)),
            }
            peer.abort();
        }
    }

    #[tokio::test]
    async fn extended_viewer_message_gates_clipboard_and_writes_selection() {
        let cursor = crate::kdrive_wire::Cursor {
            foreground: [0xff, 0xff, 0xff],
            background: [0x00, 0x00, 0x00],
            width: 2,
            height: 2,
            hot_x: 1,
            hot_y: 1,
            serial: 7,
            data: vec![0xff; 16],
        };
        let cur_json = viewer_message_extended(Message::Cursor(cursor), false)
            .unwrap()
            .expect("cursor forwarded");
        assert_eq!(cur_json["type"], "cursor");
        assert_eq!(cur_json["cursor"]["serial"], 7);

        let make_sel = || crate::kdrive_wire::Selection {
            selection: 1,
            format: 0,
            chunk_size: 5,
            first: true,
            last: true,
            compressed_size: 0,
            total: 5,
            data: b"hello".to_vec(),
        };
        assert!(viewer_message_extended(Message::Selection(make_sel()), false)
            .unwrap()
            .is_none());
        let sel_json = viewer_message_extended(Message::Selection(make_sel()), true)
            .unwrap()
            .expect("selection forwarded when opted in");
        assert_eq!(sel_json["type"], "selection");
        assert_eq!(sel_json["selection"]["format"], 0);

        assert!(viewer_message_extended(Message::DemandSelection(1), false)
            .unwrap()
            .is_none());
        let demand_json = viewer_message_extended(Message::DemandSelection(1), true)
            .unwrap()
            .expect("demand-selection forwarded when opted in");
        assert_eq!(demand_json["type"], "demand-selection");

        let (client, mut server) = tokio::io::duplex(256);
        let channel = KDriveChannel {
            stream: Box::new(client),
            decoder: Decoder::new(),
            server_version: 8,
        };
        let (_reader, mut writer) = channel.into_halves();
        writer
            .write_selection(1, b"clip-test", Duration::from_secs(1))
            .await
            .expect("write selection");
        let mut wire = vec![0u8; CLIENT_EVENT_SIZE + 9];
        server.read_exact(&mut wire).await.unwrap();
        assert_eq!(u32::from_le_bytes(wire[0..4].try_into().unwrap()), 9);
        assert_eq!(&wire[CLIENT_EVENT_SIZE..], b"clip-test");
    }
}
