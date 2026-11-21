//! Bounded service bridge for an already-negotiated X2Go graphics channel.
//!
//! The service owns this bridge and associates it with a tab and viewer
//! generation. It preserves ordered messages and performs guarded cleanup.
//! Authentication and API routing are the service owner's responsibility.

use std::future::Future;
use std::time::Duration;

use linscp_proto::desktop_frame_cache::WireFrameTracker;
use linscp_proto::kdrive_wire::{Message, CLIENT_EVENT_SIZE};
use linscp_proto::x2go_transport::{viewer_message_extended, GuardedKDriveSession, KDriveReader, KDriveWriter};
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

const INPUT_QUEUE: usize = 64;
// One queued frame and one pending frame, bounded by the wire parser's 16 MiB
// message limit. Backpressure stops further SSH reads rather than dropping a
// delta and silently corrupting the screen.
const OUTPUT_QUEUE: usize = 1;
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
// A viewer that disappears without closing must not leave the agent running.
const VIEWER_LEASE: Duration = Duration::from_secs(60);
// A connected server normally sends keepalives during idle periods. Bound a
// silent/broken SSH graphics channel rather than displaying a frozen desktop.
const SERVER_SILENCE: Duration = Duration::from_secs(45);

fn u32_at(packet: &[u8; CLIENT_EVENT_SIZE], offset: usize) -> u32 {
    u32::from_le_bytes([packet[offset], packet[offset + 1], packet[offset + 2], packet[offset + 3]])
}
fn u16_at(packet: &[u8; CLIENT_EVENT_SIZE], offset: usize) -> u16 {
    u16::from_le_bytes([packet[offset], packet[offset + 1]])
}
fn zero_after(packet: &[u8; CLIENT_EVENT_SIZE], offset: usize) -> bool {
    packet[offset..].iter().all(|byte| *byte == 0)
}

/// Only accept fixed-format input and control events. In particular a browser
/// cannot send a cookie, clipboard payload or arbitrary unframed bytes over
/// the server's authenticated SSH connection.
pub fn validate_input(packet: &[u8; CLIENT_EVENT_SIZE]) -> bool {
    let kind = u32_at(packet, 0);
    let first = u32_at(packet, 4);
    let second = u32_at(packet, 8);
    match kind {
        2 | 3 => first <= 255 && (8..=255).contains(&second) && zero_after(packet, 12),
        4 | 5 => first <= 255 && (1..=9).contains(&second) && zero_after(packet, 12),
        6 => first < 8192 && second < 8192 && zero_after(packet, 12),
        7 => {
            let width = u16_at(packet, 4) as u32;
            let height = u16_at(packet, 6) as u32;
            width > 0 && height > 0 && width <= 8192 && height <= 8192 && width * height <= 16_777_216
                && packet[8] == 0 && u16_at(packet, 9) as u32 == width
                && u16_at(packet, 11) as u32 == height && zero_after(packet, 13)
        }
        8 => {
            let x = u32_at(packet, 12);
            let y = u32_at(packet, 16);
            first > 0 && second > 0 && first <= 8192 && second <= 8192
                && first * second <= 16_777_216 && x <= 8192 - first && y <= 8192 - second
                && zero_after(packet, 20)
        }
        12 | 13 | 15 => zero_after(packet, 4),
        _ => false,
    }
}

const MAX_CLIPBOARD_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExitMode {
    Terminate,
    Suspend,
}

enum Command {
    Write([u8; CLIENT_EVENT_SIZE], oneshot::Sender<Result<(), &'static str>>),
    WriteClipboard(Vec<u8>, oneshot::Sender<Result<(), &'static str>>),
    Touch,
    Close,
    Suspend,
}

/// Cloneable write side so an API request never holds the service state mutex
/// while waiting for a remote write.
#[derive(Clone)]
pub struct X2GoInput {
    commands: mpsc::Sender<Command>,
    allow_clipboard: bool,
}

impl X2GoInput {
    pub async fn write(&self, packet: [u8; CLIENT_EVENT_SIZE]) -> Result<(), &'static str> {
        if !validate_input(&packet) { return Err("Invalid KDrive input event."); }
        let (reply, answer) = oneshot::channel();
        self.commands.send(Command::Write(packet, reply)).await.map_err(|_| "KDrive bridge is closed.")?;
        answer.await.map_err(|_| "KDrive bridge is closed.")?
    }

    pub async fn write_clipboard(&self, text: &str) -> Result<(), &'static str> {
        if !self.allow_clipboard {
            return Err("X2Go clipboard sharing is disabled for this session.");
        }
        if text.len() > MAX_CLIPBOARD_BYTES {
            return Err("X2Go clipboard text exceeds the 64 KiB limit.");
        }
        let (reply, answer) = oneshot::channel();
        self.commands.send(Command::WriteClipboard(text.as_bytes().to_vec(), reply)).await.map_err(|_| "KDrive bridge is closed.")?;
        answer.await.map_err(|_| "KDrive bridge is closed.")?
    }
}

/// An ordered bridge bound to one already-authenticated agent. The UI/HTTP
/// owner should never expose its receiver to another tab or viewer.
pub struct X2GoBridge {
    commands: mpsc::Sender<Command>,
    messages: mpsc::Receiver<Value>,
    task: JoinHandle<Result<(), &'static str>>,
    allow_clipboard: bool,
}

impl X2GoBridge {
    pub fn start(session: GuardedKDriveSession) -> Self {
        Self::start_with_options(session, false)
    }

    pub fn start_with_options(session: GuardedKDriveSession, allow_clipboard: bool) -> Self {
        let (reader, writer, agent) = session.into_parts();
        Self::spawn_with_mode(reader, writer, allow_clipboard, move |mode| async move {
            match mode {
                ExitMode::Terminate => agent.close().await.map_err(|_| "X2Go agent cleanup failed."),
                ExitMode::Suspend => agent.suspend().await.map_err(|_| "X2Go session suspend failed."),
            }
        })
    }

    fn spawn<F>(reader: KDriveReader, writer: KDriveWriter, cleanup: F) -> Self
    where F: Future<Output = Result<(), &'static str>> + Send + 'static {
        Self::spawn_with_mode(reader, writer, false, move |_| cleanup)
    }

    fn spawn_with_mode<C, F>(reader: KDriveReader, writer: KDriveWriter, allow_clipboard: bool, cleanup: C) -> Self
    where
        C: FnOnce(ExitMode) -> F + Send + 'static,
        F: Future<Output = Result<(), &'static str>> + Send + 'static,
    {
        let (commands, input) = mpsc::channel(INPUT_QUEUE);
        let (output, messages) = mpsc::channel(OUTPUT_QUEUE);
        let task = tokio::spawn(run(reader, writer, input, output, allow_clipboard, cleanup, SERVER_SILENCE));
        Self { commands, messages, task, allow_clipboard }
    }

    /// Returns the next frame/control message or None when the bridge has ended.
    pub async fn next_message(&mut self) -> Option<Value> { self.messages.recv().await }

    /// A successful write means bytes were flushed, not that the remote server
    /// processed the event or barrier. Calls must be serialized by the viewer.
    pub fn input(&self) -> X2GoInput {
        X2GoInput { commands: self.commands.clone(), allow_clipboard: self.allow_clipboard }
    }

    /// Nonblocking poll; touch renews the lease even when no frame is ready.
    pub fn poll(&mut self) -> Result<Option<Value>, &'static str> {
        let received = self.messages.try_recv();
        // Drain the final disconnect even if the actor has already stopped.
        match received {
            Ok(value) => {
                let _ = self.commands.try_send(Command::Touch);
                Ok(Some(value))
            }
            Err(mpsc::error::TryRecvError::Empty) => match self.commands.try_send(Command::Touch) {
                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(None),
                Err(mpsc::error::TrySendError::Closed(_)) => Err("KDrive bridge is closed."),
            },
            Err(mpsc::error::TryRecvError::Disconnected) => Err("KDrive bridge is closed."),
        }
    }

    /// Terminates the bridge and waits for the remote-agent cleanup attempt.
    /// Dropping without close also releases the channels and schedules cleanup.
    pub async fn close(self) -> Result<(), &'static str> {
        let Self { commands, messages, task, .. } = self;
        // Release backpressure first so a full output queue cannot delay close.
        drop(messages);
        let _ = commands.send(Command::Close).await;
        drop(commands);
        task.await.map_err(|_| "KDrive bridge task failed.")?
    }

    /// Suspends the remote X2Go session without terminating its desktop.
    pub async fn suspend(self) -> Result<(), &'static str> {
        let Self { commands, messages, task, .. } = self;
        drop(messages);
        let _ = commands.send(Command::Suspend).await;
        drop(commands);
        task.await.map_err(|_| "KDrive bridge task failed.")?
    }
}

#[cfg(test)]
pub(crate) fn test_bridge(client: tokio::io::DuplexStream, cleanup_signal: oneshot::Sender<()>) -> X2GoBridge {
    let channel = linscp_proto::x2go_transport::KDriveChannel {
        stream: Box::new(client), decoder: linscp_proto::kdrive_wire::Decoder::new(), server_version: 8,
    };
    let (reader, writer) = channel.into_halves();
    X2GoBridge::spawn(reader, writer, async move { let _ = cleanup_signal.send(()); Ok(()) })
}

async fn run<C, F>(mut reader: KDriveReader, mut writer: KDriveWriter,
                   mut commands: mpsc::Receiver<Command>, output: mpsc::Sender<Value>,
                   allow_clipboard: bool, cleanup: C, server_silence: Duration) -> Result<(), &'static str>
where
    C: FnOnce(ExitMode) -> F,
    F: Future<Output = Result<(), &'static str>>,
{
    let mut pending = None;
    let mut remote_closed = false;
    let mut exit_mode = ExitMode::Terminate;
    let mut result = Ok(());
    let mut frame_tracker = WireFrameTracker::default();
    let mut lease = tokio::time::Instant::now() + VIEWER_LEASE;
    let mut keepalive = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut last_server_message = tokio::time::Instant::now();
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(Command::Write(packet, reply)) => {
                    lease = tokio::time::Instant::now() + VIEWER_LEASE;
                    let sent = writer.write_event(&packet, WRITE_TIMEOUT).await.map_err(|_| "KDrive input write failed.");
                    let failed = sent.is_err();
                    let _ = reply.send(sent);
                    if failed { result = Err("KDrive input write failed."); break; }
                }
                Some(Command::WriteClipboard(bytes, reply)) => {
                    lease = tokio::time::Instant::now() + VIEWER_LEASE;
                    let sent = writer.write_selection(0, &bytes, WRITE_TIMEOUT).await.map_err(|_| "KDrive clipboard write failed.");
                    let failed = sent.is_err();
                    let _ = reply.send(sent);
                    if failed { result = Err("KDrive clipboard write failed."); break; }
                }
                Some(Command::Touch) => { lease = tokio::time::Instant::now() + VIEWER_LEASE; }
                Some(Command::Suspend) => { exit_mode = ExitMode::Suspend; break; }
                Some(Command::Close) | None => break,
            },
            permit = output.reserve(), if pending.is_some() => {
                match permit {
                    Ok(permit) => {
                        permit.send(pending.take().expect("pending event"));
                        // Pausing reads can make a stale silence deadline fire
                        // before buffered SSH data gets another read opportunity.
                        last_server_message = tokio::time::Instant::now();
                    }
                    Err(_) => break,
                }
                if remote_closed { break; }
            },
            _ = output.closed() => break,
            _ = tokio::time::sleep_until(lease) => { result = Err("KDrive viewer lease expired."); break; },
            // Do not time out while reads are deliberately paused by output
            // backpressure; the server may already have data waiting for us.
            _ = tokio::time::sleep_until(last_server_message + server_silence), if pending.is_none() => {
                result = Err("KDrive server is not responding.");
                break;
            },
            _ = tokio::time::sleep_until(keepalive) => {
                let mut packet = [0u8; CLIENT_EVENT_SIZE];
                packet[..4].copy_from_slice(&12u32.to_le_bytes());
                if writer.write_event(&packet, WRITE_TIMEOUT).await.is_err() {
                    result = Err("KDrive keepalive failed.");
                    break;
                }
                keepalive = tokio::time::Instant::now() + Duration::from_secs(5);
            },
            message = reader.next_message(), if pending.is_none() => {
                match message {
                    Ok(message) => {
                        last_server_message = tokio::time::Instant::now();
                        remote_closed = matches!(&message, Message::Disconnect);
                        if frame_tracker.observe_message(&message).is_err() {
                            result = Err("Invalid KDrive frame cache reference or geometry.");
                            break;
                        }
                        match viewer_message_extended(message, allow_clipboard) {
                            Ok(Some(value)) => pending = Some(value),
                            Ok(None) => {},
                            Err(_) => { result = Err("Unsupported KDrive message."); break; }
                        }
                    }
                    Err(_) => { result = Err("KDrive graphics channel ended."); break; }
                }
            }
        }
    }
    // Drop both halves before termination/suspend, without holding any service mutex.
    drop(reader);
    drop(writer);
    drop(output);
    let cleanup_err = match exit_mode {
        ExitMode::Terminate => "X2Go agent cleanup failed.",
        ExitMode::Suspend => "X2Go session suspend failed.",
    };
    if cleanup(exit_mode).await.is_err() { return Err(cleanup_err); }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use linscp_proto::kdrive_wire::{Decoder, SERVER_HEADER_SIZE};
    use linscp_proto::x2go_transport::KDriveChannel;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn event(kind: u32, a: u32, b: u32) -> [u8; CLIENT_EVENT_SIZE] {
        let mut packet = [0; CLIENT_EVENT_SIZE];
        packet[0..4].copy_from_slice(&kind.to_le_bytes());
        packet[4..8].copy_from_slice(&a.to_le_bytes());
        packet[8..12].copy_from_slice(&b.to_le_bytes());
        packet
    }
    fn header(kind: u32) -> [u8; SERVER_HEADER_SIZE] {
        let mut packet = [0; SERVER_HEADER_SIZE];
        packet[0..4].copy_from_slice(&kind.to_le_bytes());
        packet
    }
    fn test_bridge(client: tokio::io::DuplexStream, signal: oneshot::Sender<()>) -> X2GoBridge {
        let channel = KDriveChannel { stream: Box::new(client), decoder: Decoder::new(), server_version: 8 };
        let (reader, writer) = channel.into_halves();
        X2GoBridge::spawn(reader, writer, async move { let _ = signal.send(()); Ok(()) })
    }

    #[test]
    fn input_validation_accepts_only_fixed_bounded_packets() {
        assert!(validate_input(&event(2, 4, 38)));
        assert!(validate_input(&event(5, 0, 4)));
        assert!(validate_input(&event(6, 8191, 0)));
        assert!(!validate_input(&event(2, 256, 38)));
        assert!(!validate_input(&event(4, 0, 0)));
        assert!(!validate_input(&event(6, 8192, 0)));
        assert!(!validate_input(&event(9, 0, 0))); // clipboard
        assert!(!validate_input(&event(10, 0, 0))); // handshake
        let mut extra = event(2, 0, 38);
        extra[40] = 1;
        assert!(!validate_input(&extra));
        let mut update = event(8, 1, 1);
        update[12..16].copy_from_slice(&8191u32.to_le_bytes());
        assert!(validate_input(&update));
        update[12..16].copy_from_slice(&8192u32.to_le_bytes());
        assert!(!validate_input(&update));
        let mut geometry = [0; CLIENT_EVENT_SIZE];
        geometry[0..4].copy_from_slice(&7u32.to_le_bytes());
        geometry[4..6].copy_from_slice(&800u16.to_le_bytes());
        geometry[6..8].copy_from_slice(&600u16.to_le_bytes());
        geometry[9..11].copy_from_slice(&800u16.to_le_bytes());
        geometry[11..13].copy_from_slice(&600u16.to_le_bytes());
        assert!(validate_input(&geometry));
        geometry[8] = 1;
        assert!(!validate_input(&geometry));
    }

    #[tokio::test]
    async fn messages_stay_ordered_and_disconnect_runs_cleanup() {
        let (client, mut server) = tokio::io::duplex(1024);
        let (signal, observed) = oneshot::channel();
        let mut bridge = test_bridge(client, signal);
        server.write_all(&header(9)).await.unwrap();
        server.write_all(&header(10)).await.unwrap();
        assert_eq!(bridge.next_message().await.unwrap()["type"], "keepalive");
        assert_eq!(bridge.next_message().await.unwrap()["type"], "disconnect");
        assert!(bridge.next_message().await.is_none());
        assert!(observed.await.is_ok());
        assert!(bridge.close().await.is_ok());
    }

    #[tokio::test]
    async fn blocked_viewer_does_not_prevent_input_writes() {
        let (client, mut server) = tokio::io::duplex(1024);
        let (signal, observed) = oneshot::channel();
        let bridge = test_bridge(client, signal);
        server.write_all(&header(9)).await.unwrap();
        server.write_all(&header(9)).await.unwrap();
        let peer = tokio::spawn(async move {
            let mut packet = [0; CLIENT_EVENT_SIZE];
            server.read_exact(&mut packet).await.unwrap();
            assert_eq!(packet, event(2, 0, 38));
        });
        assert!(tokio::time::timeout(Duration::from_secs(1), bridge.input().write(event(2, 0, 38))).await.unwrap().is_ok());
        peer.await.unwrap();
        // Dropping the viewer releases the bounded output queue and triggers cleanup.
        drop(bridge);
        assert!(tokio::time::timeout(Duration::from_secs(1), observed).await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn silent_server_ends_session_and_attempts_cleanup() {
        let (client, _server) = tokio::io::duplex(1024);
        let channel = KDriveChannel { stream: Box::new(client), decoder: Decoder::new(), server_version: 8 };
        let (reader, writer) = channel.into_halves();
        let (_commands, input) = mpsc::channel(INPUT_QUEUE);
        let (output, _messages) = mpsc::channel(OUTPUT_QUEUE);
        let (signal, observed) = oneshot::channel();
        let cleanup = move |_| async move { let _ = signal.send(()); Ok(()) };
        let result = tokio::time::timeout(Duration::from_secs(1),
            run(reader, writer, input, output, false, cleanup, Duration::from_millis(20))).await.unwrap();
        assert_eq!(result, Err("KDrive server is not responding."));
        assert!(observed.await.is_ok());
    }

    #[tokio::test]
    async fn partial_server_message_survives_interleaved_input() {
        let (client, mut server) = tokio::io::duplex(1024);
        let (signal, observed) = oneshot::channel();
        let mut bridge = test_bridge(client, signal);
        let message = header(9);
        server.write_all(&message[..13]).await.unwrap();
        // Give the reader a chance to consume the fragment before the write
        // command interrupts its select branch.
        tokio::task::yield_now().await;
        let input = bridge.input();
        let write = tokio::spawn(async move { input.write(event(2, 0, 38)).await });
        let mut packet = [0; CLIENT_EVENT_SIZE];
        tokio::time::timeout(Duration::from_secs(1), server.read_exact(&mut packet)).await.unwrap().unwrap();
        assert_eq!(packet, event(2, 0, 38));
        assert!(write.await.unwrap().is_ok());
        server.write_all(&message[13..]).await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(1), bridge.next_message()).await.unwrap().unwrap();
        assert_eq!(received["type"], "keepalive");
        assert!(bridge.close().await.is_ok());
        assert!(observed.await.is_ok());
    }

    #[tokio::test]
    async fn malformed_server_data_stops_bridge_and_still_cleans_up() {
        let (client, mut server) = tokio::io::duplex(1024);
        let (signal, observed) = oneshot::channel();
        let mut bridge = test_bridge(client, signal);
        server.write_all(&header(u32::MAX)).await.unwrap();
        assert!(bridge.next_message().await.is_none());
        assert!(observed.await.is_ok());
        assert!(bridge.close().await.is_err());
    }
}
