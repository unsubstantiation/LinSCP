//! Transport for a future built-in X2Go KDrive viewer.
//!
//! This opens the SSH graphics channel and provides an opt-in KDrive handshake.
//! It does not start an agent, decode compressed images, or create a window.

use linscp_platform::AsyncStream;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::kdrive_wire::{Decoder, Handshake, Message};
use crate::ssh::SshConnection;
use crate::x2go_control::X2GoStartedSession;
use crate::ProtoError;

/// Opens the validated agent's graphics port on the SSH server's loopback.
///
/// `ssh` must be the authenticated destination connection on which `session`
/// was created, not a bastion or a newly constructed direct connection. That
/// preserves its host-key, proxy, and jump-host decisions. Failure is returned
/// to the caller; there is no direct TCP or external-viewer fallback. Dropping
/// the returned stream closes its SSH channel, but does not terminate the agent.
///
/// This deliberately does not start an agent: until image decoding, rendering,
/// and remote lifecycle are integrated, there is no usable built-in viewer.
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
}
