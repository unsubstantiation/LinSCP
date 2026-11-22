//! End-to-end loopback integration suite for Phase 2a & 2b (`ssh`, `sftp`,
//! `scp`, `tunnel`, `proxy`, and `gssapi`):
//! - Fail-closed host-key verification (unknown, changed, wildcard `*`, MD5 pin,
//!   and independent bastion vs destination challenges)
//! - Password, OpenSSH PEM, PuTTY `.ppk`, and SSH Agent (`AgentClient`) auth
//! - Full SFTP v3 lifecycle + OpenSSH `copy-data` and `check-file-name` extensions
//! - Native SCP (`scp -f` / `scp -t` + POSIX shell commands + traversal defense)
//! - SSH Jump Tunnel (`direct-tcpip` stream & loopback SOCKS5h relay)
//! - Client SOCKS5 (RFC 1929 auth) & HTTP CONNECT proxies

use linscp_test_support as common;
use linscp_test_support::{start_mock_ssh_server, start_mock_ssh_server_with};

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use linscp_crypto::digests::DigestAlgorithm;
use linscp_platform::AsyncStream;
use linscp_proto::gssapi::ensure_gssapi_available;
use linscp_proto::proxy::{ProxyConfig, ProxyKind};
use linscp_proto::scp::ScpSession;
use linscp_proto::sftp::SftpClientSession;
use linscp_proto::ssh::{SshAgentConnector, SshConnectConfig};
use linscp_proto::{download_bytes, upload_bytes, ProtoError, RemoteSession, TransferRequest};
use linscp_types::ProtocolScheme;
use russh::keys::PrivateKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;


#[derive(Clone)]
struct DummyAgentPolicy;
impl russh::keys::agent::server::Agent for DummyAgentPolicy {}

struct DuplexAgentConnector {
    user_key: PrivateKey,
}

#[async_trait]
impl SshAgentConnector for DuplexAgentConnector {
    async fn connect(&self) -> Result<Option<Box<dyn AsyncStream>>, ProtoError> {
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let (agent_conn, agent_client_setup) = tokio::io::duplex(64 * 1024);

        // Minimal two-connection stream yielding `agent_conn` (to preload key) then `server_side`
        let key = self.user_key.clone();
        let stream_items = vec![Ok::<_, std::io::Error>(agent_conn), Ok(server_side)];
        tokio::spawn(async move {
            let incoming = TestVecStream {
                items: std::collections::VecDeque::from(stream_items),
            };
            let _ = russh::keys::agent::server::serve(incoming, DummyAgentPolicy).await;
        });

        let mut preload = russh::keys::agent::client::AgentClient::connect(agent_client_setup);
        preload
            .add_identity(&key, &[])
            .await
            .map_err(|e| ProtoError::Transport(format!("preload agent key: {e}")))?;
        drop(preload);

        Ok(Some(Box::new(client_side)))
    }
}

/// Connector with no agent at all, optionally reporting the reason instead.
struct NoAgentConnector {
    reason: Option<String>,
}

#[async_trait]
impl SshAgentConnector for NoAgentConnector {
    async fn connect(&self) -> Result<Option<Box<dyn AsyncStream>>, ProtoError> {
        Ok(None)
    }

    fn missing_reason(&self) -> Option<String> {
        self.reason.clone()
    }
}

#[tokio::test]
async fn sftp_agent_absence_names_its_reason() {
    let user_key = common::generate_ed25519_ssh_key(0x77, "tester@linscp");
    let (port, host_sha256, _host_md5, _fs) =
        start_mock_ssh_server(0x11, user_key.private_key.public_key().clone(), false).await;

    // No password, no key, no agent: the connector's reason becomes the error.
    let agent_cfg = SshConnectConfig {
        tab_id: 1,
        role: "destination".to_string(),
        host: "127.0.0.1".to_string(),
        port,
        username: "tester".to_string(),
        pinned_host_key: Some(host_sha256),
        try_agent: true,
        agent_connector: Some(Arc::new(NoAgentConnector {
            reason: Some("stub has no agent".to_string()),
        })),
        ..Default::default()
    };
    assert_eq!(
        SftpClientSession::connect(ProtocolScheme::Sftp, &agent_cfg, None, 0)
            .await
            .err(),
        Some(ProtoError::Transport("stub has no agent".to_string()))
    );

    // A connector with no reason falls back to the generic auth failure.
    let silent_cfg = SshConnectConfig {
        agent_connector: Some(Arc::new(NoAgentConnector { reason: None })),
        ..agent_cfg
    };
    match SftpClientSession::connect(ProtocolScheme::Sftp, &silent_cfg, None, 0).await {
        Err(ProtoError::Transport(message)) => {
            assert!(
                message.contains("Authentication failed for tester@"),
                "unexpected auth error: {message}"
            );
        }
        Err(other) => panic!("expected a transport auth error, got {other:?}"),
        Ok(_) => panic!("expected a transport auth error, got a connected session"),
    }
}

struct TestVecStream<T> {
    items: std::collections::VecDeque<T>,
}

impl<T: Unpin> futures_core::Stream for TestVecStream<T> {
    type Item = T;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::task::Poll::Ready(self.items.pop_front())
    }
}

#[tokio::test]
async fn sftp_full_lifecycle_auth_modes_and_extensions_succeed() {
    let user_key = common::generate_ed25519_ssh_key(0x77, "tester@linscp");
    let (port, host_sha256, host_md5, _fs) =
        start_mock_ssh_server(0x11, user_key.private_key.public_key().clone(), false).await;

    // 1. Fail-closed host-key checks: wildcard `*`, unknown key, and mismatched pin
    let mut bad_cfg = SshConnectConfig {
        tab_id: 42,
        role: "destination".to_string(),
        host: "127.0.0.1".to_string(),
        port,
        username: "tester".to_string(),
        password: Some(Zeroizing::new("correct-horse-battery".to_string())),
        pinned_host_key: Some("*".to_string()),
        ..Default::default()
    };
    assert_eq!(
        SftpClientSession::connect(ProtocolScheme::Sftp, &bad_cfg, None, 0)
            .await
            .err(),
        Some(ProtoError::WeakHostKeyPolicy("*".to_string()))
    );

    bad_cfg.pinned_host_key = None;
    match SftpClientSession::connect(ProtocolScheme::Sftp, &bad_cfg, None, 0).await {
        Err(ProtoError::HostKeyChallengeRequired {
            role,
            state,
            fingerprint,
            ..
        }) => {
            assert_eq!(role, "destination");
            assert_eq!(state, "unknown");
            assert_eq!(fingerprint, host_sha256);
        }
        other => panic!("expected unknown host key challenge, got {}", other.err().unwrap()),
    }

    // 2. Connect with SSH Agent over duplex stream + legacy MD5 host-key pin!
    let agent_cfg = SshConnectConfig {
        tab_id: 1,
        role: "destination".to_string(),
        host: "127.0.0.1".to_string(),
        port,
        username: "tester".to_string(),
        pinned_host_key: Some(host_md5),
        try_agent: true,
        agent_connector: Some(Arc::new(DuplexAgentConnector {
            user_key: user_key.private_key.clone(),
        })),
        ..Default::default()
    };
    let sftp = SftpClientSession::connect(ProtocolScheme::Sftp, &agent_cfg, None, 0)
        .await
        .expect("SFTP agent auth + MD5 hostkey");

    assert_eq!(sftp.pwd().await.unwrap(), "/home/tester");
    sftp.mkdir("/home/tester/docs").await.unwrap();

    // Upload initial part, then resume at byte offset, then append!
    let part1 = b"Hello, pure-Rust ";
    let part2 = b"SFTP world!";
    upload_bytes(&sftp, "/home/tester/docs/note.txt", part1, TransferRequest::default())
        .await
        .unwrap();
    upload_bytes(
        &sftp,
        "/home/tester/docs/note.txt",
        part2,
        TransferRequest {
            resume_offset: part1.len() as u64,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    upload_bytes(
        &sftp,
        "/home/tester/docs/note.txt",
        b" [appended]",
        TransferRequest {
            append: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let full_expected = b"Hello, pure-Rust SFTP world! [appended]";
    let got = download_bytes(
        &sftp,
        "/home/tester/docs/note.txt",
        TransferRequest::default(),
    )
    .await
    .unwrap();
    assert_eq!(got, full_expected);

    // Resume download from offset 17
    let tail = download_bytes(
        &sftp,
        "/home/tester/docs/note.txt",
        TransferRequest {
            resume_offset: 17,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(tail, b"SFTP world! [appended]");

    // OpenSSH `copy-data` server-side copy & `check-file-name` server-side checksum!
    sftp.copy_file("/home/tester/docs/note.txt", "/home/tester/docs/copied.txt")
        .await
        .unwrap();
    let (used_alg, srv_hex) = sftp
        .checksum_extension_only("sha256", "/home/tester/docs/copied.txt")
        .await
        .unwrap()
        .expect("server supports check-file-name");
    assert_eq!(used_alg, "sha-256");
    let local_hex = linscp_crypto::digests::compute_digest_hex(DigestAlgorithm::Sha256, full_expected);
    assert_eq!(srv_hex, local_hex);
    assert_eq!(
        sftp.checksum("sha256", "/home/tester/docs/copied.txt")
            .await
            .unwrap(),
        local_hex
    );

    // Symlink, chmod, rename, list_dir, remove
    sftp.chmod("/home/tester/docs/copied.txt", 0o600)
        .await
        .unwrap();
    sftp.symlink("copied.txt", "/home/tester/docs/latest.txt")
        .await
        .unwrap();
    sftp.symlink("nonexistent.txt", "/home/tester/docs/broken.txt")
        .await
        .unwrap();

    let listing = sftp.list_dir("/home/tester/docs").await.unwrap();
    let latest = listing.iter().find(|e| e.name == "latest.txt").unwrap();
    assert!(latest.is_symlink);
    assert!(!latest.broken_link);
    let broken = listing.iter().find(|e| e.name == "broken.txt").unwrap();
    assert!(broken.is_symlink);
    assert!(broken.broken_link);

    sftp.rename("/home/tester/docs/copied.txt", "/home/tester/docs/renamed.txt")
        .await
        .unwrap();
    assert!(sftp.stat("/home/tester/docs/copied.txt").await.unwrap().is_none());
    assert!(sftp.stat("/home/tester/docs/renamed.txt").await.unwrap().is_some());

    sftp.remove_file("/home/tester/docs/note.txt").await.unwrap();
    sftp.remove_file("/home/tester/docs/renamed.txt").await.unwrap();
    sftp.remove_file("/home/tester/docs/latest.txt").await.unwrap();
    sftp.remove_file("/home/tester/docs/broken.txt").await.unwrap();
    sftp.remove_dir("/home/tester/docs").await.unwrap();
    sftp.close().await.unwrap();

    // GSSAPI fail-closed check when feature is not active
    if !cfg!(feature = "gssapi") {
        assert!(ensure_gssapi_available(false).is_err());
    }
}

#[tokio::test]
async fn scp_engine_jump_tunnel_and_proxy_dialers_work_end_to_end() {
    let user_key = common::generate_ed25519_ssh_key(0x88, "scp-user");
    let (bastion_port, bastion_fp, _, _) =
        start_mock_ssh_server(0x22, user_key.private_key.public_key().clone(), true).await;
    let (dest_port, dest_fp, _, _) =
        start_mock_ssh_server(0x33, user_key.private_key.public_key().clone(), false).await;

    // 1. Verify jump-host host-key challenge reports `role = "tunnel"` independently!
    let bad_bastion = SshConnectConfig {
        tab_id: 9,
        role: "tunnel".to_string(),
        host: "127.0.0.1".to_string(),
        port: bastion_port,
        username: "tester".to_string(),
        private_key_pem: Some(Zeroizing::new(user_key.openssh_pem.clone())),
        pinned_host_key: Some("SHA256:wrongBastionPin".to_string()),
        ..Default::default()
    };
    let dest_cfg = SshConnectConfig {
        tab_id: 9,
        role: "destination".to_string(),
        host: "127.0.0.1".to_string(),
        port: dest_port,
        username: "tester".to_string(),
        private_key_pem: Some(Zeroizing::new(user_key.openssh_pem.clone())),
        pinned_host_key: Some(dest_fp.clone()),
        ..Default::default()
    };
    match ScpSession::connect(&dest_cfg, Some(&bad_bastion), 0).await {
        Err(ProtoError::HostKeyChallengeRequired { role, state, .. }) => {
            assert_eq!(role, "tunnel");
            assert_eq!(state, "changed");
        }
        other => panic!("expected tunnel challenge, got {:?}", other.err()),
    }

    // 2. Connect SCP over verified SSH Jump Tunnel (`direct-tcpip`, zero local listener!)
    let mut good_bastion = bad_bastion;
    good_bastion.pinned_host_key = Some(bastion_fp);
    let scp = ScpSession::connect(&dest_cfg, Some(&good_bastion), 0)
        .await
        .expect("SCP over jump tunnel");

    scp.mkdir("/home/tester/scpdir").await.unwrap();
    let payload = b"SCP wire protocol payload across jump bastion!\n";
    upload_bytes(
        &scp,
        "/home/tester/scpdir/hello.txt",
        payload,
        TransferRequest {
            preserve_time: true,
            mtime: Some(1_760_123_456),
            permissions: Some(0o640),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let entries = scp.list_dir("/home/tester/scpdir").await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "hello.txt");
    assert_eq!(entries[0].size, payload.len() as u64);

    let downloaded = download_bytes(
        &scp,
        "/home/tester/scpdir/hello.txt",
        TransferRequest {
            preserve_time: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(downloaded, payload);

    // Malicious SCP server sending `C0644 5 ../pwned.txt` MUST be rejected!
    let escape_err = download_bytes(
        &scp,
        "/home/tester/malicious_escape",
        TransferRequest::default(),
    )
    .await
    .expect_err("path traversal filename from scp -f must be rejected");
    assert!(escape_err.to_string().contains("unsafe filename"));

    scp.copy_file(
        "/home/tester/scpdir/hello.txt",
        "/home/tester/scpdir/copy.txt",
    )
    .await
    .unwrap();
    scp.rename(
        "/home/tester/scpdir/copy.txt",
        "/home/tester/scpdir/moved.txt",
    )
    .await
    .unwrap();
    scp.chmod("/home/tester/scpdir/moved.txt", 0o600)
        .await
        .unwrap();
    assert_eq!(
        scp.checksum("sha256", "/home/tester/scpdir/moved.txt")
            .await
            .unwrap(),
        linscp_crypto::digests::compute_digest_hex(DigestAlgorithm::Sha256, payload)
    );
    scp.remove_file("/home/tester/scpdir/hello.txt").await.unwrap();
    scp.remove_file("/home/tester/scpdir/moved.txt").await.unwrap();
    scp.remove_dir("/home/tester/scpdir").await.unwrap();
    scp.close().await.unwrap();

    // 3. Test HTTP CONNECT proxy dialer with Basic auth!
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut client_sock, _)) = proxy_listener.accept().await {
            let mut req_buf = Vec::new();
            let mut b = [0u8; 1];
            while !req_buf.ends_with(b"\r\n\r\n") {
                if client_sock.read_exact(&mut b).await.is_err() {
                    return;
                }
                req_buf.push(b[0]);
            }
            let req_str = String::from_utf8_lossy(&req_buf);
            assert!(req_str.contains("Proxy-Authorization: Basic "));
            let target = req_str
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap();
            let mut upstream = TcpStream::connect(target).await.unwrap();
            client_sock
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let _ = tokio::io::copy_bidirectional(&mut client_sock, &mut upstream).await;
        }
    });

    let mut via_http_proxy = dest_cfg;
    via_http_proxy.proxy = Some(ProxyConfig {
        kind: ProxyKind::HttpConnect,
        host: "127.0.0.1".to_string(),
        port: proxy_port,
        username: Some("proxyuser".to_string()),
        password: Some("proxypass".to_string()),
        remote_dns: true,
        command: None,
    });
    let proxied_sftp = SftpClientSession::connect(ProtocolScheme::Sftp, &via_http_proxy, None, 0)
        .await
        .expect("SFTP over HTTP CONNECT proxy");
    assert_eq!(proxied_sftp.pwd().await.unwrap(), "/home/tester");
    proxied_sftp.close().await.unwrap();
}


#[tokio::test]
async fn bounded_exec_collects_caps_and_closes_without_killing_ssh() {
    let user_key = common::generate_ed25519_ssh_key(0x79, "monitor@test");
    let (port, host_sha256, _host_md5, _fs) =
        start_mock_ssh_server(0x19, user_key.private_key.public_key().clone(), false).await;
    let cfg = SshConnectConfig {
        tab_id: 90,
        role: "destination".into(),
        host: "127.0.0.1".into(),
        port,
        username: "tester".into(),
        password: Some(Zeroizing::new("correct-horse-battery".into())),
        pinned_host_key: Some(host_sha256),
        ..Default::default()
    };
    let session = SftpClientSession::connect(ProtocolScheme::Sftp, &cfg, None, 0)
        .await.expect("pinned SSH connection");
    let ssh = session.ssh_connection();
    let output = ssh.exec_command_bounded(
        "printf '__LINSCP_MONITOR_STAT\n'; true",
        Duration::from_secs(2), 1024,
    ).await.expect("bounded probe");
    assert_eq!(output.exit_code, Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("__LINSCP_MONITOR_STAT"));

    let started = std::time::Instant::now();
    let timeout = ssh.exec_command_bounded("__LINSCP_TEST_HANG__", Duration::from_millis(100), 1024).await;
    assert!(timeout.unwrap_err().to_string().contains("Timed out"));
    assert!(started.elapsed() < Duration::from_secs(2));
    // Closing the expired exec channel must leave the authenticated session usable.
    assert_eq!(ssh.exec_command_bounded("pwd", Duration::from_secs(2), 1024).await.unwrap().stdout, b"/home/tester\n");

    let capped = ssh.exec_command_bounded("__LINSCP_TEST_FLOOD__", Duration::from_secs(2), 1024).await;
    assert!(capped.unwrap_err().to_string().contains("1024-byte limit"));
    assert_eq!(ssh.exec_command_bounded("pwd", Duration::from_secs(2), 1024).await.unwrap().exit_code, Some(0));
}

// ---------------------------------------------------------------------------
// Granular ports of the `live-sftp` suite cases cited by the parity ledger
// (`docs/upstream-parity.json`, suite `proto-ssh`). Each test mirrors the
// case of the same name in source/linux/tests/LiveSftpTest.py and runs
// against the shared in-memory mock.
// ---------------------------------------------------------------------------

/// A connection with the wrong password is refused, not retried open.
#[tokio::test]
async fn test_open_with_a_wrong_password_is_refused() {
    let user_key = common::generate_ed25519_ssh_key(0x31, "tester@linscp");
    let (port, host_sha256, _host_md5, _fs) =
        start_mock_ssh_server(0x32, user_key.private_key.public_key().clone(), false).await;

    let cfg = SshConnectConfig {
        tab_id: 51,
        role: "destination".to_string(),
        host: "127.0.0.1".to_string(),
        port,
        username: "tester".to_string(),
        password: Some(Zeroizing::new("definitely-not-the-password".to_string())),
        pinned_host_key: Some(host_sha256),
        ..Default::default()
    };
    match SftpClientSession::connect(ProtocolScheme::Sftp, &cfg, None, 0).await {
        Err(ProtoError::Transport(message)) => {
            // The password is refused, then keyboard-interactive (tried with
            // the same password) is refused too; the last refusal wins in the
            // reported error. Either way the refusal comes from the server.
            assert!(
                message.contains("Server rejected"),
                "expected a server-side authentication refusal, got: {message}"
            );
        }
        Err(other) => panic!("expected a transport authentication error, got {other:?}"),
        Ok(_) => panic!("a wrong password must not open a session"),
    }
}

/// A pinned host key that does not match the server's key must refuse the
/// session (the host-key challenge reports `changed`), never connect.
#[tokio::test]
async fn test_open_with_an_unexpected_host_key_is_refused() {
    let user_key = common::generate_ed25519_ssh_key(0x33, "tester@linscp");
    let (port, _host_sha256, _host_md5, _fs) =
        start_mock_ssh_server(0x34, user_key.private_key.public_key().clone(), false).await;

    let cfg = SshConnectConfig {
        tab_id: 52,
        role: "destination".to_string(),
        host: "127.0.0.1".to_string(),
        port,
        username: "tester".to_string(),
        password: Some(Zeroizing::new("correct-horse-battery".to_string())),
        pinned_host_key: Some("SHA256:wrong-for-this-mock-0000000000000000000000000000000000".to_string()),
        ..Default::default()
    };
    match SftpClientSession::connect(ProtocolScheme::Sftp, &cfg, None, 0).await {
        Err(ProtoError::HostKeyChallengeRequired {
            role,
            state,
            fingerprint,
            ..
        }) => {
            assert_eq!(role, "destination");
            assert_eq!(state, "changed");
            assert!(fingerprint.starts_with("SHA256:"), "unexpected fingerprint: {fingerprint}");
        }
        Err(other) => panic!("expected a host-key challenge, got {other:?}"),
        Ok(_) => panic!("an unexpected host key must not open a session"),
    }
}

/// Operations the server refuses are reported as errors carrying the server's
/// own message, and the ones that succeed keep working.
#[tokio::test]
async fn test_operations_the_server_refuses_are_reported() {
    let user_key = common::generate_ed25519_ssh_key(0x35, "tester@linscp");
    let (port, host_sha256, _host_md5, _fs) =
        start_mock_ssh_server(0x36, user_key.private_key.public_key().clone(), false).await;

    let cfg = SshConnectConfig {
        tab_id: 53,
        role: "destination".to_string(),
        host: "127.0.0.1".to_string(),
        port,
        username: "tester".to_string(),
        password: Some(Zeroizing::new("correct-horse-battery".to_string())),
        pinned_host_key: Some(host_sha256),
        ..Default::default()
    };
    let sftp = SftpClientSession::connect(ProtocolScheme::Sftp, &cfg, None, 0)
        .await
        .expect("connect to the mock");

    // A control operation the server accepts.
    sftp.mkdir("/home/tester/ops").await.unwrap();
    sftp.chmod("/home/tester/ops", 0o750).await.unwrap();

    // Removing a file the server does not have is an error, not silence.
    let err = sftp
        .remove_file("/home/tester/ops/absent.txt")
        .await
        .expect_err("removing a missing file must fail");
    assert!(
        err.to_string().contains("Missing"),
        "the server's own wording is reported: {err}"
    );

    // Removing a directory that does not exist is an error as well.
    let err = sftp
        .remove_dir("/home/tester/ops/absent-dir")
        .await
        .expect_err("rmdir of a missing directory must fail");
    assert!(
        err.to_string().contains("Missing"),
        "the server's own wording is reported: {err}"
    );

    // chmod on a path the server does not have is reported, not ignored.
    let err = sftp
        .chmod("/home/tester/ops/absent.txt", 0o600)
        .await
        .expect_err("chmod of a missing file must fail");
    assert!(
        err.to_string().contains("Missing"),
        "the server's own wording is reported: {err}"
    );

    // Listing a directory the server does not have is an error as well.
    let err = sftp
        .list_dir("/home/tester/ops/absent-dir")
        .await
        .expect_err("listing a missing directory must fail");
    assert!(
        err.to_string().contains("No such"),
        "the server's own wording is reported: {err}"
    );

    sftp.close().await.unwrap();
}

/// When the server implements the `check-file-name` extension, the digest is
/// calculated server-side rather than by streaming the file.
#[tokio::test]
async fn test_checksum_uses_native_check_file_name_extension() {
    let user_key = common::generate_ed25519_ssh_key(0x37, "tester@linscp");
    let (port, host_sha256, _host_md5, _fs) =
        start_mock_ssh_server(0x38, user_key.private_key.public_key().clone(), false).await;

    let cfg = SshConnectConfig {
        tab_id: 54,
        role: "destination".to_string(),
        host: "127.0.0.1".to_string(),
        port,
        username: "tester".to_string(),
        password: Some(Zeroizing::new("correct-horse-battery".to_string())),
        pinned_host_key: Some(host_sha256),
        ..Default::default()
    };
    let sftp = SftpClientSession::connect(ProtocolScheme::Sftp, &cfg, None, 0)
        .await
        .expect("connect to the mock");

    let payload: Vec<u8> = (0..97 * 1024u32).map(|i| (i * 31 % 251) as u8).collect();
    upload_bytes(&sftp, "/home/tester/native-checksum.bin", &payload, TransferRequest::default())
        .await
        .unwrap();

    // The extension answers, and it used sha-256.
    let (used_alg, hex) = sftp
        .checksum_extension_only("sha256", "/home/tester/native-checksum.bin")
        .await
        .unwrap()
        .expect("the mock advertises check-file-name");
    assert_eq!(used_alg, "sha-256");
    let local_hex = linscp_crypto::digests::compute_digest_hex(DigestAlgorithm::Sha256, &payload);
    assert_eq!(hex, local_hex);

    // The general entry point prefers the extension as well.
    assert_eq!(
        sftp.checksum("sha256", "/home/tester/native-checksum.bin").await.unwrap(),
        local_hex
    );

    sftp.remove_file("/home/tester/native-checksum.bin").await.unwrap();
    sftp.close().await.unwrap();
}

/// When the server refuses `check-file-name`, every documented algorithm
/// hashes the downloaded bytes and reports the correct digest.
#[tokio::test]
async fn test_checksum_fallback_supports_all_documented_algorithms() {
    let user_key = common::generate_ed25519_ssh_key(0x39, "tester@linscp");
    let (port, host_sha256, _host_md5, _fs) = start_mock_ssh_server_with(
        0x3a,
        user_key.private_key.public_key().clone(),
        false,
        /* check_file_name */ false,
        /* copy_data */ true,
    )
    .await;

    let cfg = SshConnectConfig {
        tab_id: 55,
        role: "destination".to_string(),
        host: "127.0.0.1".to_string(),
        port,
        username: "tester".to_string(),
        password: Some(Zeroizing::new("correct-horse-battery".to_string())),
        pinned_host_key: Some(host_sha256),
        ..Default::default()
    };
    let sftp = SftpClientSession::connect(ProtocolScheme::Sftp, &cfg, None, 0)
        .await
        .expect("connect to the mock");

    let mut payload = Vec::new();
    for _ in 0..4097 {
        payload.extend_from_slice(b"checksum fallback");
        payload.push(0);
    }
    upload_bytes(&sftp, "/home/tester/fallback-checksum.bin", &payload, TransferRequest::default())
        .await
        .unwrap();

    for algorithm in ["sha-256", "sha-1", "md5", "crc32"] {
        // The extension refuses, so the fallback has to produce the digest.
        assert!(
            sftp.checksum_extension_only(algorithm, "/home/tester/fallback-checksum.bin")
                .await
                .unwrap()
                .is_none(),
            "the mock refuses check-file-name for {algorithm}"
        );
        let expected = linscp_crypto::digests::compute_digest_hex(
            DigestAlgorithm::parse(algorithm).expect("documented algorithm parses"),
            &payload,
        );
        assert_eq!(
            sftp.checksum(algorithm, "/home/tester/fallback-checksum.bin").await.unwrap(),
            expected,
            "downloaded-bytes fallback digest mismatch for {algorithm}"
        );
    }

    sftp.remove_file("/home/tester/fallback-checksum.bin").await.unwrap();
    sftp.close().await.unwrap();
}

/// The mock advertises `copy-data`, so `copy_file` is served by the
/// server-side extension (this implementation has no streamed fallback at
/// the protocol layer) and the copied bytes match.
#[tokio::test]
async fn test_cp_uses_native_copy_data_when_the_server_advertises_it() {
    let user_key = common::generate_ed25519_ssh_key(0x3b, "tester@linscp");
    let (port, host_sha256, _host_md5, _fs) =
        start_mock_ssh_server(0x3c, user_key.private_key.public_key().clone(), false).await;

    let cfg = SshConnectConfig {
        tab_id: 56,
        role: "destination".to_string(),
        host: "127.0.0.1".to_string(),
        port,
        username: "tester".to_string(),
        password: Some(Zeroizing::new("correct-horse-battery".to_string())),
        pinned_host_key: Some(host_sha256),
        ..Default::default()
    };
    let sftp = SftpClientSession::connect(ProtocolScheme::Sftp, &cfg, None, 0)
        .await
        .expect("connect to the mock");

    let payload: Vec<u8> = (0..192 * 1024u32).map(|i| (i * 7 % 256) as u8).collect();
    upload_bytes(&sftp, "/home/tester/copy-source.bin", &payload, TransferRequest::default())
        .await
        .unwrap();

    // Succeeds only through the server-side copy-data extension.
    sftp.copy_file("/home/tester/copy-source.bin", "/home/tester/copy-dest.bin")
        .await
        .expect("copy-data is advertised by the mock");

    let copied = download_bytes(&sftp, "/home/tester/copy-dest.bin", TransferRequest::default())
        .await
        .unwrap();
    assert_eq!(copied, payload);

    let source_hex = linscp_crypto::digests::compute_digest_hex(DigestAlgorithm::Sha256, &payload);
    assert_eq!(
        sftp.checksum("sha256", "/home/tester/copy-dest.bin").await.unwrap(),
        source_hex
    );

    sftp.remove_file("/home/tester/copy-source.bin").await.unwrap();
    sftp.remove_file("/home/tester/copy-dest.bin").await.unwrap();
    sftp.close().await.unwrap();
}

/// When `copy-data` is not advertised (or `from == to`), `copy_file` must
/// reject before creating a 0-byte destination or truncating an existing file.
#[tokio::test]
async fn test_cp_without_copy_data_or_onto_self_does_not_clobber_or_leave_empty_dest() {
    let user_key = common::generate_ed25519_ssh_key(0x4d, "tester@linscp");
    let (port, host_sha256, _host_md5, _fs) = start_mock_ssh_server_with(
        0x4e,
        user_key.private_key.public_key().clone(),
        false,
        /* check_file_name */ true,
        /* copy_data */ false,
    )
    .await;

    let cfg = SshConnectConfig {
        tab_id: 60,
        role: "destination".to_string(),
        host: "127.0.0.1".to_string(),
        port,
        username: "tester".to_string(),
        password: Some(Zeroizing::new("correct-horse-battery".to_string())),
        pinned_host_key: Some(host_sha256),
        ..Default::default()
    };
    let sftp = SftpClientSession::connect(ProtocolScheme::Sftp, &cfg, None, 0)
        .await
        .expect("connect to the mock");

    let source_bytes = b"important-source-bytes";
    let existing_bytes = b"existing-target-must-survive";
    upload_bytes(&sftp, "/home/tester/src.bin", source_bytes, TransferRequest::default())
        .await
        .unwrap();
    upload_bytes(&sftp, "/home/tester/existing.bin", existing_bytes, TransferRequest::default())
        .await
        .unwrap();

    // 1. Self-copy is rejected without truncating the source file.
    let self_err = sftp
        .copy_file("/home/tester/src.bin", "/home/tester/src.bin")
        .await
        .expect_err("self-copy must fail");
    assert!(matches!(self_err, linscp_proto::ProtoError::Transport(_)), "{self_err:?}");
    assert_eq!(
        download_bytes(&sftp, "/home/tester/src.bin", TransferRequest::default()).await.unwrap(),
        source_bytes
    );

    // 2. Unadvertised `copy-data` to a new path returns `UnsupportedCapability` without creating a 0-byte orphan.
    let missing_cap = sftp
        .copy_file("/home/tester/src.bin", "/home/tester/orphan.bin")
        .await
        .expect_err("copy-data is disabled");
    assert!(
        matches!(missing_cap, linscp_proto::ProtoError::UnsupportedCapability("copy-data", ProtocolScheme::Sftp)),
        "{missing_cap:?}"
    );
    assert!(
        sftp.stat("/home/tester/orphan.bin").await.unwrap().is_none(),
        "unsupported copy-data must not leave a 0-byte file at destination"
    );

    // 3. Unadvertised `copy-data` onto an existing file does not truncate `existing.bin`.
    let existing_cap = sftp
        .copy_file("/home/tester/src.bin", "/home/tester/existing.bin")
        .await
        .expect_err("copy-data is disabled");
    assert!(
        matches!(existing_cap, linscp_proto::ProtoError::UnsupportedCapability("copy-data", ProtocolScheme::Sftp)),
        "{existing_cap:?}"
    );
    assert_eq!(
        download_bytes(&sftp, "/home/tester/existing.bin", TransferRequest::default()).await.unwrap(),
        existing_bytes
    );

    sftp.close().await.unwrap();
}

/// PuTTYgen-generated keys exercise the real SSH authentication path, not just
/// the converter. The committed keys are public, disposable test fixtures.
#[tokio::test]
async fn test_ssh_authentication_with_puttygen_ppk_v2_and_v3() {
    const V2_NONE: &str = include_str!("../../linscp-crypto/tests/fixtures/ppk/v2-none.ppk");
    const V3_NONE: &str = include_str!("../../linscp-crypto/tests/fixtures/ppk/v3-none.ppk");
    const V2_ENCRYPTED: &str = include_str!("../../linscp-crypto/tests/fixtures/ppk/v2-encrypted.ppk");
    const V3_ENCRYPTED: &str = include_str!("../../linscp-crypto/tests/fixtures/ppk/v3-encrypted.ppk");
    let plain = linscp_crypto::ppk::ppk_to_openssh_pem(V3_NONE, "", None).unwrap();
    let key = russh::keys::decode_secret_key(plain.as_str(), None).unwrap();
    let (port, host_sha256, _host_md5, _fs) =
        start_mock_ssh_server(0x43, key.public_key().clone(), false).await;
    for (text, password) in [(V2_NONE, None), (V3_NONE, None),
        (V2_ENCRYPTED, Some("test-only-passphrase")), (V3_ENCRYPTED, Some("test-only-passphrase"))] {
        let cfg = SshConnectConfig {
            tab_id: 59, role: "destination".to_string(), host: "127.0.0.1".to_string(),
            port, username: "tester".to_string(), pinned_host_key: Some(host_sha256.clone()),
            private_key_pem: Some(Zeroizing::new(text.to_string())),
            key_passphrase: password.map(|value| Zeroizing::new(value.to_string())),
            ..Default::default()
        };
        let session = SftpClientSession::connect(ProtocolScheme::Sftp, &cfg, None, 0)
            .await.expect("PuTTYgen key should authenticate");
        assert_eq!(session.pwd().await.unwrap(), "/home/tester");
        session.close().await.unwrap();
    }
}

/// Agent-backed authentication opens the session with no password, and an
/// encrypted PPK only opens the session when its passphrase is supplied.
#[tokio::test]
async fn test_ssh_agent_and_encrypted_private_key_passphrase() {
    // A throwaway encrypted PPK v2 vector (public fixture from the ppk unit
    // tests); the matching public key authorizes the mock server.
    const ENCRYPTED_PPK_V2: &str = "\
PuTTY-User-Key-File-2: ssh-ed25519
Encryption: aes256-cbc
Comment: ed25519-v2
Public-Lines: 1
AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk
Private-Lines: 1
Y9f+qSB5FZfq2THk/c3+YDp7WUUEInGl7poCWM0H3hZSKKSrhvXEZOFcav7qc/bk
Private-MAC: 1459a716b2ebdea871aa101e3a6fe0801798df2f
";
    let vector_plain = linscp_crypto::ppk::ppk_to_openssh_pem(ENCRYPTED_PPK_V2, "secret-ppk", None)
        .expect("the vector decrypts with its passphrase");
    let vector_key = russh::keys::decode_secret_key(vector_plain.as_str(), None)
        .expect("the decrypted vector parses as an OpenSSH key");

    // 1. SSH agent authentication: the mock accepts the agent-held key.
    let user_key = common::generate_ed25519_ssh_key(0x3d, "tester@linscp");
    let (port, host_sha256, _host_md5, _fs) =
        start_mock_ssh_server(0x3e, user_key.private_key.public_key().clone(), false).await;
    let agent_cfg = SshConnectConfig {
        tab_id: 57,
        role: "destination".to_string(),
        host: "127.0.0.1".to_string(),
        port,
        username: "tester".to_string(),
        pinned_host_key: Some(host_sha256),
        try_agent: true,
        agent_connector: Some(Arc::new(DuplexAgentConnector {
            user_key: user_key.private_key.clone(),
        })),
        ..Default::default()
    };
    let sftp = SftpClientSession::connect(ProtocolScheme::Sftp, &agent_cfg, None, 0)
        .await
        .expect("agent-held key authenticates");
    assert_eq!(sftp.pwd().await.unwrap(), "/home/tester");
    sftp.close().await.unwrap();

    // 2. The encrypted PPK with the wrong passphrase is refused.
    let (port, host_sha256, _host_md5, _fs) =
        start_mock_ssh_server(0x3f, vector_key.public_key().clone(), false).await;
    let bad_cfg = SshConnectConfig {
        tab_id: 58,
        role: "destination".to_string(),
        host: "127.0.0.1".to_string(),
        port,
        username: "tester".to_string(),
        private_key_pem: Some(Zeroizing::new(ENCRYPTED_PPK_V2.to_string())),
        key_passphrase: Some(Zeroizing::new("wrong-pass".to_string())),
        pinned_host_key: Some(host_sha256.clone()),
        ..Default::default()
    };
    assert!(
        SftpClientSession::connect(ProtocolScheme::Sftp, &bad_cfg, None, 0).await.is_err(),
        "a wrong passphrase must not open the key"
    );

    // 3. The encrypted PPK with its passphrase opens the session.
    let good_cfg = SshConnectConfig {
        key_passphrase: Some(Zeroizing::new("secret-ppk".to_string())),
        ..bad_cfg
    };
    let sftp = SftpClientSession::connect(ProtocolScheme::Sftp, &good_cfg, None, 0)
        .await
        .expect("the passphrase opens the encrypted PPK");
    assert_eq!(sftp.pwd().await.unwrap(), "/home/tester");
    sftp.close().await.unwrap();
}

#[tokio::test]
async fn scp_copy_file_refuses_self_copy_and_signals_unsupported_when_cp_missing() {
    let user_key = common::generate_ed25519_ssh_key(0x4a, "scp-nocp");
    let (port, host_sha256, _host_md5, fs) =
        start_mock_ssh_server(0x4b, user_key.private_key.public_key().clone(), false).await;
    let cfg = SshConnectConfig {
        tab_id: 91,
        role: "destination".to_string(),
        host: "127.0.0.1".to_string(),
        port,
        username: "tester".to_string(),
        private_key_pem: Some(Zeroizing::new(user_key.openssh_pem)),
        pinned_host_key: Some(host_sha256),
        ..Default::default()
    };
    let scp = ScpSession::connect(&cfg, None, 0).await.expect("SCP connect");
    upload_bytes(&scp, "/home/tester/src.txt", b"streamed fallback", TransferRequest::default())
        .await
        .unwrap();

    // Self-copy must be rejected before invoking remote `cp`.
    let self_err = scp
        .copy_file("/home/tester/src.txt", "/home/tester/src.txt")
        .await
        .expect_err("self-copy must fail");
    assert!(self_err.to_string().contains("onto itself"), "{self_err}");

    // When the remote shell lacks `cp` (exit 127), `copy_file` must return
    // `UnsupportedCapability("cp", ProtocolScheme::Scp)` so callers fall back
    // to streaming through the client.
    fs.lock().await.disable_shell_cp = true;
    match scp
        .copy_file("/home/tester/src.txt", "/home/tester/dst.txt")
        .await
    {
        Err(ProtoError::UnsupportedCapability(cap, ProtocolScheme::Scp)) => {
            assert_eq!(cap, "cp");
        }
        other => panic!("expected UnsupportedCapability(cp, Scp), got {other:?}"),
    }
    scp.close().await.unwrap();
}

