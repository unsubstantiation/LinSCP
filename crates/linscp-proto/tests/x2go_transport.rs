//! SSH-channel tests for X2Go graphics transport. These use an echo listener,
//! not a KDrive server, and do not establish viewer compatibility.

use linscp_proto::ssh::{SshConnectConfig, SshConnection};
use linscp_proto::x2go_control::parse_start_reply;
use linscp_proto::x2go_transport::open_graphics_stream;
use linscp_test_support::{generate_ed25519_ssh_key, start_mock_ssh_server};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

fn session(port: u16) -> linscp_proto::x2go_control::X2GoStartedSession {
    let reply = format!(
        "50\n0123456789abcdef0123456789abcdef\n1234\ntest-50-session\n{port}\n31002\n31003\n"
    );
    parse_start_reply(reply.as_bytes(), Some(0)).unwrap()
}

async fn connect(allow_forwarding: bool) -> SshConnection {
    let key = generate_ed25519_ssh_key(0x77, "test");
    let (port, fingerprint, _, _) =
        start_mock_ssh_server(0x11, key.private_key.public_key().clone(), allow_forwarding).await;
    let config = SshConnectConfig {
        tab_id: 1,
        role: "destination".into(),
        host: "127.0.0.1".into(),
        port,
        username: "tester".into(),
        password: Some(Zeroizing::new("correct-horse-battery".into())),
        pinned_host_key: Some(fingerprint),
        connect_timeout: Duration::from_secs(2),
        ..Default::default()
    };
    SshConnection::connect(&config).await.expect("authenticated SSH session")
}

#[tokio::test]
async fn graphics_bytes_flow_through_the_authenticated_ssh_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let echo = tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await.unwrap();
        let mut received = [0u8; 5];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"hello");
        peer.write_all(b"world").await.unwrap();
    });
    let ssh = connect(true).await;
    let mut stream = open_graphics_stream(&ssh, &session(port)).await.unwrap();
    stream.write_all(b"hello").await.unwrap();
    let mut received = [0u8; 5];
    stream.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"world");
    drop(stream);
    echo.await.unwrap();
    ssh.disconnect().await.unwrap();
}

#[tokio::test]
async fn refused_forwarding_never_falls_back_to_direct_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let ssh = connect(false).await;
    assert!(open_graphics_stream(&ssh, &session(port)).await.is_err());
    assert!(tokio::time::timeout(Duration::from_millis(200), listener.accept()).await.is_err(),
        "a failed SSH forwarding request must not connect directly");
    ssh.disconnect().await.unwrap();
}
