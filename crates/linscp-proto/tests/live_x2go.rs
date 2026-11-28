//! Opt-in integration test against an isolated X2Go KDrive server over SSH.
//! Set LSCP_LIVE_X2GO=1 only for the disposable CI fixture, not a real account.

use std::sync::Arc;
use std::time::Duration;
use linscp_proto::kdrive_wire::Message;
use linscp_proto::ssh::{SshConnectConfig, SshConnection};
use linscp_proto::x2go_control::{list_sessions, resume_guarded_agent, start_guarded_agent, X2GoDesktop, X2GoLink};
use linscp_proto::x2go_transport::GuardedKDriveSession;
use zeroize::Zeroizing;

#[tokio::test]
async fn x2go_kdrive_start_frames_suspend_resume_and_terminate() {
    if std::env::var_os("LSCP_LIVE_X2GO").is_none() { return; }
    let config = SshConnectConfig {
        tab_id: 1, role: "destination".into(), host: "127.0.0.1".into(), port: 22222,
        username: "x2gotest".into(), password: Some(Zeroizing::new("fixture-password".into())),
        // Only the local disposable runner is used; real connections must pin host keys.
        danger_accept_any_host_key: true, connect_timeout: Duration::from_secs(10),
        ..Default::default()
    };
    let ssh = Arc::new(SshConnection::connect(&config).await.expect("connect to fixture SSH"));
    let agent = start_guarded_agent(ssh.clone(), 800, 600, X2GoDesktop::Xfce, X2GoLink::Lan, Duration::from_secs(60)).await.expect("start KDrive agent");
    let id = agent.session().session_id().to_owned();
    let mut channel = GuardedKDriveSession::attach(agent, 800, 600, Duration::from_secs(30)).await.expect("negotiate KDrive graphics over SSH");
    channel.start_desktop(X2GoDesktop::Xfce).await.expect("launch desktop");
    let saw_main = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            match channel.reader.next_message().await.expect("read KDrive message") {
                Message::Frame(frame) if frame.is_main_image() => break true,
                Message::Disconnect => break false,
                _ => {}
            }
        }
    }).await.expect("timed out waiting for KDrive main frame");
    assert!(saw_main, "server disconnected before main frame");
    channel.suspend().await.expect("suspend desktop");
    let sessions = list_sessions(&ssh, Duration::from_secs(15)).await.expect("list sessions");
    assert!(sessions.iter().any(|item| item.session_id == id && item.status == "S"), "suspended session not listed");
    let agent = resume_guarded_agent(ssh.clone(), &id, 800, 600, X2GoLink::Lan, Duration::from_secs(60)).await.expect("resume desktop");
    let channel = GuardedKDriveSession::attach(agent, 800, 600, Duration::from_secs(30)).await.expect("reattach graphics");
    channel.close().await.expect("terminate desktop");
    ssh.disconnect().await.expect("disconnect SSH");
}
