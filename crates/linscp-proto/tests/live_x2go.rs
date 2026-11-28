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
    let display = agent.session().display();
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
    // Drain updates while exercising input: KDrive can block the X server if
    // the graphics channel is not read as windows are created and repainted.
    let (mut reader, mut writer, agent) = channel.into_parts();
    let drain = tokio::spawn(async move {
        while reader.next_message().await.is_ok() {}
    });
    // An X client on the fixture display observes keyboard input sent through
    // the real KDrive channel, not through the control SSH connection.
    let launch = format!("rm -f ~/x2go-input-result; DISPLAY=:{display} nohup xterm -title LinSCPInputFixture -e sh -c 'IFS= read -r line; printf %s \"$line\" > \"$HOME/x2go-input-result\"' </dev/null >~/x2go-xterm.log 2>&1 &");
    let launched = ssh.exec_command_bounded(&launch, Duration::from_secs(10), 8192).await.expect("launch input fixture");
    assert_eq!(launched.exit_code, Some(0));
    let focus = format!("export DISPLAY=:{display}; timeout 8s xdotool search --sync --onlyvisible --name '^LinSCPInputFixture$' windowfocus --sync || {{ cat ~/x2go-xterm.log >&2; xdotool search --name . >&2 || true; exit 1; }}");
    let focused = ssh.exec_command_bounded(&focus, Duration::from_secs(20), 8192).await.expect("focus input fixture");
    assert_eq!(focused.exit_code, Some(0), "could not focus fixture window: {}", String::from_utf8_lossy(&focused.stderr));
    for (kind, keycode) in [(2u32, 38u32), (3, 38), (2, 36), (3, 36)] {
        let mut event = [0u8; linscp_proto::kdrive_wire::CLIENT_EVENT_SIZE];
        event[..4].copy_from_slice(&kind.to_le_bytes());
        event[8..12].copy_from_slice(&keycode.to_le_bytes());
        writer.write_event(&event, Duration::from_secs(5)).await.expect("send KDrive keyboard input");
    }
    let check = ssh.exec_command_bounded("for i in $(seq 1 50); do test -f ~/x2go-input-result && break; sleep 0.1; done; cat ~/x2go-input-result", Duration::from_secs(10), 8192).await.expect("read input result");
    assert_eq!(check.exit_code, Some(0), "input fixture did not receive Return");
    assert_eq!(check.stdout, b"a", "input fixture did not receive the expected key");
    drain.abort();
    let _ = drain.await;
    drop(writer);
    agent.suspend().await.expect("suspend desktop");
    let sessions = list_sessions(&ssh, Duration::from_secs(15)).await.expect("list sessions");
    assert!(sessions.iter().any(|item| item.session_id == id && item.status == "S"), "suspended session not listed");
    let agent = resume_guarded_agent(ssh.clone(), &id, 800, 600, X2GoLink::Lan, Duration::from_secs(60)).await.expect("resume desktop");
    let mut channel = GuardedKDriveSession::attach(agent, 800, 600, Duration::from_secs(30)).await.expect("reattach graphics");
    let saw_resumed_main = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.reader.next_message().await.expect("read resumed KDrive message") {
                Message::Frame(frame) if frame.is_main_image() => break true,
                Message::Disconnect => break false,
                _ => {}
            }
        }
    }).await.expect("timed out waiting for resumed KDrive frame");
    assert!(saw_resumed_main, "resumed server disconnected before main frame");
    channel.close().await.expect("terminate desktop");
    ssh.disconnect().await.expect("disconnect SSH");
}
