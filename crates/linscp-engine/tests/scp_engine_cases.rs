//! Rust ports of the `live-scp` cases the parity ledger (`docs/upstream-parity.json`,
//! suite `engine-scp`) cites. The retired Python suite drove a `linscp`
//! binary this repository does not build; these cases drive the same
//! behaviour through the engine against the shared in-memory mock SSH
//! server, which serves the remote shell (`ls -l -a --full-time`, `mkdir`,
//! `rm`, `rmdir`, `mv`, `cp`, `chmod`, `ln`, `touch -t`, `readlink`,
//! `sha256sum`) and the server's own `scp -f` / `scp -t`.
//!
//! Every case carries the upstream case name of the same name; the tests
//! carrying that name are what the ledger cites as evidence.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use linscp_engine::script::{BatchMode, ScriptInterpreter, ScriptRunConfig};
use linscp_engine::transfer::{download_single_file, TransferFlags};
use linscp_engine::url_and_raw::ParsedSiteSpec;
use linscp_engine::xml_log::SessionLogger;
use linscp_proto::scp::ScpSession;
use linscp_proto::ssh::SshConnectConfig;
use linscp_proto::{ProgressCallback, RemoteSession};
use linscp_test_support::{
    generate_ed25519_ssh_key, start_mock_ssh_server_with, MemFs, MemNode,
};
use linscp_types::ProtocolScheme;
use zeroize::Zeroizing;

fn test_config(config_dir: &Path) -> ScriptRunConfig {
    ScriptRunConfig {
        config_dir: config_dir.to_path_buf(),
        batch_mode: BatchMode::Abort,
        confirm: false,
        echo: false,
        log_level: 0,
        ..ScriptRunConfig::default()
    }
}

fn in_memory_logger() -> SessionLogger {
    SessionLogger::open(None, 0, false, None, None, false, "linscp-test").expect("a logger opens")
}

/// Connects to a fresh mock SSH server and returns the SCP session, the
/// server's filesystem and the fingerprint the client must pin.
async fn connect_scp(
    host_seed: u8,
    key_seed: u8,
) -> (Arc<ScpSession>, Arc<tokio::sync::Mutex<MemFs>>, String, u16) {
    let user_key = generate_ed25519_ssh_key(key_seed, "tester@linscp");
    let (port, host_sha256, _md5, fs) = start_mock_ssh_server_with(
        host_seed,
        user_key.private_key.public_key().clone(),
        false,
        /* check_file_name */ true,
        /* copy_data */ true,
    )
    .await;
    let cfg = SshConnectConfig {
        tab_id: 1,
        role: "destination".to_string(),
        host: "127.0.0.1".to_string(),
        port,
        username: "tester".to_string(),
        password: Some(Zeroizing::new("correct-horse-battery".to_string())),
        pinned_host_key: Some(host_sha256.clone()),
        ..Default::default()
    };
    let scp = ScpSession::connect(&cfg, None, 0)
        .await
        .expect("connect to the mock SSH server");
    (Arc::new(scp), fs, host_sha256, port)
}

/// Puts a file straight into the server's filesystem, so only the remote
/// shell can hand it over.
async fn seed_file(fs: &Arc<tokio::sync::Mutex<MemFs>>, path: &str, data: &[u8]) {
    fs.lock().await.nodes.insert(
        path.to_string(),
        MemNode::File {
            data: data.to_vec(),
            mode: 0o644,
            mtime: 1_760_000_000,
        },
    );
}

/// Adopts the session in a script interpreter rooted at `local_dir`.
fn adopt(interp: &mut ScriptInterpreter, scp: Arc<ScpSession>, local_dir: &Path) {
    interp.adopt_session(
        ParsedSiteSpec::default(),
        scp as Arc<dyn RemoteSession>,
        "/home/tester".to_string(),
        local_dir.to_path_buf(),
    );
}

/// Splits a line on unquoted semicolons, matching how `-command=...`
/// separates commands.
fn split_semicolons(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    for ch in line.chars() {
        match ch {
            '\'' if !in_double => {
                in_single = !in_single;
                cur.push(ch);
            }
            '"' if !in_single => {
                in_double = !in_double;
                cur.push(ch);
            }
            ';' if !in_single && !in_double => out.push(std::mem::take(&mut cur)),
            _ => cur.push(ch),
        }
    }
    out.push(cur);
    out
}

/// Runs one line (which may hold several `;`-separated commands) and returns
/// (every command succeeded, the text the commands printed).
async fn run_line(interp: &mut ScriptInterpreter, line: &str) -> (bool, String) {
    let seen = interp.capture_console();
    let mut ok = true;
    'outer: for part in split_semicolons(line) {
        let part = part.trim();
        if part.is_empty() || part.starts_with('#') {
            continue;
        }
        if !interp.execute_line(part).await {
            ok = false;
            break 'outer;
        }
        if interp.should_exit() {
            break 'outer;
        }
    }
    let (stdout, stderr) = ScriptInterpreter::collected_console(&seen);
    (ok, format!("{stdout}{stderr}"))
}

/// The bytes the server holds at `path`, or `None` when it holds nothing.
async fn server_bytes(fs: &Arc<tokio::sync::Mutex<MemFs>>, path: &str) -> Option<Vec<u8>> {
    let guard = fs.lock().await;
    match guard.nodes.get(path) {
        Some(MemNode::File { data, .. }) => Some(data.clone()),
        _ => None,
    }
}

/// The bytes and mode the server holds at `path`.
async fn server_node(fs: &Arc<tokio::sync::Mutex<MemFs>>, path: &str) -> Option<(Vec<u8>, u32, u32)> {
    let guard = fs.lock().await;
    match guard.nodes.get(path) {
        Some(MemNode::File { data, mode, mtime }) => Some((data.clone(), *mode, *mtime)),
        _ => None,
    }
}

/// A download and an upload carry the bytes exactly: the file the server
/// holds arrives locally unchanged, and a local file reaches the server
/// unchanged.
#[tokio::test]
async fn test_download_and_upload_carry_the_bytes_intact() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let (scp, fs, _fp, _port) = connect_scp(0x61, 0x62).await;
    // Big enough to be staged: a download of this size is written to the
    // '.filepart' file and renamed onto the destination when it is whole.
    let payload: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
    seed_file(&fs, "/home/tester/payload.bin", &payload).await;

    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());
    adopt(&mut interp, Arc::clone(&scp), tmp.path());

    let (ok, out) = run_line(&mut interp, "get /home/tester/payload.bin payload.bin").await;
    assert!(ok, "the download succeeds: {out}");
    let local = std::fs::read(tmp.path().join("payload.bin")).expect("the local copy");
    assert_eq!(local, payload, "the bytes arrive unchanged");
    assert!(
        !tmp.path().join("payload.bin.filepart").exists(),
        "the staging file was renamed onto the destination"
    );

    std::fs::write(tmp.path().join("upload.bin"), b"bytes going up\n").expect("write the local file");
    let (ok, out) = run_line(
        &mut interp,
        "option sftpriskypublish on ; put upload.bin /home/tester/uploaded.bin",
    )
    .await;
    assert!(ok, "the upload succeeds: {out}");
    assert_eq!(
        server_bytes(&fs, "/home/tester/uploaded.bin").await,
        Some(b"bytes going up\n".to_vec()),
        "the server holds the uploaded bytes"
    );
    // The stage the client published through is gone; only the destination
    // is left on the server.
    let leftover: Vec<String> = fs
        .lock()
        .await
        .nodes
        .keys()
        .filter(|k| k.contains("linscp-sftp-stage") || k.contains("linscp-scp-stage"))
        .cloned()
        .collect();
    assert!(leftover.is_empty(), "no stage is left behind: {leftover:?}");

    let _ = scp.close().await;
}

/// A tree goes up as a tree, and a copy the server performs itself never
/// travels through the client.
#[tokio::test]
async fn test_recursive_transfer_and_server_side_copy() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let (scp, fs, _fp, _port) = connect_scp(0x63, 0x64).await;

    let tree = tmp.path().join("tree");
    std::fs::create_dir_all(tree.join("nested")).expect("the local tree");
    std::fs::write(tree.join("top.txt"), b"top level\n").expect("top file");
    std::fs::write(tree.join("nested/inner.txt"), b"inner level\n").expect("inner file");

    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());
    adopt(&mut interp, Arc::clone(&scp), tmp.path());

    let (ok, out) = run_line(
        &mut interp,
        "option sftpriskypublish on ; put -r tree /home/tester/tree",
    )
    .await;
    assert!(ok, "the recursive upload succeeds: {out}");
    assert_eq!(
        server_bytes(&fs, "/home/tester/tree/top.txt").await,
        Some(b"top level\n".to_vec()),
        "the top-level file reached the server"
    );
    assert_eq!(
        server_bytes(&fs, "/home/tester/tree/nested/inner.txt").await,
        Some(b"inner level\n".to_vec()),
        "the nested file reached the server"
    );

    // A server-side copy: the bytes never pass through this client.
    seed_file(&fs, "/home/tester/original.txt", b"copied on the server\n").await;
    let (ok, out) = run_line(
        &mut interp,
        "cp /home/tester/original.txt /home/tester/copy.txt",
    )
    .await;
    assert!(ok, "the server-side copy succeeds: {out}");
    assert_eq!(
        server_bytes(&fs, "/home/tester/copy.txt").await,
        Some(b"copied on the server\n".to_vec()),
        "the server made the copy"
    );

    let _ = scp.close().await;
}

/// A partial transfer is refused by name instead of attempted: SCP has no
/// offset to continue from, so the client says so and leaves the local file
/// it was asked to continue alone.
#[tokio::test]
async fn test_a_partial_transfer_is_neither_resumed_nor_left_behind() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let (scp, fs, _fp, _port) = connect_scp(0x65, 0x66).await;
    seed_file(&fs, "/home/tester/big.bin", &vec![b'x'; 4096]).await;

    std::fs::write(tmp.path().join("big.bin"), b"a partial file").expect("the partial file");
    let before = std::fs::read(tmp.path().join("big.bin")).expect("read the partial file");

    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());
    adopt(&mut interp, Arc::clone(&scp), tmp.path());

    let (ok, out) = run_line(&mut interp, "get -resume /home/tester/big.bin big.bin").await;
    assert!(!ok, "the resume is refused: {out}");
    assert!(
        out.contains("cannot resume") || out.contains("does not support"),
        "the refusal names the protocol's limit: {out}"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("big.bin")).expect("read the partial file"),
        before,
        "the partial file the client was asked to continue is untouched"
    );

    let _ = scp.close().await;
}

/// An interrupted download leaves nothing under the final name: the bytes
/// that did arrive stay in the staging file, so a later run can continue
/// them, and the destination is never a spliced half-file.
#[tokio::test]
async fn test_an_interrupted_download_leaves_nothing_under_the_final_name() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let (scp, fs, _fp, _port) = connect_scp(0x67, 0x68).await;
    seed_file(&fs, "/home/tester/large.bin", &vec![b'y'; 64 * 1024]).await;

    let dest = tmp.path().join("large.bin");
    let flags = TransferFlags {
        // Smart staging with a one-byte threshold: the file is big enough
        // to be staged, and the protocol's own resume limit is not asked
        // for.
        resume_support: linscp_engine::presets::ResumeSupportMode::Smart(1),
        ..TransferFlags::default()
    };
    let cancel = Arc::new(AtomicBool::new(true));
    let flags = TransferFlags {
        cancel_flag: Some(cancel.clone()),
        ..flags
    };
    let mut logger = in_memory_logger();
    let err = download_single_file(
        scp.as_ref() as &dyn RemoteSession,
        "/home/tester/large.bin",
        None,
        &dest,
        &flags,
        &mut logger,
        None,
    )
    .await
    .expect_err("the cancelled download fails");
    assert!(
        err.contains("cancel") || err.contains("interrupt"),
        "the failure names the cancellation: {err}"
    );
    assert!(
        !dest.exists(),
        "nothing is published under the final name: {}",
        dest.display()
    );
    let stage = tmp.path().join("large.bin.filepart");
    assert!(
        !stage.exists() || stage.metadata().map(|m| m.len()).unwrap_or(0) < 64 * 1024,
        "the staging file never holds the whole file"
    );

    let _ = scp.close().await;
}

/// ASCII conversion turns the line endings the server holds into the ones
/// the client asked for, and the bytes between the endings are untouched.
#[tokio::test]
async fn test_an_ascii_transfer_converts_the_line_endings() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let (scp, fs, _fp, _port) = connect_scp(0x69, 0x6a).await;
    seed_file(&fs, "/home/tester/text.txt", b"first\r\nsecond\r\n").await;

    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());
    adopt(&mut interp, Arc::clone(&scp), tmp.path());

    let (ok, out) = run_line(
        &mut interp,
        "get -transfer=ascii -eol=lf /home/tester/text.txt text.txt",
    )
    .await;
    assert!(ok, "the ascii download succeeds: {out}");
    let local = std::fs::read(tmp.path().join("text.txt")).expect("the local copy");
    assert_eq!(local, b"first\nsecond\n", "the line endings were converted");

    let _ = scp.close().await;
}

/// A speed limit paces the transfer: the bytes arrive whole, but they take
/// the time the limit asks for.
#[tokio::test]
async fn test_a_speed_limit_paces_the_transfer() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let (scp, fs, _fp, _port) = connect_scp(0x6b, 0x6c).await;
    let payload = vec![b'z'; 64 * 1024];
    seed_file(&fs, "/home/tester/slow.bin", &payload).await;

    let dest = tmp.path().join("slow.bin");
    let flags = TransferFlags {
        speed_kbytes_per_sec: Some(32),
        ..TransferFlags::default()
    };
    let mut logger = in_memory_logger();
    let started = Instant::now();
    download_single_file(
        scp.as_ref() as &dyn RemoteSession,
        "/home/tester/slow.bin",
        None,
        &dest,
        &flags,
        &mut logger,
        None,
    )
    .await
    .expect("the paced download succeeds");
    let elapsed = started.elapsed();
    assert_eq!(
        std::fs::read(&dest).expect("the local copy").len(),
        payload.len(),
        "every byte arrived"
    );
    assert!(
        elapsed.as_millis() >= 1200,
        "the transfer took the time the limit asks for: {elapsed:?}"
    );

    let _ = scp.close().await;
}

/// The progress callback is told what has been transferred and how much
/// there is, while the transfer runs.
#[tokio::test]
async fn test_progress_is_reported_while_the_transfer_runs() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let (scp, fs, _fp, _port) = connect_scp(0x6d, 0x6e).await;
    seed_file(&fs, "/home/tester/metered.bin", &vec![b'm'; 96 * 1024]).await;

    let dest = tmp.path().join("metered.bin");
    let seen = Arc::new(AtomicU64::new(0));
    let last = Arc::new(AtomicU64::new(0));
    let seen_for_cb = Arc::clone(&seen);
    let last_for_cb = Arc::clone(&last);
    let callback: &ProgressCallback = &move |done: u64, total: u64| {
        seen_for_cb.fetch_add(1, Ordering::SeqCst);
        last_for_cb.store(total, Ordering::SeqCst);
    };
    let mut logger = in_memory_logger();
    download_single_file(
        scp.as_ref() as &dyn RemoteSession,
        "/home/tester/metered.bin",
        None,
        &dest,
        &TransferFlags::default(),
        &mut logger,
        Some(callback),
    )
    .await
    .expect("the metered download succeeds");
    assert!(seen.load(Ordering::SeqCst) > 0, "the progress callback ran");
    assert_eq!(
        last.load(Ordering::SeqCst),
        96 * 1024,
        "the callback was told the whole size"
    );

    let _ = scp.close().await;
}

/// The listing and the stat come from the server's own shell, so a file the
/// client never knew about is listed with the server's permissions.
#[tokio::test]
async fn test_listing_and_stat_come_from_the_server_shell() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let (scp, fs, _fp, _port) = connect_scp(0x6f, 0x70).await;
    seed_file(&fs, "/home/tester/listed.txt", b"listed\n").await;
    seed_file(&fs, "/home/tester/name with spaces.txt", b"spaced\n").await;
    seed_file(&fs, "/home/tester/target.txt", b"target\n").await;
    fs.lock().await.nodes.insert(
        "/home/tester/only-a-directory".to_string(),
        MemNode::Dir {
            mode: 0o750,
            mtime: 1_760_000_000,
        },
    );
    fs.lock().await.nodes.insert(
        "/home/tester/a-link.txt".to_string(),
        MemNode::Symlink {
            target: "target.txt".to_string(),
            mtime: 1_760_000_000,
        },
    );

    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());
    adopt(&mut interp, Arc::clone(&scp), tmp.path());

    let (ok, out) = run_line(&mut interp, "ls -l /home/tester").await;
    assert!(ok, "the listing succeeds: {out}");
    assert!(
        out.contains("listed.txt"),
        "the server's file is in the listing: {out}"
    );
    assert!(
        out.contains("only-a-directory"),
        "the server's directory is in the listing: {out}"
    );
    assert!(
        out.contains("-rw-r--r--") || out.contains("rw-r--r--"),
        "the listing carries the server's permissions: {out}"
    );
    assert!(
        out.contains("name with spaces.txt"),
        "a name with spaces is kept whole: {out}"
    );
    assert!(
        out.contains("a-link.txt") && out.contains("->"),
        "a symbolic link keeps its link type: {out}"
    );

    // The server's own listing names the directory and its parent; neither
    // is a file the client offers.
    let entries = scp.list_dir("/home/tester").await.expect("list the directory");
    assert!(
        entries.iter().all(|e| e.name != "." && e.name != ".."),
        "the directory's own entries are skipped: {:?}",
        entries.iter().map(|e| &e.name).collect::<Vec<_>>()
    );

    let (ok, out) = run_line(&mut interp, "stat /home/tester/listed.txt").await;
    assert!(ok, "the stat succeeds: {out}");
    assert!(
        out.contains("listed.txt"),
        "the stat names the file: {out}"
    );

    // The server prints its timestamps with an offset; the client reads
    // them in that offset, so the time it keeps is the server's own.
    let entry = scp
        .stat("/home/tester/listed.txt")
        .await
        .expect("stat the file")
        .expect("the file is there");
    assert_eq!(
        entry.mtime, 1_773_576_000,
        "the server's timestamp is read with the offset the server printed"
    );

    // A path the server does not have is reported as missing, not invented.
    let (ok, out) = run_line(&mut interp, "stat /home/tester/not-there.txt").await;
    assert!(!ok, "the missing path fails: {out}");

    let _ = scp.close().await;
}

/// `cd` changes the directory the following commands work in, and the
/// client reports where the server says it is.
#[tokio::test]
async fn test_cd_reports_the_directory_the_server_changed_into() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let (scp, fs, _fp, _port) = connect_scp(0x71, 0x72).await;
    seed_file(&fs, "/home/other/inside.txt", b"inside\n").await;
    fs.lock().await.nodes.insert(
        "/home/other".to_string(),
        MemNode::Dir {
            mode: 0o755,
            mtime: 1_760_000_000,
        },
    );

    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());
    adopt(&mut interp, Arc::clone(&scp), tmp.path());

    let (ok, out) = run_line(&mut interp, "cd /home/other").await;
    assert!(ok, "the cd succeeds: {out}");
    let (ok, out) = run_line(&mut interp, "ls -1").await;
    assert!(ok, "the listing in the new directory succeeds: {out}");
    assert!(
        out.contains("inside.txt"),
        "the listing is of the directory the client changed into: {out}"
    );

    let _ = scp.close().await;
}

/// `open` resolves the home directory and the initial path the session was
/// asked for.
#[tokio::test]
async fn test_open_resolves_the_home_directory_and_the_initial_path() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let (scp, fs, fingerprint, port) = connect_scp(0x73, 0x74).await;
    let _ = scp.close().await;

    fs.lock().await.nodes.insert(
        "/home/tester/deep".to_string(),
        MemNode::Dir {
            mode: 0o755,
            mtime: 1_760_000_000,
        },
    );

    let mut spec = ParsedSiteSpec::default();
    spec.session.protocol = ProtocolScheme::Scp;
    spec.session.host = "127.0.0.1".to_string();
    spec.session.port = port;
    spec.session.username = "tester".to_string();
    spec.session.password = Some("correct-horse-battery".to_string());
    spec.session.hostkey = fingerprint;

    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());
    // Without an initial path the session starts in the home directory.
    interp
        .connect_initial_site(spec.clone())
        .await
        .expect("the session opens");
    let (ok, out) = run_line(&mut interp, "pwd").await;
    assert!(ok, "the working directory is reported: {out}");
    assert!(
        out.contains("/home/tester"),
        "the session started in the home directory: {out}"
    );

    // With an initial path it starts there.
    let mut spec = spec;
    spec.session.initial_dir = "/home/tester/deep".to_string();
    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());
    interp
        .connect_initial_site(spec)
        .await
        .expect("the session opens at the initial path");
    let (ok, out) = run_line(&mut interp, "pwd").await;
    assert!(ok, "the working directory is reported: {out}");
    assert!(
        out.contains("/home/tester/deep"),
        "the session started in the initial path: {out}"
    );
}

/// A session to an endpoint that is not there is refused, and the refusal
/// names the endpoint.
#[tokio::test]
async fn test_a_session_to_an_endpoint_that_is_not_there_is_refused() {
    let tmp = tempfile::tempdir().expect("temp dir");
    // A port nothing listens on: the listener is bound and dropped, so the
    // port is free.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a port");
    let port = listener.local_addr().expect("the address").port();
    drop(listener);

    let mut spec = ParsedSiteSpec::default();
    spec.session.protocol = ProtocolScheme::Scp;
    spec.session.host = "127.0.0.1".to_string();
    spec.session.port = port;
    spec.session.username = "tester".to_string();
    spec.session.password = Some("correct-horse-battery".to_string());

    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());
    let err = interp
        .connect_initial_site(spec)
        .await
        .expect_err("the session is refused");
    assert!(
        err.contains("127.0.0.1") || err.contains("Cannot open session"),
        "the refusal names the endpoint: {err}"
    );
}

/// The directory and permission operations reach the server: the server's
/// filesystem is what changes.
#[tokio::test]
async fn test_directory_and_permission_operations_reach_the_server() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let (scp, fs, _fp, _port) = connect_scp(0x75, 0x76).await;
    seed_file(&fs, "/home/tester/doomed.txt", b"doomed\n").await;
    seed_file(&fs, "/home/tester/moved.txt", b"moved\n").await;

    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());
    adopt(&mut interp, Arc::clone(&scp), tmp.path());

    let (ok, out) = run_line(&mut interp, "mkdir /home/tester/made").await;
    assert!(ok, "the mkdir succeeds: {out}");
    assert!(
        matches!(
            fs.lock().await.nodes.get("/home/tester/made"),
            Some(MemNode::Dir { .. })
        ),
        "the directory exists on the server"
    );

    let (ok, out) = run_line(&mut interp, "chmod 600 /home/tester/doomed.txt").await;
    assert!(ok, "the chmod succeeds: {out}");
    let (_, mode, _) = server_node(&fs, "/home/tester/doomed.txt")
        .await
        .expect("the file is on the server");
    assert_eq!(mode & 0o777, 0o600, "the server holds the new mode");

    let (ok, out) = run_line(&mut interp, "rm /home/tester/doomed.txt").await;
    assert!(ok, "the rm succeeds: {out}");
    assert!(
        server_bytes(&fs, "/home/tester/doomed.txt").await.is_none(),
        "the file is gone from the server"
    );

    let (ok, out) = run_line(
        &mut interp,
        "mv /home/tester/moved.txt /home/tester/moved-on.txt",
    )
    .await;
    assert!(ok, "the mv succeeds: {out}");
    assert!(
        server_bytes(&fs, "/home/tester/moved.txt").await.is_none(),
        "the old name is gone from the server"
    );
    assert_eq!(
        server_bytes(&fs, "/home/tester/moved-on.txt").await,
        Some(b"moved\n".to_vec()),
        "the new name holds the file on the server"
    );

    let (ok, out) = run_line(&mut interp, "rmdir /home/tester/made").await;
    assert!(ok, "the rmdir succeeds: {out}");
    assert!(
        !fs.lock().await.nodes.contains_key("/home/tester/made"),
        "the directory is gone from the server"
    );

    let _ = scp.close().await;
}

/// A symbolic link, the timestamp and the permissions an upload carries all
/// end up on the server.
#[tokio::test]
async fn test_symlink_times_and_upload_permissions_are_set_on_the_server() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let (scp, fs, _fp, _port) = connect_scp(0x77, 0x78).await;
    seed_file(&fs, "/home/tester/target.txt", b"target\n").await;

    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());
    adopt(&mut interp, Arc::clone(&scp), tmp.path());

    let (ok, out) = run_line(
        &mut interp,
        "ln /home/tester/target.txt /home/tester/link.txt",
    )
    .await;
    assert!(ok, "the ln succeeds: {out}");
    let guard = fs.lock().await;
    match guard.nodes.get("/home/tester/link.txt") {
        Some(MemNode::Symlink { target, .. }) => {
            assert!(
                target.contains("target.txt"),
                "the link points at the target: {target}"
            );
        }
        other => panic!("the link is on the server: {other:?}"),
    }
    drop(guard);

    // An upload that carries permissions and the local timestamp.
    let local = tmp.path().join("stamped.txt");
    std::fs::write(&local, b"stamped\n").expect("write the local file");
    let stamp = filetime::FileTime::from_unix_time(1_600_000_000, 0);
    filetime::set_file_mtime(&local, stamp).expect("pin the local timestamp");

    let (ok, out) = run_line(
        &mut interp,
        "option sftpriskypublish on ; put -permissions=0755 -preservetime stamped.txt /home/tester/stamped.txt",
    )
    .await;
    assert!(ok, "the upload succeeds: {out}");
    let (_, mode, mtime) = server_node(&fs, "/home/tester/stamped.txt")
        .await
        .expect("the file is on the server");
    assert_eq!(mode & 0o777, 0o755, "the server holds the uploaded mode");
    assert_eq!(mtime as i64, 1_600_000_000, "the server holds the uploaded time");

    let _ = scp.close().await;
}

/// A remote command runs on the server, and a checksum is computed over
/// what the server holds.
#[tokio::test]
async fn test_a_remote_command_runs_on_the_server_and_a_checksum_is_computed() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let (scp, fs, _fp, _port) = connect_scp(0x79, 0x7a).await;
    seed_file(&fs, "/home/tester/hashed.txt", b"hash me\n").await;

    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());
    adopt(&mut interp, Arc::clone(&scp), tmp.path());

    let (ok, out) = run_line(&mut interp, "call sha256sum /home/tester/hashed.txt").await;
    assert!(ok, "the remote command succeeds: {out}");
    assert!(
        out.contains("hashed.txt"),
        "the server's own answer is printed: {out}"
    );

    let (ok, out) = run_line(&mut interp, "checksum sha256 /home/tester/hashed.txt").await;
    assert!(ok, "the checksum succeeds: {out}");
    let expected = {
        use linscp_crypto::digests::{compute_digest, DigestAlgorithm};
        let hex: String = compute_digest(DigestAlgorithm::Sha256, b"hash me\n")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        hex
    };
    assert!(
        out.contains(&expected),
        "the checksum is the digest of the server's bytes: {out}"
    );
    assert!(
        out.contains("computed from the downloaded file"),
        "the checksum says where the digest came from: {out}"
    );

    let _ = scp.close().await;
}

/// An operation the server refuses is reported with what the server said.
#[tokio::test]
async fn test_an_operation_the_server_refuses_says_what_the_server_said() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let (scp, fs, _fp, _port) = connect_scp(0x7b, 0x7c).await;
    seed_file(&fs, "/home/tester/busy/inside.txt", b"inside\n").await;
    fs.lock().await.nodes.insert(
        "/home/tester/busy".to_string(),
        MemNode::Dir {
            mode: 0o755,
            mtime: 1_760_000_000,
        },
    );

    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());
    adopt(&mut interp, Arc::clone(&scp), tmp.path());

    let (ok, out) = run_line(&mut interp, "rmdir /home/tester/busy").await;
    assert!(!ok, "the rmdir of a busy directory fails: {out}");
    assert!(
        out.contains("Directory not empty"),
        "the server's own words are reported: {out}"
    );

    let (ok, out) = run_line(&mut interp, "rm /home/tester/not-there.txt").await;
    assert!(!ok, "the rm of a missing file fails: {out}");
    assert!(
        out.contains("No such file or directory"),
        "the server's own words are reported: {out}"
    );

    let _ = scp.close().await;
}

/// A relative path is resolved against the directory the client changed
/// into, not against the home directory it started in.
#[tokio::test]
async fn test_rmdir_resolves_relative_directory_after_cd() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let (scp, fs, _fp, _port) = connect_scp(0x7d, 0x7e).await;
    fs.lock().await.nodes.insert(
        "/home/tester/relative".to_string(),
        MemNode::Dir {
            mode: 0o755,
            mtime: 1_760_000_000,
        },
    );
    // The same name in the home directory must not be the one removed.
    fs.lock().await.nodes.insert(
        "/home/relative".to_string(),
        MemNode::Dir {
            mode: 0o755,
            mtime: 1_760_000_000,
        },
    );

    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());
    adopt(&mut interp, Arc::clone(&scp), tmp.path());

    let (ok, out) = run_line(&mut interp, "cd /home/tester ; rmdir relative").await;
    assert!(ok, "the rmdir succeeds: {out}");
    let guard = fs.lock().await;
    assert!(
        !guard.nodes.contains_key("/home/tester/relative"),
        "the relative directory in the current directory was removed"
    );
    assert!(
        guard.nodes.contains_key("/home/relative"),
        "the directory of the same name elsewhere was left alone"
    );

    let _ = scp.close().await;
}

/// A server whose `ls` knows no `--full-time` is asked in the plainer way
/// instead of being an error.
#[tokio::test]
async fn test_a_server_without_full_time_ls_is_asked_in_the_plainer_way() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let (scp, fs, _fp, _port) = connect_scp(0x7f, 0x80).await;
    seed_file(&fs, "/home/tester/plain.txt", b"plain\n").await;
    {
        let mut guard = fs.lock().await;
        guard.disable_ls_full_time = true;
        guard.disable_env = true;
    }

    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());
    adopt(&mut interp, Arc::clone(&scp), tmp.path());

    let (ok, out) = run_line(&mut interp, "ls -l /home/tester").await;
    assert!(ok, "the listing still succeeds: {out}");
    assert!(
        out.contains("plain.txt"),
        "the server's file is in the listing: {out}"
    );
    assert!(
        fs.lock().await.ls_full_time_attempts > 0,
        "the client tried the richer command first"
    );
    assert!(
        out.contains("plain.txt"),
        "the plainer command still listed the directory: {out}"
    );

    let _ = scp.close().await;
}

/// A server with no `cp` of its own is answered by streaming the file
/// through this client.
#[tokio::test]
async fn test_a_server_without_cp_is_answered_by_streaming_through_the_client() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let (scp, fs, _fp, _port) = connect_scp(0x81, 0x82).await;
    seed_file(&fs, "/home/tester/source.txt", b"streamed through\n").await;
    fs.lock().await.disable_shell_cp = true;

    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());
    adopt(&mut interp, Arc::clone(&scp), tmp.path());

    let (ok, out) = run_line(
        &mut interp,
        "cp /home/tester/source.txt /home/tester/streamed.txt",
    )
    .await;
    assert!(ok, "the copy succeeds: {out}");
    assert_eq!(
        server_bytes(&fs, "/home/tester/streamed.txt").await,
        Some(b"streamed through\n".to_vec()),
        "the file arrived through the client"
    );

    let _ = scp.close().await;
}

/// A file mask prunes what a transfer takes: the excluded name never
/// reaches the server and never lands locally.
#[tokio::test]
async fn test_a_file_mask_prunes_what_the_transfer_takes() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let (scp, fs, _fp, _port) = connect_scp(0x83, 0x84).await;
    seed_file(&fs, "/home/tester/keep.txt", b"keep\n").await;
    seed_file(&fs, "/home/tester/skip.log", b"skip\n").await;

    let dest = tmp.path().join("out");
    std::fs::create_dir_all(&dest).expect("the local directory");
    let flags = TransferFlags {
        file_mask: linscp_engine::filemask::FileMask::parse("| *.log")
            .expect("the mask parses"),
        ..TransferFlags::default()
    };
    let mut logger = in_memory_logger();
    let taken = download_single_file(
        scp.as_ref() as &dyn RemoteSession,
        "/home/tester/keep.txt",
        None,
        &dest.join("keep.txt"),
        &flags,
        &mut logger,
        None,
    )
    .await
    .expect("the kept file is downloaded");
    assert!(taken, "the file the mask allows is taken");

    let skipped = download_single_file(
        scp.as_ref() as &dyn RemoteSession,
        "/home/tester/skip.log",
        None,
        &dest.join("skip.log"),
        &flags,
        &mut logger,
        None,
    )
    .await
    .expect("the masked file is skipped, not an error");
    assert!(!skipped, "the file the mask excludes is left alone");
    assert!(
        !dest.join("skip.log").exists(),
        "the excluded file never lands locally"
    );

    let _ = scp.close().await;
}
