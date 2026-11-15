//! Granular ports of the `live-sftp` suite cases the parity ledger
//! (`docs/upstream-parity.json`, suite `engine-sftp`) cites, plus the
//! change-guards proving where this build diverges from the upstream case
//! until the gap is closed. Each upstream-mirroring test carries the
//! upstream case of the same name; tests carrying that name are what the
//! ledger cites as evidence. Everything runs against the shared in-memory
//! mock SSH/SFTP server — the same one the `proto-ssh` suite uses — driving
//! the script interpreter end to end.
//!
//! Not ported (evidenced here only as change-guards, never as upstream
//! coverage): guarded/overwrite SFTP uploads themselves. The build refuses
//! unguarded SFTP uploads by design ("Unguarded SFTP/FTP uploads are
//! disabled; use exclusive creation ..."), so `synchronize remote`,
//! `keepuptodate` and the upload half of `synchronize both` cannot complete
//! against the mock until that gap closes. The conflict-resolution phase of
//! `synchronize both` needs no upload (a conflicted pair is left alone) and
//! is ported in full.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use filetime::FileTime;
use linscp_engine::filemask::mode_from_permissions_str;
use linscp_engine::script::{BatchMode, ScriptInterpreter, ScriptRunConfig};
use linscp_engine::url_and_raw::ParsedSiteSpec;
use linscp_engine::xml_log::SessionLogger;
use linscp_proto::sftp::SftpClientSession;
use linscp_proto::ssh::SshConnectConfig;
use linscp_proto::{download_bytes, upload_bytes, RemoteSession, TransferRequest};
use linscp_test_support::{generate_ed25519_ssh_key, start_mock_ssh_server};
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
    SessionLogger::open(None, 0, false, None, None, false, "linscp-test")
        .expect("an in-memory logger opens")
}

/// Connects to a fresh mock SSH/SFTP server (seeded with caller-chosen host
/// and key seeds) and returns the session plus the pinned host fingerprint.
async fn connect_mock(host_seed: u8, key_seed: u8) -> (Arc<SftpClientSession>, String) {
    let user_key = generate_ed25519_ssh_key(key_seed, "tester@linscp");
    let (port, host_sha256, _md5, _fs) =
        start_mock_ssh_server(host_seed, user_key.private_key.public_key().clone(), false).await;
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
    let sftp = SftpClientSession::connect(ProtocolScheme::Sftp, &cfg, None, 0)
        .await
        .expect("connect to the mock SSH server");
    (Arc::new(sftp), host_sha256)
}

/// Adopts the session in a script interpreter rooted at `local_dir`.
fn adopt(interp: &mut ScriptInterpreter, sftp: Arc<SftpClientSession>, local_dir: &Path) {
    interp.adopt_session(
        ParsedSiteSpec::default(),
        sftp as Arc<dyn RemoteSession>,
        "/home/tester".to_string(),
        local_dir.to_path_buf(),
    );
}

/// Splits a line on unquoted semicolons, matching how `-command=...`
/// separates commands. Quote-aware, like the script tokenizer.
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

/// Runs a multi-line script against the adopted session, honouring the
/// batch-abort semantics of a real run: a failed command stops the rest of
/// the script. Returns (every command succeeded, captured console text).
async fn run_script(interp: &mut ScriptInterpreter, script: &str) -> (bool, String) {
    let seen = interp.capture_console();
    let mut ok = true;
    'outer: for raw in script.lines() {
        for part in split_semicolons(raw) {
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
    }
    let (stdout, stderr) = ScriptInterpreter::collected_console(&seen);
    (ok, format!("{stdout}{stderr}"))
}

/// Runs one line (which may hold several `;`-separated commands) and returns
/// (success, captured text).
async fn run_line_captured(interp: &mut ScriptInterpreter, line: &str) -> (bool, String) {
    run_script(interp, line).await
}

/// Writes `data` to the remote path and pins its mtime when asked.
async fn seed_remote(sftp: &SftpClientSession, path: &str, data: &[u8], mtime: Option<i64>) {
    upload_bytes(sftp, path, data, TransferRequest::default())
        .await
        .expect("seed the remote file");
    if let Some(stamp) = mtime {
        sftp.set_mtime(path, stamp).await.expect("pin the remote mtime");
    }
}


/// A recursive symbolic mode applies to every directory and file below the
/// requested path, not just the top-level entry: `chmod -recursive g+w`
/// widens group write on the root, the nested directory and the nested file
/// alike. Symbolic links are skipped, and a mode the parser refuses is a
/// failure rather than a partial run.
#[tokio::test]
async fn test_chmod_symbolic_mode_recurses_over_directories_and_files() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let (sftp, _fp) = connect_mock(0x51, 0x52).await;
    sftp.mkdir("/home/tester/modedir").await.expect("create the root dir");
    sftp.mkdir("/home/tester/modedir/nested").await.expect("create the nested dir");
    seed_remote(&sftp, "/home/tester/modedir/nested/data.txt", b"mode test\n", None)
        .await;
    // A symlink must be skipped by the recursive walk.
    sftp.symlink("data.txt", "/home/tester/modedir/nested/current.txt")
        .await
        .expect("create the symlink");

    // Reset the tree to the upstream fixture modes.
    sftp.chmod("/home/tester/modedir/nested/data.txt", 0o640).await.unwrap();
    sftp.chmod("/home/tester/modedir/nested", 0o750).await.unwrap();
    sftp.chmod("/home/tester/modedir", 0o755).await.unwrap();
    let link_before = sftp
        .stat("/home/tester/modedir/nested/current.txt")
        .await
        .unwrap()
        .expect("link stat");
    assert!(link_before.is_symlink, "the fixture link is a symlink");

    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());
    adopt(&mut interp, Arc::clone(&sftp), tmp.path());

    let (ok, out) = run_line_captured(
        &mut interp,
        "chmod -recursive g+w /home/tester/modedir",
    )
    .await;
    assert!(ok, "chmod -recursive reports success: {out}");

    let mode_of = |e: &linscp_types::FileEntry| mode_from_permissions_str(&e.permissions);
    let root = sftp.stat("/home/tester/modedir").await.unwrap().expect("root stat");
    assert_eq!(mode_of(&root) & 0o777, 0o775, "the root gained group write");
    let nested = sftp.stat("/home/tester/modedir/nested").await.unwrap().expect("nested stat");
    assert_eq!(mode_of(&nested) & 0o777, 0o770, "the nested directory gained group write");
    let data = sftp.stat("/home/tester/modedir/nested/data.txt").await.unwrap().expect("data stat");
    assert_eq!(mode_of(&data) & 0o777, 0o660, "the nested file gained group write");
    let link = sftp
        .stat("/home/tester/modedir/nested/current.txt")
        .await
        .unwrap()
        .expect("link stat");
    assert_eq!(mode_of(&link) & 0o7777, mode_of(&link_before) & 0o7777, "the symlink kept its mode");

    // A mode the parser refuses is reported as a failure and changes nothing.
    let (ok, out) = run_line_captured(
        &mut interp,
        "chmod -recursive bogus-mode /home/tester/modedir",
    )
    .await;
    assert!(!ok, "the bogus mode is refused: {out}");
    let root = sftp.stat("/home/tester/modedir").await.unwrap().expect("root stat");
    assert_eq!(mode_of(&root) & 0o777, 0o775, "the refusal did not widen anything");

    sftp.close().await.unwrap();
}

/// `ln` and `symlink` create symbolic links on the server, and the
/// recursive `chmod` below it applies both a symbolic mode list (`u+x,go+r`)
/// and an octal mode (`-r 750`) to directories and files alike, leaving the
/// links alone.
#[tokio::test]
async fn test_ln_symlink_and_recursive_chmod() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let (sftp, _fp) = connect_mock(0x53, 0x54).await;
    seed_remote(&sftp, "/home/tester/target.txt", b"symlink-payload\n", None).await;
    sftp.mkdir("/home/tester/chmod-tree").await.expect("tree dir");
    sftp.mkdir("/home/tester/chmod-tree/nested").await.expect("nested dir");
    seed_remote(&sftp, "/home/tester/chmod-tree/nested/script.sh", b"#!/bin/sh\necho hi\n", None)
        .await;
    sftp.chmod("/home/tester/chmod-tree/nested/script.sh", 0o600).await.unwrap();

    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());
    adopt(&mut interp, Arc::clone(&sftp), tmp.path());

    let (ok, out) = run_line_captured(
        &mut interp,
        "ln /home/tester/target.txt /home/tester/link1.txt ; symlink /home/tester/target.txt /home/tester/link2.txt ; chmod u+x,go+r /home/tester/chmod-tree/nested/script.sh ; chmod -r 750 /home/tester/chmod-tree ; exit",
    )
    .await;
    assert!(ok, "the ln/chmod script runs: {out}");

    let listing = sftp.list_dir("/home/tester").await.unwrap();
    for name in ["link1.txt", "link2.txt"] {
        let link = listing
            .iter()
            .find(|entry| entry.name == name)
            .unwrap_or_else(|| panic!("{name} is in the listing"));
        assert!(link.is_symlink, "{name} is a symlink");
    }
    let read1 = sftp.readlink("/home/tester/link1.txt").await.expect("readlink works");
    assert!(read1.ends_with("/target.txt"), "link1 points at the target: {read1}");
    let read2 = sftp.readlink("/home/tester/link2.txt").await.expect("readlink works");
    assert!(read2.ends_with("/target.txt"), "link2 points at the target: {read2}");

    let mode_of = |e: &linscp_types::FileEntry| mode_from_permissions_str(&e.permissions);
    let tree = sftp.stat("/home/tester/chmod-tree").await.unwrap().expect("tree stat");
    assert_eq!(mode_of(&tree) & 0o777, 0o750, "the tree root is 750");
    let nested = sftp.stat("/home/tester/chmod-tree/nested").await.unwrap().expect("nested stat");
    assert_eq!(mode_of(&nested) & 0o777, 0o750, "the nested directory is 750");
    let script = sftp.stat("/home/tester/chmod-tree/nested/script.sh").await.unwrap().expect("script stat");
    assert_eq!(mode_of(&script) & 0o777, 0o750, "the octal recursive chmod reached the file");

    sftp.close().await.unwrap();
}

/// `-filemask=|skip/` prunes the excluded subtree in both the transfer and
/// the delete phases: the preview lists the surviving file and neither of
/// the excluded ones. The full upstream case cannot run as written in this
/// build: every unguarded SFTP upload is refused, so the real run aborts
/// naming the refusal (a change-guard, pending guarded overwrite uploads).
#[tokio::test]
async fn test_synchronize_filemask_prunes_excluded_subtrees() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let root = tmp.path();
    let local = root.join("sync-exclusion");
    fs::create_dir_all(local.join("skip")).unwrap();
    let keep = b"included by synchronization\n";
    let excluded = b"excluded source\n";
    fs::write(local.join("keep.txt"), keep).unwrap();
    fs::write(local.join("skip").join("new.txt"), excluded).unwrap();

    let (sftp, _fp) = connect_mock(0x55, 0x56).await;
    sftp.mkdir("/home/tester/sync-exclusion").await.expect("remote root");
    sftp.mkdir("/home/tester/sync-exclusion/skip").await.expect("remote skip dir");
    seed_remote(&sftp, "/home/tester/sync-exclusion/skip/old.txt", b"must survive -delete\n", None)
        .await;

    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());
    adopt(&mut interp, Arc::clone(&sftp), tmp.path());

    let (ok, preview) = run_line_captured(
        &mut interp,
        "synchronize remote -filemask=|skip/ -delete -preview ./sync-exclusion /home/tester/sync-exclusion",
    )
    .await;
    assert!(ok, "the preview runs: {preview}");
    assert!(preview.contains("keep.txt"), "the preview lists the surviving file: {preview}");
    assert!(!preview.contains("new.txt"), "the preview prunes the excluded source: {preview}");
    assert!(!preview.contains("old.txt"), "the excluded remote delete is not planned: {preview}");

    // The run aborts at the unguarded SFTP upload naming the refusal; the
    // excluded subtree is untouched either way.
    let (ok, out) = run_script(
        &mut interp,
        "option confirm off ; synchronize remote -filemask=|skip/ -delete ./sync-exclusion /home/tester/sync-exclusion ; exit",
    )
    .await;
    assert!(!ok, "the sync aborts naming the refused upload: {out}");
    assert!(
        out.contains("Unguarded SFTP/FTP uploads are disabled"),
        "the refusal names itself: {out}"
    );
    let old = sftp.stat("/home/tester/sync-exclusion/skip/old.txt").await.unwrap();
    assert!(old.is_some(), "the excluded remote file survives");
    let new_remote = sftp.stat("/home/tester/sync-exclusion/skip/new.txt").await.unwrap();
    assert!(new_remote.is_none(), "the excluded source was never uploaded");
    let keep_remote = sftp.stat("/home/tester/sync-exclusion/keep.txt").await.unwrap();
    assert!(keep_remote.is_none(), "the refused upload never landed");

    sftp.close().await.unwrap();
}

/// A remote file whose contents changed without its size or its timestamp
/// changing is invisible to `-criteria=time` and visible to
/// `-criteria=checksum`: the preview says which comparison found it, the run
/// with `-criteria=time,size,checksum` brings the local copy back in line,
/// and afterwards the checksum preview has nothing left to do.
#[tokio::test]
async fn test_synchronize_by_checksum_sees_what_the_timestamp_hides() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let hidden = tmp.path().join("hidden");
    fs::create_dir_all(&hidden).unwrap();

    let payload = vec![0xABu8; 8 << 10];
    let stamp = 1_700_000_000i64;

    let (sftp, _fp) = connect_mock(0x57, 0x58).await;
    sftp.mkdir("/home/tester/hidden").await.expect("remote hidden dir");
    seed_remote(&sftp, "/home/tester/hidden/data.bin", &payload, Some(stamp)).await;

    let local_copy = hidden.join("data.bin");
    fs::write(&local_copy, &payload).unwrap();
    // Same size and same timestamp, different leading bytes: exactly what a
    // time or size comparison cannot see.
    fs::write(&local_copy, {
        let mut divergent = payload.clone();
        for byte in divergent.iter_mut().take(32) {
            *byte = 0;
        }
        divergent
    })
    .unwrap();
    filetime::set_file_mtime(&local_copy, FileTime::from_unix_time(stamp, 0)).unwrap();

    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());
    adopt(&mut interp, Arc::clone(&sftp), tmp.path());

    let (ok, out) = run_line_captured(
        &mut interp,
        "synchronize local -criteria=time -preview ./hidden /home/tester/hidden",
    )
    .await;
    assert!(ok, "the preview runs: {out}");
    assert!(out.contains("criteria=time"), "the preview names the criteria: {out}");
    assert!(!out.contains("download\tdata.bin"), "time criteria sees nothing: {out}");

    let (ok, out) = run_line_captured(
        &mut interp,
        "synchronize local -criteria=checksum -preview ./hidden /home/tester/hidden",
    )
    .await;
    assert!(ok, "the preview runs: {out}");
    assert!(out.contains("criteria=checksum"), "the preview names the criteria: {out}");
    assert!(out.contains("download\tdata.bin"), "the checksum sees the file: {out}");
    assert!(out.contains("contents differ"), "the preview says why: {out}");

    let (ok, out) = run_line_captured(
        &mut interp,
        "synchronize local -criteria=time,size,checksum ./hidden /home/tester/hidden",
    )
    .await;
    assert!(ok, "the real run converges: {out}");
    assert_eq!(fs::read(&local_copy).unwrap(), payload, "the local copy is whole again");

    let (ok, out) = run_line_captured(
        &mut interp,
        "synchronize local -criteria=checksum -preview ./hidden /home/tester/hidden",
    )
    .await;
    assert!(ok, "the preview runs: {out}");
    assert!(!out.contains("download\tdata.bin"), "nothing is left to download: {out}");

    sftp.close().await.unwrap();
}

/// `synchronize both` records its state under `<config_dir>/sync/`, refuses a
/// conflicted pair in the default policy (skip) and applies `-conflict=newer`
/// resolving in favour of the newer side. The `keepuptodate` half of the
/// upstream case is deliberately not ported: local-to-remote uploads are
/// refused by the guarded-upload rules in this build, so the case cannot run
/// as written here. See `test_keepuptodate_reports_the_unguarded_sftp_upload_by_name`.
#[tokio::test]
async fn test_synchronize_conflict_policy() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let local = tmp.path().join("local");
    fs::create_dir_all(&local).unwrap();

    let stamp = |path: &Path, secs: i64| {
        filetime::set_file_mtime(path, FileTime::from_unix_time(secs, 0)).unwrap();
    };

    let (sftp, _fp) = connect_mock(0x5b, 0x5c).await;
    sftp.mkdir("/home/tester/sync-both").await.expect("sync root");
    seed_remote(&sftp, "/home/tester/sync-both/doc.txt", b"v1\n", Some(1_700_000_000)).await;
    let local_doc = local.join("doc.txt");
    fs::write(&local_doc, b"v1\n").unwrap();
    stamp(&local_doc, 1_700_000_000);

    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());
    adopt(&mut interp, Arc::clone(&sftp), tmp.path());

    // Baseline bidirectional sync records the state file.
    let (baseline_ok, baseline) = run_script(
        &mut interp,
        "synchronize both ./local /home/tester/sync-both",
    )
    .await;
    assert!(baseline_ok, "the baseline runs: {baseline}");
    assert!(!baseline.to_lowercase().contains("conflict"), "the baseline is clean: {baseline}");

    // Diverge both sides: different bytes, sizes and mtimes.
    fs::write(&local_doc, b"local-v2\n").unwrap();
    stamp(&local_doc, 1_700_000_100);
    seed_remote(&sftp, "/home/tester/sync-both/doc.txt", b"remote-v2-longer\n", Some(1_700_000_200)).await;

    // The default policy (skip) reports the conflict and the script fails.
    let (conflict_ok, conflict) = run_script(
        &mut interp,
        "synchronize both ./local /home/tester/sync-both",
    )
    .await;
    assert!(!conflict_ok, "the conflicted pair aborts the script: {conflict}");
    assert!(conflict.to_lowercase().contains("conflict"), "the conflict is reported: {conflict}");
    let after = download_bytes(&*sftp, "/home/tester/sync-both/doc.txt", TransferRequest::default())
        .await
        .unwrap();
    assert_eq!(after, b"remote-v2-longer\n", "the remote file was left unchanged");
    assert_eq!(fs::read(&local_doc).unwrap(), b"local-v2\n", "the local file was left unchanged");

    // -conflict=newer resolves in favour of the newer remote side.
    let (resolved_ok, resolved) = run_script(
        &mut interp,
        "synchronize both -conflict=newer ./local /home/tester/sync-both",
    )
    .await;
    assert!(resolved_ok, "the newer-side resolution applies: {resolved}");
    assert_eq!(fs::read(&local_doc).unwrap(), b"remote-v2-longer\n", "the newer remote side won");

    sftp.close().await.unwrap();
}

/// keepuptodate cannot currently run as the upstream case requires: the build
/// refuses every unguarded SFTP upload, so the command fails closed naming
/// the refusal instead of mirroring the watch directory. This pins the
/// refusal by name as a change-guard; the port of the full upstream case
/// lands when guarded overwrite uploads over native SFTP exist.
#[tokio::test]
async fn test_keepuptodate_reports_the_unguarded_sftp_upload_by_name() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let watch = tmp.path().join("watch");
    fs::create_dir_all(&watch).unwrap();
    fs::write(watch.join("fresh.txt"), b"watched\n").unwrap();

    let (sftp, _fp) = connect_mock(0x5f, 0x60).await;
    sftp.mkdir("/home/tester/keepuptodate").await.expect("watch root");
    seed_remote(&sftp, "/home/tester/keepuptodate/stale.txt", b"remove-me\n", None).await;

    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());
    adopt(&mut interp, Arc::clone(&sftp), tmp.path());

    let (ok, out) = run_script(
        &mut interp,
        "option confirm off ; keepuptodate -count=1 -delete ./watch /home/tester/keepuptodate ; exit",
    )
    .await;
    assert!(!ok, "keepuptodate refuses the unguarded SFTP upload: {out}");
    assert!(
        out.contains("Unguarded SFTP/FTP uploads are disabled"),
        "the refusal names itself: {out}"
    );
    let stale = sftp.stat("/home/tester/keepuptodate/stale.txt").await.unwrap();
    assert!(stale.is_some(), "the refusal aborts before any delete");
    let fresh = sftp.stat("/home/tester/keepuptodate/fresh.txt").await.unwrap();
    assert!(fresh.is_none(), "the refused upload never landed");

    sftp.close().await.unwrap();
}

/// `etag <path> -get` on a protocol with no entity tags says so by name and
/// succeeds; `-match`, `-nomatch` and `-clear` are refused by name and
/// record nothing, so a later upload is not gated on a version that will
/// never come.
#[tokio::test]
async fn test_etag_names_a_protocol_that_has_no_etags() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let (sftp, _fp) = connect_mock(0x5d, 0x5e).await;
    seed_remote(&sftp, "/home/tester/config.ini", b"[global]\n", None).await;

    let mut interp = ScriptInterpreter::new(test_config(tmp.path()), in_memory_logger());
    adopt(&mut interp, Arc::clone(&sftp), tmp.path());

    let (asked_ok, asked) = run_script(&mut interp, "etag /config.ini -get ; echo ASKED").await;
    assert!(asked_ok, "the -get action succeeds: {asked}");
    assert!(asked.contains("ETag not available"), "the answer names the protocol: {asked}");
    assert!(asked.contains("ASKED"), "the script kept running: {asked}");

    for switch in ["-match=\"abc\"", "-nomatch=abc", "-clear"] {
        let (refused_ok, refused) = run_script(
            &mut interp,
            &format!("etag /config.ini {switch} ; echo SHOULD_NOT_RUN"),
        )
        .await;
        assert!(!refused_ok, "{switch} stops the script: {refused}");
        assert!(refused.contains("ETag not available"), "{switch} is refused by name: {refused}");
        assert!(!refused.contains("SHOULD_NOT_RUN"), "{switch} stopped the script: {refused}");
    }

    // Nothing was recorded on the way, so a plain remote copy of the path
    // succeeds exactly as it would have before the refusals: no precondition
    // is waiting for a version that will never come. (The upstream case's
    // trailing 'put' is not ported: unguarded SFTP uploads are refused in
    // this build, by design.)
    let (cp_ok, cp_out) = run_line_captured(&mut interp, "cp /home/tester/config.ini /home/tester/config-copy.ini").await;
    assert!(cp_ok, "the copy after the refusals runs: {cp_out}");
    let copied = download_bytes(&*sftp, "/home/tester/config-copy.ini", TransferRequest::default())
        .await
        .unwrap();
    assert_eq!(copied, b"[global]\n");

    sftp.close().await.unwrap();
}
