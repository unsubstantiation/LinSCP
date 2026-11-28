//! Engine-level staged ASCII uploads over an actual loopback FTP connection.
use std::{collections::HashMap, sync::{Arc, atomic::{AtomicU64, Ordering}}};
use linscp_engine::{text_mode::EolStyle, transfer::{upload_single_file, TransferFlags}, xml_log::SessionLogger};
use linscp_proto::{ftp::{FtpConnectConfig, FtpSession}, RemoteSession};
use linscp_types::{ProtocolScheme, TransferMode};
use tokio::{io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader}, net::TcpListener, sync::Mutex};

/// Minimal FTP fixture supporting unique staging and publication. Stored paths
/// are inspected directly so the test does not depend on an FTP download path.
async fn ftp_fixture() -> (u16, Arc<Mutex<HashMap<String, Vec<u8>>>>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let files = Arc::new(Mutex::new(HashMap::from([("/dest.txt".to_string(), b"old".to_vec())])));
    let shared = Arc::clone(&files);
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut control = BufReader::new(stream);
        control.get_mut().write_all(b"220 ready\r\n").await.unwrap();
        let mut data_listener: Option<TcpListener> = None;
        let mut rename_source = String::new();
        let mut rest_offset = 0usize;
        let mut sequence = 0;
        loop {
            let mut line = String::new();
            if control.read_line(&mut line).await.unwrap() == 0 { break; }
            let line = line.trim_end_matches(['\r', '\n']);
            let (verb, arg) = line.split_once(' ').unwrap_or((line, ""));
            let response = match verb {
                "USER" => "230 logged in\r\n".to_string(),
                "FEAT" => "211-Features\r\n MLST type*;size*;\r\n211 End\r\n".to_string(),
                "TYPE" | "OPTS" => "200 OK\r\n".to_string(),
                "PWD" => "257 \"/\" current directory\r\n".to_string(),
                "EPSV" => {
                    let data = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let data_port = data.local_addr().unwrap().port();
                    data_listener = Some(data);
                    format!("229 Entering Extended Passive Mode (|||{data_port}|)\r\n")
                }
                "STOU" => {
                    sequence += 1;
                    let stage = format!("{arg}{sequence}");
                    control.get_mut().write_all(format!("150 FILE: {stage}\r\n").as_bytes()).await.unwrap();
                    let (mut data, _) = data_listener.take().unwrap().accept().await.unwrap();
                    let mut bytes = Vec::new();
                    data.read_to_end(&mut bytes).await.unwrap();
                    shared.lock().await.insert(stage, bytes);
                    "226 transfer complete\r\n".to_string()
                }
                "REST" => { rest_offset = arg.parse().unwrap(); "350 Restart position accepted\r\n".to_string() }
                "RETR" => {
                    let bytes = shared.lock().await.get(arg).cloned().unwrap();
                    control.get_mut().write_all(b"150 Opening data connection\r\n").await.unwrap();
                    let (mut data, _) = data_listener.take().unwrap().accept().await.unwrap();
                    data.write_all(&bytes[rest_offset..]).await.unwrap();
                    data.shutdown().await.unwrap();
                    rest_offset = 0;
                    "226 transfer complete\r\n".to_string()
                }
                "MLST" => {
                    let guard = shared.lock().await;
                    match guard.get(arg) {
                        Some(bytes) => format!("250-Listing\r\n type=file;size={}; {}\r\n250 End\r\n", bytes.len(), arg),
                        None => "550 Not found\r\n".to_string(),
                    }
                }
                "RNFR" => { rename_source = arg.to_owned(); "350 Ready\r\n".to_string() }
                "RNTO" => {
                    let mut guard = shared.lock().await;
                    match guard.remove(&rename_source) {
                        Some(bytes) => { guard.insert(arg.to_string(), bytes); "250 Renamed\r\n".to_string() }
                        None => "550 Not found\r\n".to_string(),
                    }
                }
                "QUIT" => { control.get_mut().write_all(b"221 Bye\r\n").await.unwrap(); break; }
                _ => "502 Unsupported\r\n".to_string(),
            };
            control.get_mut().write_all(response.as_bytes()).await.unwrap();
        }
    });
    (port, files, server)
}

#[tokio::test]
async fn staged_ftp_ascii_preserves_guards_and_reports_converted_size() {
    let (port, files, server) = ftp_fixture().await;
    let ftp = FtpSession::connect(FtpConnectConfig { scheme: ProtocolScheme::Ftp, host: "127.0.0.1".into(), port, ..Default::default() }, None, 0).await.unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source.txt");
    std::fs::write(&source, b"one\ntwo\rthree\r\n").unwrap();
    let mut logger = SessionLogger::open(None, 0, false, None, None, false, "test").unwrap();
    let mut flags = TransferFlags { transfer_mode: TransferMode::Ascii, ftp_risky_publish: true, preserve_time: false, ..Default::default() };
    let done = Arc::new(AtomicU64::new(0));
    let total = Arc::new(AtomicU64::new(0));
    let (done_cb, total_cb) = (Arc::clone(&done), Arc::clone(&total));
    let callback = move |d: u64, t: u64| { done_cb.store(d, Ordering::SeqCst); total_cb.store(t, Ordering::SeqCst); };
    upload_single_file(&ftp, &source, "/dest.txt", &flags, &mut logger, Some(&callback)).await.unwrap();
    let expected = b"one\r\ntwo\r\nthree\r\n";
    assert_eq!(files.lock().await.get("/dest.txt").unwrap(), expected);
    assert_eq!(done.load(Ordering::SeqCst), expected.len() as u64);
    assert_eq!(total.load(Ordering::SeqCst), expected.len() as u64);
    assert_eq!(std::fs::read(&source).unwrap(), b"one\ntwo\rthree\r\n");

    flags.eol_override = Some(EolStyle::Lf);
    upload_single_file(&ftp, &source, "/dest.txt", &flags, &mut logger, None).await.unwrap();
    assert_eq!(files.lock().await.get("/dest.txt").unwrap(), b"one\ntwo\nthree\n");
    flags.no_clobber = true;
    assert!(upload_single_file(&ftp, &source, "/dest.txt", &flags, &mut logger, None).await.is_err());
    assert_eq!(files.lock().await.get("/dest.txt").unwrap(), b"one\ntwo\nthree\n");
    flags.no_clobber = false;
    flags.overwrite_etag = Some("\"version\"".into());
    assert!(upload_single_file(&ftp, &source, "/dest.txt", &flags, &mut logger, None).await.is_err());
    flags.overwrite_etag = None;
    flags.append = true;
    assert!(upload_single_file(&ftp, &source, "/dest.txt", &flags, &mut logger, None).await.is_err());
    assert_eq!(files.lock().await.get("/dest.txt").unwrap(), b"one\ntwo\nthree\n");
    ftp.close().await.unwrap();
    server.await.unwrap();
}

/// A stale FTP prefix is rejected without touching either local path. The
/// complete RETR is drained after a mismatch, so the session remains usable.
#[tokio::test]
async fn ordinary_ftp_resume_checks_prefix_and_keeps_control_connection_usable() {
    use linscp_engine::presets::ResumeSupportMode;
    use linscp_engine::transfer::download_single_file;

    let (port, files, server) = ftp_fixture().await;
    let ftp = FtpSession::connect(FtpConnectConfig { scheme: ProtocolScheme::Ftp, host: "127.0.0.1".into(), port, ..Default::default() }, None, 0).await.unwrap();
    let payload: Vec<u8> = (0..(1024 * 1024 + 17)).map(|i| (i % 251) as u8).collect();
    files.lock().await.insert("/dest.txt".into(), payload.clone());
    let tmp = tempfile::tempdir().unwrap();
    let destination = tmp.path().join("download.bin");
    let stage = tmp.path().join("download.bin.filepart");
    std::fs::write(&destination, b"old destination").unwrap();
    std::fs::write(&stage, b"wrong prefix").unwrap();
    let mut flags = TransferFlags { resume: true, resume_support: ResumeSupportMode::On, preserve_time: false, ..Default::default() };
    let mut logger = SessionLogger::open(None, 0, false, None, None, false, "test").unwrap();
    let refused = download_single_file(&ftp, "/dest.txt", None, &destination, &flags, &mut logger, None).await.unwrap_err();
    assert!(refused.contains("explicit best-effort"), "{refused}");
    assert_eq!(std::fs::read(&stage).unwrap(), b"wrong prefix");
    assert_eq!(std::fs::read(&destination).unwrap(), b"old destination");
    flags.allow_best_effort_resume = true;
    let error = download_single_file(&ftp, "/dest.txt", None, &destination, &flags, &mut logger, None).await.unwrap_err();
    assert!(error.contains("do not match"), "{error}");
    assert_eq!(std::fs::read(&destination).unwrap(), b"old destination");
    assert_eq!(std::fs::read(&stage).unwrap(), b"wrong prefix");

    // The prefix spans several comparator chunks. After the mismatch above,
    // an ordinary command and a successful resumed transfer must both work.
    assert!(ftp.stat("/dest.txt").await.unwrap().is_some());
    std::fs::write(&stage, &payload[..100_000]).unwrap();
    assert!(download_single_file(&ftp, "/dest.txt", None, &destination, &flags, &mut logger, None).await.unwrap());
    assert_eq!(std::fs::read(&destination).unwrap(), payload);
    assert_eq!(std::fs::read(&stage).unwrap(), payload[..100_000]);
    ftp.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn ftp_resume_verification_rate_limits_the_full_retr() {
    use std::time::{Duration, Instant};
    let (port, files, server) = ftp_fixture().await;
    let ftp = FtpSession::connect(FtpConnectConfig { scheme: ProtocolScheme::Ftp, host: "127.0.0.1".into(), port, ..Default::default() }, None, 0).await.unwrap();
    let payload = vec![91u8; 16 * 1024];
    files.lock().await.insert("/limited.bin".into(), payload.clone());
    let info = ftp.stat("/limited.bin").await.unwrap().unwrap();
    let token = format!("\"ftp:{}:{}\"", info.size, info.mtime);
    let mut prefix = &payload[..1024];
    let start = Instant::now();
    ftp.verify_prefix_if_match("/limited.bin", &token, 1024, info.size, &mut prefix, None, 64).await.unwrap();
    assert!(start.elapsed() >= Duration::from_millis(220), "FTP verification must throttle the entire RETR");
    assert!(ftp.stat("/limited.bin").await.unwrap().is_some());
    ftp.close().await.unwrap();
    server.await.unwrap();
}
