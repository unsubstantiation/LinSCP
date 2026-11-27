//! Ordinary resumes must pin and compare the local prefix before appending.
use std::sync::{Arc, Mutex};
use axum::{body::Body, extract::State, http::{HeaderMap, Method, StatusCode, Uri}, response::{IntoResponse, Response}, Router};
use linscp_engine::{presets::ResumeSupportMode, transfer::{download_single_file, upload_single_file, TransferFlags}, xml_log::SessionLogger};
use linscp_proto::{s3::{S3ConnectConfig, S3Session}, webdav::{WebDavConnectConfig, WebDavSession}, RemoteSession};
use linscp_types::{FileEntry, ProtocolScheme, TransferMode};
use zeroize::Zeroizing;

struct Resource { data: Vec<u8>, etag: String, change_after_prefix: bool, wrong_version_at: Option<&'static str>, bad_etag_at: Option<(&'static str, bool)>, version_requests: Vec<String>, swap_partial: Option<std::path::PathBuf> }
async fn resource(State(state): State<Arc<Mutex<Resource>>>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let mut r = state.lock().unwrap();
    if method.as_str() == "PROPFIND" {
        let xml = format!("<D:multistatus xmlns:D=\"DAV:\"><D:response><D:href>/dav/file.bin</D:href><D:propstat><D:prop><D:resourcetype/><D:getcontentlength>{}</D:getcontentlength><D:getetag>{}</D:getetag></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>", r.data.len(), r.etag);
        return (StatusCode::MULTI_STATUS, xml).into_response();
    }
    let versioned = uri.query() == Some("versionId=ver-1");
    if versioned { r.version_requests.push(format!("{} {}", method, headers.get("range").and_then(|v| v.to_str().ok()).unwrap_or(""))); }
    if method == Method::HEAD {
        let mut response = Response::builder().status(StatusCode::OK).header("etag", &r.etag).header("content-length", r.data.len());
        if versioned { response = response.header("x-amz-version-id", if r.wrong_version_at == Some("head") { "other" } else { "ver-1" }); }
        return response.body(Body::empty()).unwrap();
    }
    if method == Method::GET {
        if headers.get("if-match").and_then(|x| x.to_str().ok()) != Some(r.etag.as_str()) { return StatusCode::PRECONDITION_FAILED.into_response(); }
        if headers.get("range").is_none() {
            let mut response = Response::builder().status(StatusCode::OK);
            if let Some(("full", omit)) = r.bad_etag_at {
                if !omit { response = response.header("etag", "\"other\""); }
            } else { response = response.header("etag", &r.etag); }
            if versioned { response = response.header("x-amz-version-id", if r.wrong_version_at == Some("tail") { "other" } else { "ver-1" }); }
            return response.body(Body::from(r.data.clone())).unwrap();
        }
        let range = headers.get("range").unwrap().to_str().unwrap().strip_prefix("bytes=").unwrap();
        let (start, end) = range.split_once('-').unwrap();
        let start: usize = start.parse().unwrap();
        let end: usize = if end.is_empty() { r.data.len() - 1 } else { end.parse().unwrap() };
        let content_range = format!("bytes {}-{}/{}", start, end, r.data.len());
        let etag = r.etag.clone();
        let data = r.data[start..=end].to_vec();
        if start == 0 && r.change_after_prefix { r.etag = "\"v2\"".into(); }
        if start == 0 {
            if let Some(path) = r.swap_partial.take() {
                std::fs::remove_file(&path).unwrap();
                std::fs::write(path, b"xxxxx").unwrap();
            }
        }
        let phase = if start == 0 { "prefix" } else { "tail" };
        let mut response = Response::builder().status(StatusCode::PARTIAL_CONTENT).header("content-range", content_range);
        if let Some((fault_phase, omit)) = r.bad_etag_at.filter(|(fault_phase, _)| *fault_phase == phase) {
            let _ = fault_phase;
            if !omit { response = response.header("etag", "\"other\""); }
        } else { response = response.header("etag", etag); }
        if versioned {
            response = response.header("x-amz-version-id", if r.wrong_version_at == Some(phase) { "other" } else { "ver-1" });
        }
        return response.body(Body::from(data)).unwrap();
    }
    StatusCode::METHOD_NOT_ALLOWED.into_response()
}

async fn exercise(session: &dyn RemoteSession, path: &str, state: Arc<Mutex<Resource>>) {
    state.lock().unwrap().etag = "\"v1\"".into();
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("file.bin");
    let stage = tmp.path().join("file.bin.filepart");
    let entry = FileEntry { name: "file.bin".into(), size: 10, is_dir: false, is_symlink: false, broken_link: false, date: String::new(), mtime: 0, permissions: String::new(), owner: None, group: None };
    let flags = TransferFlags { resume: true, resume_support: ResumeSupportMode::On, preserve_time: false, ..Default::default() };
    let mut logger = SessionLogger::open(None, 0, false, None, None, false, "test").unwrap();
    std::fs::write(&dest, b"old").unwrap();
    std::fs::write(&stage, b"wrong").unwrap();
    assert!(download_single_file(session, path, Some(&entry), &dest, &flags, &mut logger, None).await.is_err());
    assert_eq!(std::fs::read(&stage).unwrap(), b"wrong");
    assert_eq!(std::fs::read(&dest).unwrap(), b"old");
    std::fs::write(&stage, b"01234").unwrap();
    state.lock().unwrap().etag = "W/\"v1\"".into();
    assert!(download_single_file(session, path, Some(&entry), &dest, &flags, &mut logger, None).await.is_err());
    assert_eq!(std::fs::read(&stage).unwrap(), b"01234");
    state.lock().unwrap().etag = "\"v1\"".into();
    state.lock().unwrap().change_after_prefix = true;
    assert!(download_single_file(session, path, Some(&entry), &dest, &flags, &mut logger, None).await.is_err());
    assert_eq!(std::fs::read(&stage).unwrap(), b"01234");
    assert_eq!(std::fs::read(&dest).unwrap(), b"old");
    state.lock().unwrap().change_after_prefix = false;
    // Replace the name after its prefix is read. On Unix the transfer must
    // write through the verified handle and must not publish the substitute.
    #[cfg(unix)]
    {
        state.lock().unwrap().swap_partial = Some(stage.clone());
        let error = download_single_file(session, path, Some(&entry), &dest, &flags, &mut logger, None).await.unwrap_err();
        assert!(error.contains("pathname changed"), "{error}");
        assert_eq!(std::fs::read(&stage).unwrap(), b"xxxxx");
        assert_eq!(std::fs::read(&dest).unwrap(), b"old");
        std::fs::write(&stage, b"01234").unwrap();
    }
    download_single_file(session, path, Some(&entry), &dest, &flags, &mut logger, None).await.unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"0123456789");
    // With staging disabled, the destination itself is the partial.
    std::fs::write(&dest, b"xxxxx").unwrap();
    let direct = TransferFlags { resume_support: ResumeSupportMode::Off, ..flags };
    assert!(download_single_file(session, path, Some(&entry), &dest, &direct, &mut logger, None).await.is_err());
    assert_eq!(std::fs::read(&dest).unwrap(), b"xxxxx");
    for contents in [b"0123456789".as_slice(), b"0123456789extra".as_slice()] {
        std::fs::write(&dest, contents).unwrap();
        assert!(download_single_file(session, path, Some(&entry), &dest, &direct, &mut logger, None).await.is_err());
        assert_eq!(std::fs::read(&dest).unwrap(), contents);
    }
    for mode in [TransferMode::Ascii, TransferMode::Automatic] {
        let text_flags = TransferFlags { transfer_mode: mode, ..direct.clone() };
        let err = download_single_file(session, "file.txt", Some(&entry), &dest, &text_flags, &mut logger, None).await.unwrap_err();
        assert!(err.contains("binary transfer mode"), "{err}");
        let source = tmp.path().join("file.txt");
        std::fs::write(&source, b"local text").unwrap();
        let err = upload_single_file(session, &source, "file.txt", &text_flags, &mut logger, None).await.unwrap_err();
        assert!(err.contains("binary transfer mode"), "{err}");
        assert_eq!(std::fs::read(&dest).unwrap(), b"0123456789extra");
    }
    let err = download_single_file(session, path, Some(&entry), std::path::Path::new("-"), &direct, &mut logger, None).await.unwrap_err();
    assert!(err.contains("standard output"), "{err}");
}

#[tokio::test]
async fn webdav_and_s3_ordinary_resume_pin_and_compare() {
    let state = Arc::new(Mutex::new(Resource { data: b"0123456789".to_vec(), etag: "\"v1\"".into(), change_after_prefix: false, wrong_version_at: None, bad_etag_at: None, version_requests: Vec::new(), swap_partial: None }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new().fallback(resource).with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let dav = WebDavSession::connect(WebDavConnectConfig { scheme: ProtocolScheme::Dav, host: "127.0.0.1".into(), port, base_path: "/dav".into(), ..Default::default() }, None, 0).await.unwrap();
    exercise(&dav, "file.bin", state.clone()).await;
    let s3 = S3Session::connect(S3ConnectConfig { use_https: false, host: "127.0.0.1".into(), port, region: Some("us-east-1".into()), access_key_id: "key".into(), secret_access_key: Zeroizing::new("secret".into()), path_style: true, ..Default::default() }, None, 0).await.unwrap();
    exercise(&s3, "/bucket/file.bin", state).await;
    server.abort();
}

#[tokio::test]
async fn s3_versioned_resume_pins_version_and_preserves_partials_on_failure() {
    use linscp_engine::transfer::local_stage_path;
    let state = Arc::new(Mutex::new(Resource { data: b"0123456789".to_vec(), etag: "\"v1\"".into(), change_after_prefix: false, wrong_version_at: None, bad_etag_at: None, version_requests: Vec::new(), swap_partial: None }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new().fallback(resource).with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let s3 = S3Session::connect(S3ConnectConfig { use_https: false, host: "127.0.0.1".into(), port, region: Some("us-east-1".into()), access_key_id: "key".into(), secret_access_key: Zeroizing::new("secret".into()), path_style: true, ..Default::default() }, None, 0).await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let dest = temp.path().join("file.bin");
    let stage = local_stage_path(&dest, Some("ver-1")).unwrap();
    let entry = FileEntry { name: "file.bin".into(), size: 10, is_dir: false, is_symlink: false, broken_link: false, date: String::new(), mtime: 0, permissions: String::new(), owner: None, group: None };
    let flags = TransferFlags { resume: true, version_id: Some("ver-1".into()), resume_support: ResumeSupportMode::On, preserve_time: false, ..Default::default() };
    let mut log = SessionLogger::open(None, 0, false, None, None, false, "test").unwrap();
    std::fs::write(&dest, b"old").unwrap();
    std::fs::write(&stage, b"wrong").unwrap();
    assert!(download_single_file(&s3, "/bucket/file.bin", Some(&entry), &dest, &flags, &mut log, None).await.is_err());
    assert_eq!(std::fs::read(&stage).unwrap(), b"wrong");
    std::fs::write(&stage, b"01234").unwrap();
    for phase in ["head", "prefix", "tail"] {
        state.lock().unwrap().wrong_version_at = Some(phase);
        assert!(download_single_file(&s3, "/bucket/file.bin", Some(&entry), &dest, &flags, &mut log, None).await.is_err(), "{phase}");
        assert_eq!(std::fs::read(&stage).unwrap(), b"01234");
        assert_eq!(std::fs::read(&dest).unwrap(), b"old");
    }
    state.lock().unwrap().wrong_version_at = None;
    state.lock().unwrap().version_requests.clear();
    download_single_file(&s3, "/bucket/file.bin", Some(&entry), &dest, &flags, &mut log, None).await.unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"0123456789");
    assert_eq!(state.lock().unwrap().version_requests, ["HEAD ", "GET bytes=0-4", "GET bytes=5-"]);
    let deleting = TransferFlags { delete_source: true, ..flags };
    let error = download_single_file(&s3, "/bucket/file.bin", Some(&entry), &dest, &deleting, &mut log, None).await.unwrap_err();
    assert!(error.contains("conditional version delete"), "{error}");
    server.abort();
}

#[tokio::test]
async fn s3_version_verified_resume_uses_version_scoped_checkpoint() {
    use linscp_engine::transfer::{download_verified_resume, local_stage_path};
    let state = Arc::new(Mutex::new(Resource { data: b"0123456789".to_vec(), etag: "\"v1\"".into(), change_after_prefix: false, wrong_version_at: None, bad_etag_at: None, version_requests: Vec::new(), swap_partial: None }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new().fallback(resource).with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let s3 = S3Session::connect(S3ConnectConfig { use_https: false, host: "127.0.0.1".into(), port, region: Some("us-east-1".into()), access_key_id: "key".into(), secret_access_key: Zeroizing::new("secret".into()), path_style: true, ..Default::default() }, None, 0).await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let dest = temp.path().join("version.bin");
    let partial = local_stage_path(&dest, Some("ver-1")).unwrap();
    let unrelated = local_stage_path(&dest, Some("other")).unwrap();
    let entry = FileEntry { name: "version.bin".into(), size: 10, is_dir: false, is_symlink: false, broken_link: false, date: String::new(), mtime: 0, permissions: String::new(), owner: None, group: None };
    let flags = TransferFlags { resume: true, no_clobber: true, version_id: Some("ver-1".into()), source_etag: Some("\"v1\"".into()), preserve_time: false, ..Default::default() };
    let mut log = SessionLogger::open(None, 0, false, None, None, false, "test").unwrap();
    std::fs::write(&partial, b"wrong").unwrap();
    std::fs::write(&unrelated, b"unrelated").unwrap();
    assert!(download_verified_resume(&s3, "/bucket/file.bin", &entry, &dest, &flags, &mut log, None).await.is_err());
    assert_eq!(std::fs::read(&partial).unwrap(), b"wrong");
    assert!(!dest.exists());
    std::fs::write(&partial, b"01234").unwrap();
    state.lock().unwrap().wrong_version_at = Some("tail");
    assert!(download_verified_resume(&s3, "/bucket/file.bin", &entry, &dest, &flags, &mut log, None).await.is_err());
    assert_eq!(std::fs::read(&partial).unwrap(), b"01234");
    assert!(!dest.exists());
    state.lock().unwrap().wrong_version_at = None;
    download_verified_resume(&s3, "/bucket/file.bin", &entry, &dest, &flags, &mut log, None).await.unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"0123456789");
    assert_eq!(std::fs::read(&partial).unwrap(), b"01234");
    assert_eq!(std::fs::read(&unrelated).unwrap(), b"unrelated");
    assert!(download_verified_resume(&s3, "/bucket/file.bin", &entry, &dest, &flags, &mut log, None).await.is_err());
    assert_eq!(std::fs::read(&dest).unwrap(), b"0123456789");
    server.abort();
}

#[tokio::test]
async fn conditional_s3_download_obeys_speed_limit_for_first_chunk_and_resume() {
    use linscp_proto::TransferRequest;
    use std::time::{Duration, Instant};
    let payload = vec![42u8; 16 * 1024];
    let state = Arc::new(Mutex::new(Resource { data: payload.clone(), etag: "\"v1\"".into(), change_after_prefix: false, wrong_version_at: None, bad_etag_at: None, version_requests: Vec::new(), swap_partial: None }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new().fallback(resource).with_state(state);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let s3 = S3Session::connect(S3ConnectConfig { use_https: false, host: "127.0.0.1".into(), port, region: Some("us-east-1".into()), access_key_id: "key".into(), secret_access_key: Zeroizing::new("secret".into()), path_style: true, ..Default::default() }, None, 0).await.unwrap();
    // A complete response may arrive as just one chunk, which previously
    // escaped limiting entirely. Also cover a version-pinned range request.
    for (offset, version, minimum) in [(0, None, 220), (4096, Some("ver-1"), 165)] {
        let mut output = Vec::new();
        let request = TransferRequest { resume_offset: offset, speed_kbytes_per_sec: 64, version_id: version.map(str::to_string), ..Default::default() };
        let start = Instant::now();
        let count = s3.download_if_match("/bucket/file.bin", "\"v1\"", request, &mut output, None).await.unwrap();
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(minimum), "conditional transfer ignored speed limit: {elapsed:?}");
        assert_eq!(count as usize, payload.len() - offset as usize);
        assert_eq!(output, payload[offset as usize..]);
    }
    server.abort();
}

#[tokio::test]
async fn http_resume_prefix_verification_obeys_speed_limit() {
    use std::time::{Duration, Instant};
    let payload = vec![71u8; 16 * 1024];
    let state = Arc::new(Mutex::new(Resource { data: payload.clone(), etag: "\"v1\"".into(), change_after_prefix: false, wrong_version_at: None, bad_etag_at: None, version_requests: Vec::new(), swap_partial: None }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new().fallback(resource).with_state(state);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let dav = WebDavSession::connect(WebDavConnectConfig { scheme: ProtocolScheme::Dav, host: "127.0.0.1".into(), port, base_path: "/dav".into(), ..Default::default() }, None, 0).await.unwrap();
    let s3 = S3Session::connect(S3ConnectConfig { use_https: false, host: "127.0.0.1".into(), port, region: Some("us-east-1".into()), access_key_id: "key".into(), secret_access_key: Zeroizing::new("secret".into()), path_style: true, ..Default::default() }, None, 0).await.unwrap();
    for (session, path, version) in [(&dav as &dyn RemoteSession, "file.bin", None), (&s3 as &dyn RemoteSession, "/bucket/file.bin", Some("ver-1"))] {
        let mut prefix = payload.as_slice();
        let start = Instant::now();
        session.verify_prefix_if_match(path, "\"v1\"", payload.len() as u64, payload.len() as u64, &mut prefix, version, 64).await.unwrap();
        assert!(start.elapsed() >= Duration::from_millis(220), "prefix verification ignored speed limit");
        assert!(prefix.is_empty());
    }
    server.abort();
}

#[tokio::test]
async fn webdav_conditional_downloads_reject_unconfirmed_response_etags() {
    use linscp_engine::transfer::download_verified_resume;
    use linscp_proto::TransferRequest;
    let state = Arc::new(Mutex::new(Resource { data: b"0123456789".to_vec(), etag: "\"v1\"".into(), change_after_prefix: false, wrong_version_at: None, bad_etag_at: None, version_requests: Vec::new(), swap_partial: None }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new().fallback(resource).with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let dav = WebDavSession::connect(WebDavConnectConfig { scheme: ProtocolScheme::Dav, host: "127.0.0.1".into(), port, base_path: "/dav".into(), ..Default::default() }, None, 0).await.unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("file.bin");
    let stage = tmp.path().join("file.bin.filepart");
    let entry = FileEntry { name: "file.bin".into(), size: 10, is_dir: false, is_symlink: false, broken_link: false, date: String::new(), mtime: 0, permissions: String::new(), owner: None, group: None };
    let flags = TransferFlags { resume: true, resume_support: ResumeSupportMode::On, preserve_time: false, ..Default::default() };
    let verified = TransferFlags { no_clobber: true, source_etag: Some("\"v1\"".into()), ..flags.clone() };
    let mut logger = SessionLogger::open(None, 0, false, None, None, false, "test").unwrap();
    std::fs::write(&stage, b"01234").unwrap();
    for phase in ["prefix", "tail"] {
        for omit in [true, false] {
            state.lock().unwrap().bad_etag_at = Some((phase, omit));
            let err = download_single_file(&dav, "file.bin", Some(&entry), &dest, &flags, &mut logger, None).await.unwrap_err();
            assert!(err.contains("ETag"), "{phase} {omit}: {err}");
            assert_eq!(std::fs::read(&stage).unwrap(), b"01234");
            assert!(!dest.exists());
            let err = download_verified_resume(&dav, "file.bin", &entry, &dest, &verified, &mut logger, None).await.unwrap_err();
            assert!(err.contains("ETag"), "{phase} {omit}: {err}");
            assert_eq!(std::fs::read(&stage).unwrap(), b"01234");
            assert!(!dest.exists());
        }
    }
    for omit in [true, false] {
        state.lock().unwrap().bad_etag_at = Some(("full", omit));
        let mut output = Vec::new();
        let err = dav.download_if_match("file.bin", "\"v1\"", TransferRequest::default(), &mut output, None).await.unwrap_err();
        assert!(err.to_string().contains("ETag"));
        assert!(output.is_empty(), "unconfirmed bytes must not reach the sink");
    }
    state.lock().unwrap().bad_etag_at = None;
    download_verified_resume(&dav, "file.bin", &entry, &dest, &verified, &mut logger, None).await.unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"0123456789");
    server.abort();
}
