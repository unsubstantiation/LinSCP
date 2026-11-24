//! Ordinary resumes must pin and compare the local prefix before appending.
use std::sync::{Arc, Mutex};
use axum::{body::Body, extract::State, http::{HeaderMap, Method, StatusCode}, response::{IntoResponse, Response}, Router};
use linscp_engine::{presets::ResumeSupportMode, transfer::{download_single_file, TransferFlags}, xml_log::SessionLogger};
use linscp_proto::{s3::{S3ConnectConfig, S3Session}, webdav::{WebDavConnectConfig, WebDavSession}, RemoteSession};
use linscp_types::{FileEntry, ProtocolScheme};
use zeroize::Zeroizing;

struct Resource { data: Vec<u8>, etag: String, change_after_prefix: bool }
async fn resource(State(state): State<Arc<Mutex<Resource>>>, method: Method, headers: HeaderMap) -> Response {
    let mut r = state.lock().unwrap();
    if method.as_str() == "PROPFIND" {
        let xml = format!("<D:multistatus xmlns:D=\"DAV:\"><D:response><D:href>/dav/file.bin</D:href><D:propstat><D:prop><D:resourcetype/><D:getcontentlength>{}</D:getcontentlength><D:getetag>{}</D:getetag></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>", r.data.len(), r.etag);
        return (StatusCode::MULTI_STATUS, xml).into_response();
    }
    if method == Method::HEAD {
        return (StatusCode::OK, [("etag", r.etag.clone()), ("content-length", r.data.len().to_string())]).into_response();
    }
    if method == Method::GET {
        if headers.get("if-match").and_then(|x| x.to_str().ok()) != Some(r.etag.as_str()) { return StatusCode::PRECONDITION_FAILED.into_response(); }
        let range = headers.get("range").unwrap().to_str().unwrap().strip_prefix("bytes=").unwrap();
        let (start, end) = range.split_once('-').unwrap();
        let start: usize = start.parse().unwrap();
        let end: usize = if end.is_empty() { r.data.len() - 1 } else { end.parse().unwrap() };
        let content_range = format!("bytes {}-{}/{}", start, end, r.data.len());
        let etag = r.etag.clone();
        let data = r.data[start..=end].to_vec();
        if start == 0 && r.change_after_prefix { r.etag = "\"v2\"".into(); }
        return Response::builder().status(StatusCode::PARTIAL_CONTENT).header("content-range", content_range).header("etag", etag).body(Body::from(data)).unwrap();
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
    download_single_file(session, path, Some(&entry), &dest, &flags, &mut logger, None).await.unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"0123456789");
    // With staging disabled, the destination itself is the partial.
    std::fs::write(&dest, b"xxxxx").unwrap();
    let direct = TransferFlags { resume_support: ResumeSupportMode::Off, ..flags };
    assert!(download_single_file(session, path, Some(&entry), &dest, &direct, &mut logger, None).await.is_err());
    assert_eq!(std::fs::read(&dest).unwrap(), b"xxxxx");
}

#[tokio::test]
async fn webdav_and_s3_ordinary_resume_pin_and_compare() {
    let state = Arc::new(Mutex::new(Resource { data: b"0123456789".to_vec(), etag: "\"v1\"".into(), change_after_prefix: false }));
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
