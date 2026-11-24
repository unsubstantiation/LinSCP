//! End-to-end ETag-conditional text upload through the engine and WebDAV.
use std::sync::{Arc, Mutex};

use axum::{body::Bytes, extract::State, http::{HeaderMap, StatusCode}, routing::put, Router};
use linscp_engine::{text_mode::EolStyle, transfer::{upload_single_file, TransferFlags}, xml_log::SessionLogger};
use linscp_proto::{webdav::{WebDavConnectConfig, WebDavSession}, RemoteSession};
use linscp_types::{ProtocolScheme, TransferMode};

#[derive(Default)]
struct Resource {
    body: Vec<u8>,
    requests: usize,
}

async fn conditional_put(State(state): State<Arc<Mutex<Resource>>>, headers: HeaderMap, body: Bytes) -> StatusCode {
    let mut resource = state.lock().unwrap();
    resource.requests += 1;
    // The fixture changes its version after the first successful write.
    let expected = if resource.requests == 1 { "\"v1\"" } else { "\"v2\"" };
    if headers.get("if-match").and_then(|v| v.to_str().ok()) != Some(expected) {
        return StatusCode::PRECONDITION_FAILED;
    }
    resource.body = body.to_vec();
    StatusCode::NO_CONTENT
}

#[tokio::test]
async fn conditional_ascii_upload_converts_before_applying_etag() {
    let state = Arc::new(Mutex::new(Resource::default()));
    let app = Router::new().route("/dav/file.txt", put(conditional_put)).with_state(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let session = WebDavSession::connect(WebDavConnectConfig {
        scheme: ProtocolScheme::Dav, host: "127.0.0.1".into(), port,
        base_path: "/dav".into(), ..Default::default()
    }, None, 0).await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("file.txt");
    std::fs::write(&source, b"one\ntwo\r\nthree\r").unwrap();
    let mut log = SessionLogger::open(None, 0, false, None, None, false, "test").unwrap();
    let mut flags = TransferFlags {
        transfer_mode: TransferMode::Ascii, overwrite_etag: Some("\"v1\"".into()),
        preserve_time: false, ..Default::default()
    };
    upload_single_file(&session, &source, "file.txt", &flags, &mut log, None).await.unwrap();
    assert_eq!(state.lock().unwrap().body, b"one\r\ntwo\r\nthree\r\n");

    // Stale ETags must leave the remote file and the local source unchanged.
    std::fs::write(&source, b"replacement\n").unwrap();
    flags.delete_source = true;
    assert!(upload_single_file(&session, &source, "file.txt", &flags, &mut log, None).await.is_err());
    assert_eq!(state.lock().unwrap().body, b"one\r\ntwo\r\nthree\r\n");
    assert!(source.exists());

    flags.delete_source = false;
    flags.overwrite_etag = Some("\"v2\"".into());
    flags.eol_override = Some(EolStyle::Lf);
    upload_single_file(&session, &source, "file.txt", &flags, &mut log, None).await.unwrap();
    assert_eq!(state.lock().unwrap().body, b"replacement\n");
    session.close().await.unwrap();
    server.abort();
}
