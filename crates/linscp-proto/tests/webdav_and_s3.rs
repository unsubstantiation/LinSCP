//! End-to-end HTTPS loopback integration suite for Phase 2c (`tls`, `webdav`,
//! and `s3`):
//! - Custom `rustls` `PinnedPublicKey` SPKI SHA-256 verification (accepting
//!   matching pin, rejecting wrong pin, enforcing `MinTlsVersion`/`MaxTlsVersion`)
//! - WebDAV `PROPFIND`, `MKCOL`, `PUT`, byte-range `GET`, `COPY`, `MOVE`,
//!   `LOCK`/`UNLOCK`, `PROPPATCH`/`PROPFIND` dead properties, and RFC 4918 `If`
//!   lock-token & ETag preconditions
//! - AWS SigV4 S3 bucket/prefix `ListObjectsV2`, `HEAD`, `PUT`, byte-range `GET`,
//!   `CopyObject`, `rename`, resumable Multipart Upload (skipping uploaded parts
//!   on retry!), and `ListObjectVersions` / `?versionId=` operations


use linscp_test_support as common;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;
use linscp_crypto::digests::{compute_digest_hex, DigestAlgorithm};
use linscp_proto::s3::{MultipartResumeStore, S3ConnectConfig, S3Session};
use linscp_proto::tls::{TlsSettings, TlsVersion};
use linscp_proto::webdav::{DavEtagPrecondition, WebDavConnectConfig, WebDavSession};
use linscp_proto::{
    download_bytes, upload_bytes, ProgressCallback, RemoteSession, TransferRequest,
};
use linscp_types::ProtocolScheme;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

async fn spawn_https_router(router: Router, pki: &common::GeneratedTlsPki) -> u16 {
    let plain_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind plain");
    let plain_addr = plain_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(plain_listener, router).await;
    });

    let tls_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tls");
    let tls_port = tls_listener.local_addr().unwrap().port();
    let acceptor = TlsAcceptor::from(Arc::clone(&pki.server_config));

    tokio::spawn(async move {
        while let Ok((client_tcp, _)) = tls_listener.accept().await {
            let acc = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls_stream) = acc.accept(client_tcp).await else {
                    return;
                };
                let Ok(mut backend) = TcpStream::connect(plain_addr).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut tls_stream, &mut backend).await;
            });
        }
    });
    tls_port
}

#[derive(Clone)]
struct MockDavResource {
    is_dir: bool,
    data: Vec<u8>,
    etag: String,
    props: HashMap<String, String>,
    lock_token: Option<String>,
}

#[derive(Default)]
struct MockDavStore {
    items: HashMap<String, MockDavResource>,
    rev: u64,
}

impl MockDavStore {
    fn new() -> Self {
        let mut items = HashMap::new();
        items.insert(
            "/dav".to_string(),
            MockDavResource {
                is_dir: true,
                data: Vec::new(),
                etag: "\"dir-0\"".to_string(),
                props: HashMap::new(),
                lock_token: None,
            },
        );
        Self { items, rev: 1 }
    }
}

fn norm_dav_path(raw: &str) -> String {
    let p = raw.trim_end_matches('/');
    if p.is_empty() {
        "/".to_string()
    } else {
        p.to_string()
    }
}

fn check_dav_if_precondition(res: Option<&MockDavResource>, if_hdr: Option<&str>) -> StatusCode {
    if let Some(r) = res {
        if let Some(ref lock_tok) = r.lock_token {
            let expected = format!("<{lock_tok}>");
            if !if_hdr.is_some_and(|h| h.contains(&expected)) {
                return StatusCode::LOCKED;
            }
        }
    }
    if let Some(hdr) = if_hdr {
        // Check `Not ["etag"]` vs `["etag"]`
        if let Some(not_idx) = hdr.find("Not [") {
            let rest = &hdr[not_idx + 5..];
            if let Some(end) = rest.find(']') {
                let tag = &rest[..end];
                if res.is_some_and(|r| r.etag == tag) {
                    return StatusCode::PRECONDITION_FAILED;
                }
            }
        } else if let Some(b_idx) = hdr.find('[') {
            let rest = &hdr[b_idx + 1..];
            if let Some(end) = rest.find(']') {
                let tag = &rest[..end];
                if !res.is_some_and(|r| r.etag == tag) {
                    return StatusCode::PRECONDITION_FAILED;
                }
            }
        }
    }
    StatusCode::OK
}

async fn handle_mock_dav(
    State(store): State<Arc<Mutex<MockDavStore>>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = norm_dav_path(uri.path());
    let if_hdr = headers.get("if").and_then(|v| v.to_str().ok());
    let depth = headers
        .get("depth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("1");

    match method.as_str() {
        "PROPFIND" => {
            let guard = store.lock().await;
            let Some(root_res) = guard.items.get(&path) else {
                return (StatusCode::NOT_FOUND, "Not Found").into_response();
            };
            let mut targets = vec![(path.clone(), root_res)];
            if depth == "1" && root_res.is_dir {
                let prefix = format!("{path}/");
                for (k, v) in &guard.items {
                    if let Some(rem) = k.strip_prefix(&prefix) {
                        if !rem.is_empty() && !rem.contains('/') {
                            targets.push((k.clone(), v));
                        }
                    }
                }
            }

            let mut xml = String::from(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
                 <D:multistatus xmlns:D=\"DAV:\" xmlns:L=\"urn:linscp:properties\">",
            );
            for (href_p, r) in targets {
                let href = if r.is_dir {
                    format!("{href_p}/")
                } else {
                    href_p
                };
                let rtype = if r.is_dir { "<D:collection/>" } else { "" };
                let mut custom = String::new();
                for (pk, pv) in &r.props {
                    custom.push_str(&format!("<L:{pk}>{pv}</L:{pk}>"));
                }
                xml.push_str(&format!(
                    "<D:response><D:href>{href}</D:href><D:propstat><D:prop>\
                     <D:resourcetype>{rtype}</D:resourcetype>\
                     <D:getcontentlength>{}</D:getcontentlength>\
                     <D:getlastmodified>Sun, 15 Mar 2026 12:00:00 GMT</D:getlastmodified>\
                     <D:getetag>{}</D:getetag>{custom}\
                     </D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>",
                    r.data.len(),
                    r.etag
                ));
            }
            xml.push_str("</D:multistatus>");
            (
                StatusCode::MULTI_STATUS,
                [("content-type", "application/xml")],
                xml,
            )
                .into_response()
        }
        "MKCOL" => {
            let mut guard = store.lock().await;
            guard.rev += 1;
            let etag = format!("\"rev-{}\"", guard.rev);
            guard.items.insert(
                path,
                MockDavResource {
                    is_dir: true,
                    data: Vec::new(),
                    etag,
                    props: HashMap::new(),
                    lock_token: None,
                },
            );
            StatusCode::CREATED.into_response()
        }
        "PUT" => {
            let mut guard = store.lock().await;
            let pre_code = check_dav_if_precondition(guard.items.get(&path), if_hdr);
            if pre_code != StatusCode::OK {
                return pre_code.into_response();
            }
            let existing_lock = guard.items.get(&path).and_then(|r| r.lock_token.clone());
            let existing_props = guard
                .items
                .get(&path)
                .map(|r| r.props.clone())
                .unwrap_or_default();
            guard.rev += 1;
            let etag = format!("\"rev-{}\"", guard.rev);
            guard.items.insert(
                path,
                MockDavResource {
                    is_dir: false,
                    data: body.to_vec(),
                    etag,
                    props: existing_props,
                    lock_token: existing_lock,
                },
            );
            StatusCode::CREATED.into_response()
        }
        "GET" => {
            let guard = store.lock().await;
            let Some(res) = guard.items.get(&path) else {
                return StatusCode::NOT_FOUND.into_response();
            };
            if let Some(range) = headers.get("range").and_then(|v| v.to_str().ok()) {
                if let Some(off_str) = range.strip_prefix("bytes=").and_then(|s| s.strip_suffix('-'))
                {
                    if let Ok(off) = off_str.parse::<usize>() {
                        if off >= res.data.len() { return StatusCode::RANGE_NOT_SATISFIABLE.into_response(); }
                        let slice = res.data[off..].to_vec();
                        let content_range = format!("bytes {}-{}/{}", off, res.data.len() - 1, res.data.len());
                        return (StatusCode::PARTIAL_CONTENT, [("content-range", content_range)], slice).into_response();
                    }
                }
            }
            (StatusCode::OK, res.data.clone()).into_response()
        }
        "DELETE" => {
            let mut guard = store.lock().await;
            let pre_code = check_dav_if_precondition(guard.items.get(&path), if_hdr);
            if pre_code != StatusCode::OK {
                return pre_code.into_response();
            }
            // A collection that still holds members is not removed: a server
            // that emptied it first would leave a half-deleted tree behind.
            if guard.items.get(&path).is_some_and(|r| r.is_dir) {
                let prefix = format!("{path}/");
                if guard.items.keys().any(|k| k.starts_with(&prefix)) {
                    return StatusCode::CONFLICT.into_response();
                }
            }
            if guard.items.remove(&path).is_some() {
                StatusCode::NO_CONTENT.into_response()
            } else {
                StatusCode::NOT_FOUND.into_response()
            }
        }
        "COPY" | "MOVE" => {
            let Some(dest_hdr) = headers.get("destination").and_then(|v| v.to_str().ok()) else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            let dest_path = dest_hdr
                .split_once("://")
                .and_then(|(_, r)| r.find('/').map(|i| &r[i..]))
                .unwrap_or(dest_hdr);
            let norm_dest = norm_dav_path(dest_path);
            let mut guard = store.lock().await;
            let pre_code = check_dav_if_precondition(guard.items.get(&path), if_hdr);
            if pre_code != StatusCode::OK {
                return pre_code.into_response();
            }
            let Some(mut cloned) = guard.items.get(&path).cloned() else {
                return StatusCode::NOT_FOUND.into_response();
            };
            cloned.lock_token = None;
            if method.as_str() == "MOVE" {
                guard.items.remove(&path);
            }
            guard.items.insert(norm_dest, cloned);
            StatusCode::CREATED.into_response()
        }
        "LOCK" => {
            let mut guard = store.lock().await;
            let Some(res) = guard.items.get_mut(&path) else {
                return StatusCode::NOT_FOUND.into_response();
            };
            let tok = "opaquelocktoken:7777-8888-9999".to_string();
            res.lock_token = Some(tok.clone());
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
                 <D:prop xmlns:D=\"DAV:\"><D:lockdiscovery><D:activelock>\
                 <D:locktoken><D:href>{tok}</D:href></D:locktoken>\
                 </D:activelock></D:lockdiscovery></D:prop>"
            );
            (
                StatusCode::OK,
                [
                    ("content-type", "application/xml"),
                    ("lock-token", "<opaquelocktoken:7777-8888-9999>"),
                ],
                xml,
            )
                .into_response()
        }
        "UNLOCK" => {
            let mut guard = store.lock().await;
            if let Some(res) = guard.items.get_mut(&path) {
                res.lock_token = None;
                StatusCode::NO_CONTENT.into_response()
            } else {
                StatusCode::NOT_FOUND.into_response()
            }
        }
        "PROPPATCH" => {
            let xml_str = String::from_utf8_lossy(&body);
            let mut guard = store.lock().await;
            let pre_code = check_dav_if_precondition(guard.items.get(&path), if_hdr);
            if pre_code != StatusCode::OK {
                return pre_code.into_response();
            }
            if let (Ok(doc), Some(res)) = (
                roxmltree::Document::parse(&xml_str),
                guard.items.get_mut(&path),
            ) {
                for prop_parent in doc
                    .descendants()
                    .filter(|n| n.is_element() && n.tag_name().name() == "prop")
                {
                    for elem in prop_parent.children().filter(|c| c.is_element()) {
                        res.props.insert(
                            elem.tag_name().name().to_string(),
                            elem.text().unwrap_or("").to_string(),
                        );
                    }
                }
                return StatusCode::MULTI_STATUS.into_response();
            }
            StatusCode::BAD_REQUEST.into_response()
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

#[tokio::test]
async fn webdavs_spki_pinning_locks_etags_and_properties_round_trip() {
    let pki = common::generate_test_tls_pki(1);
    let store = Arc::new(Mutex::new(MockDavStore::new()));
    let router = Router::new()
        .fallback(handle_mock_dav)
        .with_state(Arc::clone(&store));
    let port = spawn_https_router(router, &pki).await;

    // 1. Mismatched SPKI pin MUST fail TLS handshake even when CA is trusted!
    let wrong_pin = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string();
    let bad_dav = WebDavSession::connect(
        WebDavConnectConfig {
            scheme: ProtocolScheme::Webdavs,
            host: "localhost".to_string(),
            port,
            base_path: "/dav".to_string(),
            tls: TlsSettings {
                pinned_public_key: Some(wrong_pin),
                ca_cert_pem: Some(pki.ca_cert_pem.clone()),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
        0,
    )
    .await
    .unwrap();
    assert!(bad_dav.list_dir("/").await.is_err());

    // 2. Matching SPKI SHA-256 pin + TLS 1.3 succeeds!
    let dav = WebDavSession::connect(
        WebDavConnectConfig {
            scheme: ProtocolScheme::Webdavs,
            host: "localhost".to_string(),
            port,
            base_path: "/dav".to_string(),
            tls: TlsSettings {
                pinned_public_key: Some(pki.server_spki_pin.clone()),
                min_version: Some(TlsVersion::Tls13),
                max_version: Some(TlsVersion::Tls13),
                ca_cert_pem: Some(pki.ca_cert_pem.clone()),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
        0,
    )
    .await
    .unwrap();

    dav.mkdir("project").await.unwrap();
    let body_v1 = b"WebDAV version 1 content -- pure Rust!";
    upload_bytes(&dav, "project/spec.txt", body_v1, TransferRequest::default())
        .await
        .unwrap();

    let items = dav.list_dir("project").await.unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].name, "spec.txt");
    assert_eq!(items[0].size, body_v1.len() as u64);

    // Byte-range resume GET
    let resumed = download_bytes(
        &dav,
        "project/spec.txt",
        TransferRequest {
            resume_offset: 7,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(resumed, &body_v1[7..]);

    // Dead properties (`PROPPATCH` + `PROPFIND`)
    dav.set_property("project/spec.txt", "owner_team", "storage-core")
        .await
        .unwrap();
    assert_eq!(
        dav.get_property("project/spec.txt", "owner_team")
            .await
            .unwrap(),
        Some("storage-core".to_string())
    );

    // Exclusive LOCK: another client without the lock token receives HTTP 423 Locked,
    // while `dav` (which holds the token) succeeds via RFC 4918 `If: (<token>)`!
    let token = dav.lock("project/spec.txt", 300).await.unwrap();
    assert_eq!(token, "opaquelocktoken:7777-8888-9999");

    let outsider = WebDavSession::connect(
        WebDavConnectConfig {
            scheme: ProtocolScheme::Webdavs,
            host: "localhost".to_string(),
            port,
            base_path: "/dav".to_string(),
            tls: TlsSettings {
                ca_cert_pem: Some(pki.ca_cert_pem.clone()),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
        0,
    )
    .await
    .unwrap();
    let locked_err = upload_bytes(
        &outsider,
        "project/spec.txt",
        b"unauthorized overwrite",
        TransferRequest::default(),
    )
    .await
    .unwrap_err();
    assert!(locked_err.to_string().contains("423"));

    // Holder writes v2 cleanly, then tests ETag preconditions (`If-Match`) and unlocks!
    let body_v2 = b"WebDAV version 2 guarded by LOCK + ETag!";
    upload_bytes(&dav, "project/spec.txt", body_v2, TransferRequest::default())
        .await
        .unwrap();
    let current_etag = dav
        .get_etag("project/spec.txt")
        .await
        .unwrap()
        .expect("etag present");

    dav.set_etag_precondition(
        "project/spec.txt",
        Some(DavEtagPrecondition {
            if_match: Some("\"stale-etag\"".to_string()),
            if_none_match: None,
        }),
    )
    .await;
    let precond_err = upload_bytes(
        &dav,
        "project/spec.txt",
        b"should fail 412",
        TransferRequest::default(),
    )
    .await
    .unwrap_err();
    assert!(precond_err.to_string().contains("412"));
    // The refusal left the bytes exactly as they were.
    assert_eq!(
        download_bytes(&dav, "project/spec.txt", TransferRequest::default())
            .await
            .unwrap(),
        body_v2,
        "a refused write must not change the file"
    );

    dav.set_etag_precondition(
        "project/spec.txt",
        Some(DavEtagPrecondition {
            if_match: Some(current_etag.clone()),
            if_none_match: None,
        }),
    )
    .await;
    upload_bytes(&dav, "project/spec.txt", body_v2, TransferRequest::default())
        .await
        .unwrap();

    // If-None-Match writes where the version differs and is refused where it
    // does not: that is the opposite of If-Match.
    let written_etag = dav
        .get_etag("project/spec.txt")
        .await
        .unwrap()
        .expect("etag present");
    dav.set_etag_precondition(
        "project/spec.txt",
        Some(DavEtagPrecondition {
            if_match: None,
            if_none_match: Some(written_etag),
        }),
    )
    .await;
    let same_version = upload_bytes(
        &dav,
        "project/spec.txt",
        b"should fail 412 as well",
        TransferRequest::default(),
    )
    .await
    .unwrap_err();
    assert!(same_version.to_string().contains("412"));

    dav.set_etag_precondition(
        "project/spec.txt",
        Some(DavEtagPrecondition {
            if_match: None,
            if_none_match: Some("\"a-different-etag\"".to_string()),
        }),
    )
    .await;
    upload_bytes(&dav, "project/spec.txt", body_v2, TransferRequest::default())
        .await
        .unwrap();

    dav.set_etag_precondition("project/spec.txt", None).await;
    dav.unlock("project/spec.txt", None).await.unwrap();

    dav.copy_file("project/spec.txt", "project/copy.txt")
        .await
        .unwrap();
    dav.rename("project/copy.txt", "project/moved.txt")
        .await
        .unwrap();
    dav.remove_file("project/spec.txt").await.unwrap();
    dav.remove_file("project/moved.txt").await.unwrap();
    dav.remove_dir("project").await.unwrap();
    dav.close().await.unwrap();
}

// =========================================================================
// Mock SigV4-verifying S3 Server (Multipart Resume + Object Versioning)
// =========================================================================

#[derive(Clone)]
struct MockS3VersionEntry {
    version_id: String,
    is_delete_marker: bool,
    data: Vec<u8>,
}

/// How the mock answers a `ListObjectsV2` request that claims to be
/// truncated. A real endpoint either names the next page or admits the
/// listing is over; a client that cannot tell must refuse the listing rather
/// than return half of it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PaginationMode {
    Normal,
    TruncatedWithoutToken,
    RepeatedToken,
}

struct MockS3State {
    buckets: HashMap<String, BTreeMap<String, Vec<MockS3VersionEntry>>>,
    multiparts: HashMap<String, BTreeMap<u32, (String, Vec<u8>)>>,
    next_ver: u64,
    next_upload: u64,
    fail_part_2_once: AtomicBool,
    part_1_uploads: AtomicUsize,
    last_create_bucket_xml: String,
    /// The headers of the last object write, so a case can prove that the
    /// configured `x-amz-*` headers really reached the server.
    last_write_headers: BTreeMap<String, String>,
    /// The SigV4 `Authorization` header of that write, so a case can prove
    /// those headers were *signed* rather than merely sent.
    last_authorization: String,
    pagination_mode: PaginationMode,
    /// When `true`, `CompleteMultipartUpload` answers 200 with an error
    /// document instead of a result: the failure a server hides inside a
    /// successful status.
    complete_reports_error: AtomicBool,
    /// The byte ranges the server was asked to copy, so a case can prove a
    /// large copy really went through multipart `UploadPartCopy`.
    copy_ranges: Vec<String>,
}

impl MockS3State {
    fn new() -> Self {
        let mut buckets = HashMap::new();
        buckets.insert("alpha-bucket".to_string(), BTreeMap::new());
        Self {
            buckets,
            multiparts: HashMap::new(),
            next_ver: 1,
            next_upload: 1,
            fail_part_2_once: AtomicBool::new(true),
            part_1_uploads: AtomicUsize::new(0),
            last_create_bucket_xml: String::new(),
            last_write_headers: BTreeMap::new(),
            last_authorization: String::new(),
            pagination_mode: PaginationMode::Normal,
            complete_reports_error: AtomicBool::new(false),
            copy_ranges: Vec::new(),
        }
    }
}

fn percent_decode_str(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push(((h << 4) | l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_query_map(query: Option<&str>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Some(q) = query else {
        return map;
    };
    for pair in q.split('&').filter(|s| !s.is_empty()) {
        match pair.split_once('=') {
            Some((k, v)) => {
                map.insert(percent_decode_str(k), percent_decode_str(v));
            }
            None => {
                map.insert(percent_decode_str(pair), String::new());
            }
        }
    }
    map
}

async fn handle_mock_s3(
    State(state): State<Arc<Mutex<MockS3State>>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Enforce AWS SigV4 headers on every single request!
    let auth_hdr = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let content_sha = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !auth_hdr.starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/")
        || content_sha != compute_digest_hex(DigestAlgorithm::Sha256, &body)
    {
        let err_xml = "<Error><Code>SignatureDoesNotMatch</Code>\
            <Message>Invalid SigV4 header or payload hash</Message></Error>";
        return (StatusCode::FORBIDDEN, err_xml).into_response();
    }

    let qmap = parse_query_map(uri.query());
    let decoded_path = percent_decode_str(uri.path());
    let path = decoded_path.trim_start_matches('/');
    if path.is_empty() && method == Method::GET {
        let guard = state.lock().await;
        let mut xml = String::from("<ListAllMyBucketsResult><Buckets>");
        for bkt in guard.buckets.keys() {
            xml.push_str(&format!(
                "<Bucket><Name>{bkt}</Name><CreationDate>2026-03-15T12:00:00Z</CreationDate></Bucket>"
            ));
        }
        xml.push_str("</Buckets></ListAllMyBucketsResult>");
        return (StatusCode::OK, xml).into_response();
    }

    let (bucket, key) = match path.split_once('/') {
        Some((b, k)) => (b.to_string(), k.to_string()),
        None => (path.to_string(), String::new()),
    };

    // Bucket-level operations (`key.is_empty()`)
    if key.is_empty() {
        if method == Method::HEAD {
            if state.lock().await.buckets.contains_key(&bucket) {
                return StatusCode::OK.into_response();
            }
            return StatusCode::NOT_FOUND.into_response();
        }
        if method == Method::PUT {
            let mut guard = state.lock().await;
            guard.last_create_bucket_xml = String::from_utf8_lossy(&body).into_owned();
            guard.buckets.entry(bucket).or_default();
            return StatusCode::OK.into_response();
        }
        if method == Method::GET && qmap.contains_key("versions") {
            let prefix = qmap.get("prefix").cloned().unwrap_or_default();
            let guard = state.lock().await;
            let mut xml = String::from("<ListVersionsResult><IsTruncated>false</IsTruncated>");
            if let Some(objs) = guard.buckets.get(&bucket) {
                for (okey, vers) in objs {
                    if !okey.starts_with(&prefix) {
                        continue;
                    }
                    let last_idx = vers.len().saturating_sub(1);
                    for (idx, v) in vers.iter().enumerate() {
                        let latest = if idx == last_idx { "true" } else { "false" };
                        if v.is_delete_marker {
                            xml.push_str(&format!(
                                "<DeleteMarker><Key>{okey}</Key><VersionId>{}</VersionId>\
                                 <IsLatest>{latest}</IsLatest>\
                                 <LastModified>2026-03-15T12:00:00Z</LastModified></DeleteMarker>",
                                v.version_id
                            ));
                        } else {
                            xml.push_str(&format!(
                                "<Version><Key>{okey}</Key><VersionId>{}</VersionId>\
                                 <IsLatest>{latest}</IsLatest><Size>{}</Size>\
                                 <LastModified>2026-03-15T12:00:00Z</LastModified></Version>",
                                v.version_id,
                                v.data.len()
                            ));
                        }
                    }
                }
            }
            xml.push_str("</ListVersionsResult>");
            return (StatusCode::OK, xml).into_response();
        }
        if method == Method::GET {
            let prefix = qmap.get("prefix").cloned().unwrap_or_default();
            let delim = qmap.get("delimiter").cloned().unwrap_or_default();
            let guard = state.lock().await;
            let mut xml = String::from("<ListBucketResult><IsTruncated>false</IsTruncated>");
            let mut prefixes = std::collections::BTreeSet::new();
            if let Some(objs) = guard.buckets.get(&bucket) {
                for (okey, vers) in objs {
                    let Some(cur) = vers.last() else { continue };
                    if cur.is_delete_marker || !okey.starts_with(&prefix) {
                        continue;
                    }
                    let rem = &okey[prefix.len()..];
                    if !delim.is_empty() {
                        if let Some(pos) = rem.find(&delim) {
                            let sub = format!("{prefix}{}", &rem[..pos + delim.len()]);
                            if sub != prefix {
                                prefixes.insert(sub);
                                continue;
                            }
                        }
                    }
                    xml.push_str(&format!(
                        "<Contents><Key>{okey}</Key><Size>{}</Size>\
                         <LastModified>2026-03-15T12:00:00Z</LastModified></Contents>",
                        cur.data.len()
                    ));
                }
            }
            for cp in prefixes {
                xml.push_str(&format!("<CommonPrefixes><Prefix>{cp}</Prefix></CommonPrefixes>"));
            }
            // A truncated listing has to name the page that follows, and it
            // must not name the page it was just given.
            match guard.pagination_mode {
                PaginationMode::Normal => {}
                PaginationMode::TruncatedWithoutToken => {
                    xml = xml.replace(
                        "<IsTruncated>false</IsTruncated>",
                        "<IsTruncated>true</IsTruncated>",
                    );
                }
                PaginationMode::RepeatedToken => {
                    xml = xml.replace(
                        "<IsTruncated>false</IsTruncated>",
                        "<IsTruncated>true</IsTruncated><NextContinuationToken>same</NextContinuationToken>",
                    );
                }
            }
            xml.push_str("</ListBucketResult>");
            return (StatusCode::OK, xml).into_response();
        }
    }

    // Multipart upload endpoints
    if method == Method::POST && qmap.contains_key("uploads") {
        let mut guard = state.lock().await;
        // `CreateMultipartUpload` is an object write too: the configured
        // headers have to reach it.
        let mut recorded = BTreeMap::new();
        for (name, value) in headers.iter() {
            recorded.insert(
                name.as_str().to_ascii_lowercase(),
                value.to_str().unwrap_or("").to_string(),
            );
        }
        guard.last_authorization = recorded
            .get("authorization")
            .cloned()
            .unwrap_or_default();
        guard.last_write_headers = recorded;
        let uid = format!("upload-{}", guard.next_upload);
        guard.next_upload += 1;
        guard.multiparts.insert(uid.clone(), BTreeMap::new());
        let xml = format!(
            "<InitiateMultipartUploadResult><Bucket>{bucket}</Bucket>\
             <Key>{key}</Key><UploadId>{uid}</UploadId></InitiateMultipartUploadResult>"
        );
        return (StatusCode::OK, xml).into_response();
    }

    if let Some(uid) = qmap.get("uploadId") {
        if method == Method::PUT {
            let pnum: u32 = qmap
                .get("partNumber")
                .and_then(|s| s.parse().ok())
                .unwrap_or(1);
            let mut guard = state.lock().await;
            if pnum == 1 {
                guard.part_1_uploads.fetch_add(1, Ordering::SeqCst);
            }
            if pnum == 2 && guard.fail_part_2_once.swap(false, Ordering::SeqCst) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "<Error><Code>InternalError</Code><Message>Simulated transient error on part 2</Message></Error>",
                )
                    .into_response();
            }
            let etag = format!("\"part-etag-{pnum}\"");
            if let Some(copy_src) = headers
                .get("x-amz-copy-source")
                .and_then(|v| v.to_str().ok())
            {
                let decoded_copy = percent_decode_str(copy_src);
                let clean = decoded_copy.trim_start_matches('/');
                let (sb, sk) = clean.split_once('/').unwrap_or(("", ""));
                let Some(mut src_bytes) = guard
                    .buckets
                    .get(sb)
                    .and_then(|m| m.get(sk))
                    .and_then(|v| v.last())
                    .filter(|e| !e.is_delete_marker)
                    .map(|e| e.data.clone())
                else {
                    return StatusCode::NOT_FOUND.into_response();
                };
                if let Some(rng) = headers
                    .get("x-amz-copy-source-range")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.strip_prefix("bytes="))
                {
                    if let Some((a, b)) = rng.split_once('-') {
                        if let (Ok(start), Ok(end)) = (a.parse::<usize>(), b.parse::<usize>()) {
                            if start <= end && end < src_bytes.len() {
                                src_bytes = src_bytes[start..=end].to_vec();
                            }
                        }
                    }
                }
                if let Some(range) = headers
                    .get("x-amz-copy-source-range")
                    .and_then(|v| v.to_str().ok())
                {
                    guard.copy_ranges.push(range.to_string());
                }
                if let Some(parts) = guard.multiparts.get_mut(uid) {
                    parts.insert(pnum, (etag.clone(), src_bytes));
                }
                let xml = format!("<CopyPartResult><ETag>{etag}</ETag></CopyPartResult>");
                return (StatusCode::OK, xml).into_response();
            }
            if let Some(parts) = guard.multiparts.get_mut(uid) {
                parts.insert(pnum, (etag.clone(), body.to_vec()));
            }
            return (StatusCode::OK, [("etag", etag)], "").into_response();
        }
        if method == Method::POST {
            let mut guard = state.lock().await;
            if guard.complete_reports_error.swap(false, Ordering::SeqCst) {
                // A failure hidden inside a successful status: the client has
                // to read the document, not the status line.
                return (
                    StatusCode::OK,
                    "<Error><Code>InternalError</Code>\
                     <Message>Simulated failure reported with a successful status</Message></Error>",
                )
                    .into_response();
            }
            let Some(parts) = guard.multiparts.remove(uid) else {
                return StatusCode::NOT_FOUND.into_response();
            };
            let mut combined = Vec::new();
            for (_pnum, (_etag, bytes)) in parts {
                combined.extend_from_slice(&bytes);
            }
            let vid = format!("v{}", guard.next_ver);
            guard.next_ver += 1;
            guard
                .buckets
                .entry(bucket)
                .or_default()
                .entry(key)
                .or_default()
                .push(MockS3VersionEntry {
                    version_id: vid,
                    is_delete_marker: false,
                    data: combined,
                });
            return (
                StatusCode::OK,
                "<CompleteMultipartUploadResult><ETag>\"final\"</ETag></CompleteMultipartUploadResult>",
            )
                .into_response();
        }
        if method == Method::DELETE {
            state.lock().await.multiparts.remove(uid);
            return StatusCode::NO_CONTENT.into_response();
        }
    }

    // Object-level CRUD & versioning
    match method {
        Method::PUT => {
            let mut guard = state.lock().await;
            // Record what the write actually carried: the configured
            // `x-amz-*` headers and the signature that covers them.
            let mut recorded = BTreeMap::new();
            for (name, value) in headers.iter() {
                recorded.insert(
                    name.as_str().to_ascii_lowercase(),
                    value.to_str().unwrap_or("").to_string(),
                );
            }
            guard.last_authorization = recorded
                .get("authorization")
                .cloned()
                .unwrap_or_default();
            guard.last_write_headers = recorded;
            let data = if let Some(copy_src) =
                headers.get("x-amz-copy-source").and_then(|v| v.to_str().ok())
            {
                let decoded_copy = percent_decode_str(copy_src);
                let clean = decoded_copy.trim_start_matches('/');
                let (sb, sk) = clean.split_once('/').unwrap_or(("", ""));
                let Some(src_bytes) = guard
                    .buckets
                    .get(sb)
                    .and_then(|m| m.get(sk))
                    .and_then(|v| v.last())
                    .filter(|e| !e.is_delete_marker)
                    .map(|e| e.data.clone())
                else {
                    return StatusCode::NOT_FOUND.into_response();
                };
                src_bytes
            } else {
                body.to_vec()
            };
            let vid = format!("v{}", guard.next_ver);
            guard.next_ver += 1;
            guard
                .buckets
                .entry(bucket)
                .or_default()
                .entry(key)
                .or_default()
                .push(MockS3VersionEntry {
                    version_id: vid,
                    is_delete_marker: false,
                    data,
                });
            if headers.contains_key("x-amz-copy-source") {
                (StatusCode::OK, "<CopyObjectResult><ETag>\"copied\"</ETag></CopyObjectResult>")
                    .into_response()
            } else {
                StatusCode::OK.into_response()
            }
        }
        Method::HEAD | Method::GET => {
            let req_vid = qmap.get("versionId").map(String::as_str).unwrap_or("");
            let guard = state.lock().await;
            let entry_opt = guard
                .buckets
                .get(&bucket)
                .and_then(|m| m.get(&key))
                .and_then(|vers| {
                    if req_vid.is_empty() {
                        vers.last()
                    } else {
                        vers.iter().find(|v| v.version_id == req_vid)
                    }
                })
                .filter(|v| !v.is_delete_marker);
            let Some(entry) = entry_opt else {
                return StatusCode::NOT_FOUND.into_response();
            };
            if method == Method::HEAD {
                return (
                    StatusCode::OK,
                    [
                        ("content-length", entry.data.len().to_string()),
                        (
                            "last-modified",
                            "Sun, 15 Mar 2026 12:00:00 GMT".to_string(),
                        ),
                    ],
                    Vec::<u8>::new(),
                )
                    .into_response();
            }
            if let Some(range) = headers.get("range").and_then(|v| v.to_str().ok()) {
                if let Some(off_s) = range.strip_prefix("bytes=").and_then(|s| s.strip_suffix('-')) {
                    if let Ok(off) = off_s.parse::<usize>() {
                        let slice = entry.data[off.min(entry.data.len())..].to_vec();
                        return (StatusCode::PARTIAL_CONTENT, slice).into_response();
                    }
                }
            }
            (StatusCode::OK, entry.data.clone()).into_response()
        }
        Method::DELETE => {
            let req_vid = qmap.get("versionId").cloned().unwrap_or_default();
            let mut guard = state.lock().await;
            let next_id = format!("v{}", guard.next_ver);
            guard.next_ver += 1;
            if let Some(objs) = guard.buckets.get_mut(&bucket) {
                if req_vid.is_empty() {
                    objs.entry(key).or_default().push(MockS3VersionEntry {
                        version_id: next_id,
                        is_delete_marker: true,
                        data: Vec::new(),
                    });
                } else if let Some(vers) = objs.get_mut(&key) {
                    vers.retain(|v| v.version_id != req_vid);
                }
            }
            StatusCode::NO_CONTENT.into_response()
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

#[tokio::test]
async fn s3_multipart_checkpoints_are_scoped_to_the_endpoint() {
    let pki = common::generate_test_tls_pki(2);
    let first = Arc::new(Mutex::new(MockS3State::new()));
    let second = Arc::new(Mutex::new(MockS3State::new()));
    second.lock().await.fail_part_2_once.store(false, Ordering::SeqCst);
    let port_a = spawn_https_router(Router::new().fallback(handle_mock_s3).with_state(Arc::clone(&first)), &pki).await;
    let port_b = spawn_https_router(Router::new().fallback(handle_mock_s3).with_state(Arc::clone(&second)), &pki).await;
    let store = MultipartResumeStore::new_in_memory();
    let connect = |port| S3ConnectConfig {
        use_https: true, host: "localhost".into(), port,
        region: Some("us-east-1".into()), access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
        secret_access_key: Zeroizing::new("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into()),
        path_style: true, multipart_threshold: 16 * 1024, min_part_size: 8 * 1024,
        abort_multipart_on_error: false, resume_store: store.clone(),
        tls: TlsSettings { pinned_public_key: Some(pki.server_spki_pin.clone()),
            ca_cert_pem: Some(pki.ca_cert_pem.clone()), ..Default::default() },
        ..Default::default()
    };
    let a = S3Session::connect(connect(port_a), None, 0).await.unwrap();
    let b = S3Session::connect(connect(port_b), None, 0).await.unwrap();
    let target = "/alpha-bucket/releases/shared.bin";
    let payload = vec![0x35; 20 * 1024];
    assert!(upload_bytes(&a, target, &payload, TransferRequest::default()).await.is_err());
    upload_bytes(&b, target, &payload, TransferRequest::default()).await.unwrap();
    assert_eq!(download_bytes(&b, target, TransferRequest::default()).await.unwrap(), payload);
    assert_eq!(second.lock().await.part_1_uploads.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn s3_sigv4_resumable_multipart_and_object_versioning_succeed() {
    let pki = common::generate_test_tls_pki(2);
    let state = Arc::new(Mutex::new(MockS3State::new()));
    let router = Router::new()
        .fallback(handle_mock_s3)
        .with_state(Arc::clone(&state));
    let port = spawn_https_router(router, &pki).await;

    let resume_store = MultipartResumeStore::new_in_memory();
    let s3 = S3Session::connect(
        S3ConnectConfig {
            use_https: true,
            host: "localhost".to_string(),
            port,
            region: Some("us-east-1".to_string()),
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: Zeroizing::new(
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            ),
            path_style: true,
            multipart_threshold: 16 * 1024,
            min_part_size: 8 * 1024,
            abort_multipart_on_error: false,
            resume_store: Arc::clone(&resume_store),
            tls: TlsSettings {
                pinned_public_key: Some(pki.server_spki_pin.clone()),
                ca_cert_pem: Some(pki.ca_cert_pem.clone()),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
        0,
    )
    .await
    .unwrap();

    // 1. Root bucket listing + create new bucket & folder
    let buckets = s3.list_dir("/").await.unwrap();
    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0].name, "alpha-bucket");

    s3.mkdir("/alpha-bucket/releases").await.unwrap();

    // 2. Object Versioning: upload v1 & v2, list versions, download v1 specifically!
    upload_bytes(
        &s3,
        "/alpha-bucket/releases/changelog.txt",
        b"Release 1.0 notes",
        TransferRequest::default(),
    )
    .await
    .unwrap();
    upload_bytes(
        &s3,
        "/alpha-bucket/releases/changelog.txt",
        b"Release 2.0 updated notes",
        TransferRequest::default(),
    )
    .await
    .unwrap();

    let versions = s3
        .list_versions("/alpha-bucket/releases/changelog.txt")
        .await
        .unwrap();
    assert_eq!(versions.len(), 2);
    assert!(!versions[0].is_latest);
    assert!(versions[1].is_latest);

    let v1_bytes = download_bytes(
        &s3,
        "/alpha-bucket/releases/changelog.txt",
        TransferRequest {
            version_id: Some(versions[0].version_id.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(v1_bytes, b"Release 1.0 notes");

    // 3. Resumable Multipart Upload (20 KiB -> 3 parts of 8 KiB, 8 KiB, 4 KiB):
    // First attempt fails transiently on Part 2 AFTER Part 1 succeeded.
    // Second attempt resumes from `MultipartResumeStore` WITHOUT re-uploading Part 1!
    let large_payload: Vec<u8> = (0..(20 * 1024)).map(|i| (i % 251) as u8).collect();
    let first_try = upload_bytes(
        &s3,
        "/alpha-bucket/releases/bundle.bin",
        &large_payload,
        TransferRequest::default(),
    )
    .await;
    assert!(first_try.is_err(), "simulated transient error on part 2");
    assert_eq!(
        state.lock().await.part_1_uploads.load(Ordering::SeqCst),
        1,
        "part 1 uploaded once before failure"
    );

    upload_bytes(
        &s3,
        "/alpha-bucket/releases/bundle.bin",
        &large_payload,
        TransferRequest::default(),
    )
    .await
    .expect("resumed multipart upload succeeds on retry");
    assert_eq!(
        state.lock().await.part_1_uploads.load(Ordering::SeqCst),
        1,
        "resumed multipart upload MUST skip already-completed part 1!"
    );

    let reassembled = download_bytes(
        &s3,
        "/alpha-bucket/releases/bundle.bin",
        TransferRequest::default(),
    )
    .await
    .unwrap();
    assert_eq!(reassembled, large_payload);

    // A same-length source changed between attempts must not reuse a stale
    // uploaded part merely because the target key and total size match.
    state.lock().await.fail_part_2_once.store(true, Ordering::SeqCst);
    let before = state.lock().await.part_1_uploads.load(Ordering::SeqCst);
    let original = vec![b'a'; 20 * 1024];
    let mut changed = original.clone();
    changed[7] = b'b';
    let target = "/alpha-bucket/releases/changed-source.bin";
    assert!(upload_bytes(&s3, target, &original, TransferRequest::default()).await.is_err());
    upload_bytes(&s3, target, &changed, TransferRequest::default()).await.unwrap();
    assert_eq!(state.lock().await.part_1_uploads.load(Ordering::SeqCst), before + 2,
        "the changed first part must be sent again");
    assert_eq!(download_bytes(&s3, target, TransferRequest::default()).await.unwrap(), changed);

    // Byte-range GET resume + server-side CopyObject / rename / version delete
    let tail = download_bytes(
        &s3,
        "/alpha-bucket/releases/bundle.bin",
        TransferRequest {
            resume_offset: 19_000,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(tail, &large_payload[19_000..]);

    s3.rename(
        "/alpha-bucket/releases/bundle.bin",
        "/alpha-bucket/releases/bundle-final.bin",
    )
    .await
    .unwrap();
    assert!(s3
        .stat("/alpha-bucket/releases/bundle.bin")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        s3.stat("/alpha-bucket/releases/bundle-final.bin")
            .await
            .unwrap()
            .unwrap()
            .size,
        large_payload.len() as u64
    );

    s3.remove_version("/alpha-bucket/releases/changelog.txt", &versions[0].version_id)
        .await
        .unwrap();

    // 4. Self-rename must be a safe no-op (never deleting the object!), self-copy and
    //    bucket-root download must be rejected, virtual folder rename must move all
    //    nested keys, and non-us-east-1 CreateBucket must send LocationConstraint.
    s3.rename(
        "/alpha-bucket/releases/bundle-final.bin",
        "/alpha-bucket/releases/bundle-final.bin",
    )
    .await
    .expect("self-rename must not fail or delete the object");
    assert!(
        s3.stat("/alpha-bucket/releases/bundle-final.bin")
            .await
            .unwrap()
            .is_some(),
        "object must survive self-rename"
    );
    assert!(
        s3.copy_file(
            "/alpha-bucket/releases/bundle-final.bin",
            "/alpha-bucket/releases/bundle-final.bin"
        )
        .await
        .is_err(),
        "self-copy must be rejected"
    );
    assert!(
        download_bytes(&s3, "/alpha-bucket", TransferRequest::default())
            .await
            .is_err(),
        "bucket-root download must be rejected instead of returning ListBucketResult XML"
    );

    upload_bytes(
        &s3,
        "/alpha-bucket/releases/nested/notes.txt",
        b"nested key",
        TransferRequest::default(),
    )
    .await
    .unwrap();
    s3.rename("/alpha-bucket/releases", "/alpha-bucket/archive")
        .await
        .expect("virtual prefix directory rename must succeed");
    assert!(
        s3.stat("/alpha-bucket/releases/bundle-final.bin")
            .await
            .unwrap()
            .is_none(),
        "old prefix key removed after folder rename"
    );
    assert_eq!(
        download_bytes(
            &s3,
            "/alpha-bucket/archive/nested/notes.txt",
            TransferRequest::default()
        )
        .await
        .unwrap(),
        b"nested key"
    );

    let s3_eu = S3Session::connect(
        S3ConnectConfig {
            use_https: true,
            host: "localhost".to_string(),
            port,
            region: Some("eu-west-1".to_string()),
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: Zeroizing::new(
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            ),
            path_style: true,
            tls: TlsSettings {
                pinned_public_key: Some(pki.server_spki_pin.clone()),
                ca_cert_pem: Some(pki.ca_cert_pem.clone()),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
        0,
    )
    .await
    .unwrap();
    s3_eu
        .mkdir("/eu-regional-bucket")
        .await
        .expect("regional CreateBucket");
    assert!(
        state
            .lock()
            .await
            .last_create_bucket_xml
            .contains("<LocationConstraint>eu-west-1</LocationConstraint>"),
        "non-us-east-1 CreateBucket must send LocationConstraint XML"
    );
    s3_eu.close().await.unwrap();
    s3.close().await.unwrap();
}

/// The S3 raw settings are not decoration: they are the headers the object
/// write has to carry, and a header that is sent but not signed is not
/// covered by the signature. This drives a client configured with the
/// upstream header set and reads back what the server actually received.
#[tokio::test]
async fn s3_object_write_headers_are_signed_and_sent_on_uploads_and_copies() {
    let pki = common::generate_test_tls_pki(4);
    let state = Arc::new(Mutex::new(MockS3State::new()));
    let router = Router::new()
        .fallback(handle_mock_s3)
        .with_state(Arc::clone(&state));
    let port = spawn_https_router(router, &pki).await;

    let mut object_write_headers = BTreeMap::new();
    for (name, value) in [
        ("x-amz-storage-class", "STANDARD_IA"),
        ("x-amz-acl", "private"),
        ("x-amz-server-side-encryption", "aws:kms"),
        (
            "x-amz-server-side-encryption-aws-kms-key-id",
            "key-1",
        ),
        ("x-amz-request-payer", "requester"),
        ("x-amz-meta-team", "storage-core"),
    ] {
        object_write_headers.insert(name.to_string(), value.to_string());
    }

    let s3 = S3Session::connect(
        S3ConnectConfig {
            use_https: true,
            host: "localhost".to_string(),
            port,
            region: Some("us-east-1".to_string()),
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: Zeroizing::new(
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            ),
            path_style: true,
            object_write_headers: object_write_headers.clone(),
            tls: TlsSettings {
                pinned_public_key: Some(pki.server_spki_pin.clone()),
                ca_cert_pem: Some(pki.ca_cert_pem.clone()),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
        0,
    )
    .await
    .unwrap();

    upload_bytes(
        &s3,
        "/alpha-bucket/releases/options.txt",
        b"storage class",
        TransferRequest::default(),
    )
    .await
    .unwrap();

    {
        let guard = state.lock().await;
        for (name, value) in &object_write_headers {
            assert_eq!(
                guard.last_write_headers.get(name).map(String::as_str),
                Some(value.as_str()),
                "{name} must reach the server on an upload"
            );
        }
        let signed: Vec<&str> = guard
            .last_authorization
            .split("SignedHeaders=")
            .nth(1)
            .and_then(|rest| rest.split(',').next())
            .expect("the Authorization header carries SignedHeaders")
            .split(';')
            .collect();
        for name in object_write_headers.keys() {
            assert!(
                signed.contains(&name.as_str()),
                "{name} must be covered by the signature, not merely sent: {signed:?}"
            );
        }
    }

    // The same headers have to reach a server-side copy.
    s3.copy_file(
        "/alpha-bucket/releases/options.txt",
        "/alpha-bucket/releases/options-copy.txt",
    )
    .await
    .unwrap();

    {
        let guard = state.lock().await;
        for (name, value) in &object_write_headers {
            assert_eq!(
                guard.last_write_headers.get(name).map(String::as_str),
                Some(value.as_str()),
                "{name} must reach the server on a copy"
            );
        }
    }

    s3.close().await.unwrap();
}

/// The byte progress is told while the transfer runs: the callback is
/// told what has arrived and how much there is, before the transfer ends.
/// The upload and the download both report it.
#[tokio::test]
async fn dav_reports_the_byte_progress_while_the_transfer_runs() {
    let pki = common::generate_test_tls_pki(9);
    let store = Arc::new(Mutex::new(MockDavStore::new()));
    let router = Router::new()
        .fallback(handle_mock_dav)
        .with_state(Arc::clone(&store));
    let port = spawn_https_router(router, &pki).await;

    let dav = WebDavSession::connect(
        WebDavConnectConfig {
            scheme: ProtocolScheme::Webdavs,
            host: "localhost".to_string(),
            port,
            base_path: "/dav".to_string(),
            tls: TlsSettings {
                pinned_public_key: Some(pki.server_spki_pin.clone()),
                ca_cert_pem: Some(pki.ca_cert_pem.clone()),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
        0,
    )
    .await
    .unwrap();

    let body = vec![b'p'; 256 * 1024];

    // The upload reports what it sent and how much there was to send.
    let up_calls = Arc::new(AtomicUsize::new(0));
    let up_last = Arc::new(AtomicUsize::new(0));
    let up_total = Arc::new(AtomicUsize::new(0));
    let up_calls_for_cb = Arc::clone(&up_calls);
    let up_last_for_cb = Arc::clone(&up_last);
    let up_total_for_cb = Arc::clone(&up_total);
    let up_callback: &ProgressCallback = &move |done: u64, total: u64| {
        up_calls_for_cb.fetch_add(1, Ordering::SeqCst);
        up_last_for_cb.store(done as usize, Ordering::SeqCst);
        up_total_for_cb.store(total as usize, Ordering::SeqCst);
    };
    let mut cursor = std::io::Cursor::new(body.clone());
    dav.upload(
        "metered.bin",
        TransferRequest::default(),
        &mut cursor,
        Some(body.len() as u64),
        Some(up_callback),
    )
    .await
    .unwrap();
    assert!(up_calls.load(Ordering::SeqCst) > 0, "the upload reported progress");
    assert_eq!(
        up_last.load(Ordering::SeqCst),
        body.len(),
        "the upload reported every byte"
    );
    assert_eq!(
        up_total.load(Ordering::SeqCst),
        body.len(),
        "the upload was told the whole size"
    );

    // The download reports what it received and how much there was.
    let down_calls = Arc::new(AtomicUsize::new(0));
    let down_last = Arc::new(AtomicUsize::new(0));
    let down_total = Arc::new(AtomicUsize::new(0));
    let down_calls_for_cb = Arc::clone(&down_calls);
    let down_last_for_cb = Arc::clone(&down_last);
    let down_total_for_cb = Arc::clone(&down_total);
    let down_callback: &ProgressCallback = &move |done: u64, total: u64| {
        down_calls_for_cb.fetch_add(1, Ordering::SeqCst);
        down_last_for_cb.store(done as usize, Ordering::SeqCst);
        down_total_for_cb.store(total as usize, Ordering::SeqCst);
    };
    let mut sink: Vec<u8> = Vec::new();
    dav.download(
        "metered.bin",
        TransferRequest::default(),
        &mut sink,
        Some(down_callback),
    )
    .await
    .unwrap();
    assert_eq!(sink, body, "the download carried the original bytes");
    assert!(
        down_calls.load(Ordering::SeqCst) > 0,
        "the download reported progress"
    );
    assert_eq!(
        down_last.load(Ordering::SeqCst),
        body.len(),
        "the download reported every byte"
    );
    assert_eq!(
        down_total.load(Ordering::SeqCst),
        body.len(),
        "the download was told the whole size"
    );

    dav.close().await.unwrap();
}

/// A name may hold spaces and the characters a URL treats as structure. The
/// client has to encode them on the way out and decode them on the way back,
/// so what the server stores is what the user typed.
#[tokio::test]
async fn dav_paths_with_spaces_and_reserved_characters_round_trip() {
    let pki = common::generate_test_tls_pki(5);
    let store = Arc::new(Mutex::new(MockDavStore::new()));
    let router = Router::new()
        .fallback(handle_mock_dav)
        .with_state(Arc::clone(&store));
    let port = spawn_https_router(router, &pki).await;

    let dav = WebDavSession::connect(
        WebDavConnectConfig {
            scheme: ProtocolScheme::Webdavs,
            host: "localhost".to_string(),
            port,
            base_path: "/dav".to_string(),
            tls: TlsSettings {
                ca_cert_pem: Some(pki.ca_cert_pem.clone()),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
        0,
    )
    .await
    .unwrap();

    dav.mkdir("odd names").await.unwrap();

    let names = [
        "plain name.txt",
        "100% done.txt",
        "what?.txt",
        "hash#.txt",
        "a&b c.txt",
    ];
    for name in names {
        let path = format!("odd names/{name}");
        upload_bytes(&dav, &path, name.as_bytes(), TransferRequest::default())
            .await
            .unwrap_or_else(|e| panic!("uploading {name} failed: {e}"));
        let bytes = download_bytes(&dav, &path, TransferRequest::default())
            .await
            .unwrap_or_else(|e| panic!("downloading {name} failed: {e}"));
        assert_eq!(bytes, name.as_bytes(), "the bytes of {name} must survive");
    }

    let items = dav.list_dir("odd names").await.unwrap();
    let mut listed: Vec<String> = items.iter().map(|i| i.name.clone()).collect();
    listed.sort();
    let mut expected: Vec<String> = names.iter().map(|n| n.to_string()).collect();
    expected.sort();
    assert_eq!(
        listed, expected,
        "the listing must show the names as they were written"
    );

    dav.close().await.unwrap();
}

/// A collection that still holds a member is refused, and the refusal does
/// not empty it: a server that removed the members first would leave a
/// half-deleted tree behind. A path the server does not have is told apart
/// from an empty one.
#[tokio::test]
async fn dav_a_non_empty_collection_is_refused_and_a_missing_path_is_told_apart() {
    let pki = common::generate_test_tls_pki(6);
    let store = Arc::new(Mutex::new(MockDavStore::new()));
    let router = Router::new()
        .fallback(handle_mock_dav)
        .with_state(Arc::clone(&store));
    let port = spawn_https_router(router, &pki).await;

    let dav = WebDavSession::connect(
        WebDavConnectConfig {
            scheme: ProtocolScheme::Webdavs,
            host: "localhost".to_string(),
            port,
            base_path: "/dav".to_string(),
            tls: TlsSettings {
                ca_cert_pem: Some(pki.ca_cert_pem.clone()),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
        0,
    )
    .await
    .unwrap();

    dav.mkdir("full").await.unwrap();
    upload_bytes(
        &dav,
        "full/child.txt",
        b"child",
        TransferRequest::default(),
    )
    .await
    .unwrap();

    let refused = dav
        .remove_dir("full")
        .await
        .expect_err("a collection that still holds a member must be refused");
    assert!(
        refused.to_string().contains("not empty"),
        "the refusal must name the reason: {refused}"
    );
    let items = dav.list_dir("full").await.unwrap();
    assert_eq!(
        items.len(),
        1,
        "the refusal must not have emptied the collection"
    );
    assert_eq!(items[0].name, "child.txt");

    // A path the server does not have is absent, not empty and not an error.
    assert!(
        dav.stat("nowhere.txt").await.unwrap().is_none(),
        "a missing path must be reported as absent"
    );

    dav.remove_file("full/child.txt").await.unwrap();
    dav.remove_dir("full").await.unwrap();
    dav.close().await.unwrap();
}

/// A listing that says it is truncated has to name the page that follows,
/// and it must not name the page it was just given. Either mistake is an
/// error rather than a directory that quietly shows half of its contents.
#[tokio::test]
async fn s3_a_truncated_listing_without_a_usable_continuation_token_is_an_error() {
    let pki = common::generate_test_tls_pki(7);
    let state = Arc::new(Mutex::new(MockS3State::new()));
    let router = Router::new()
        .fallback(handle_mock_s3)
        .with_state(Arc::clone(&state));
    let port = spawn_https_router(router, &pki).await;

    let s3 = S3Session::connect(
        S3ConnectConfig {
            use_https: true,
            host: "localhost".to_string(),
            port,
            region: Some("us-east-1".to_string()),
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: Zeroizing::new(
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            ),
            path_style: true,
            tls: TlsSettings {
                pinned_public_key: Some(pki.server_spki_pin.clone()),
                ca_cert_pem: Some(pki.ca_cert_pem.clone()),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
        0,
    )
    .await
    .unwrap();

    upload_bytes(
        &s3,
        "/alpha-bucket/releases/changelog.txt",
        b"Release 1.0 notes",
        TransferRequest::default(),
    )
    .await
    .unwrap();

    state.lock().await.pagination_mode = PaginationMode::TruncatedWithoutToken;
    let without_token = s3
        .list_dir("/alpha-bucket/releases")
        .await
        .expect_err("a truncated listing without a continuation token must be an error");
    assert!(
        without_token.to_string().contains("no continuation token"),
        "the error must name the reason: {without_token}"
    );

    state.lock().await.pagination_mode = PaginationMode::RepeatedToken;
    let repeated = s3
        .list_dir("/alpha-bucket/releases")
        .await
        .expect_err("a listing that repeats its continuation token must be an error");
    assert!(
        repeated.to_string().contains("repeated a continuation token"),
        "the error must name the reason: {repeated}"
    );

    state.lock().await.pagination_mode = PaginationMode::Normal;
    let items = s3.list_dir("/alpha-bucket/releases").await.unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].name, "changelog.txt");

    s3.close().await.unwrap();
}

/// An interrupted multipart upload keeps the parts it finished in a local
/// sidecar, so a later run resumes instead of starting over. A failure the
/// server hides inside a successful status still fails the upload, and the
/// unfinished upload is aborted rather than left behind. A copy of an object
/// over the threshold goes through multipart `UploadPartCopy`, so the bytes
/// never travel through this client.
#[tokio::test]
async fn s3_multipart_resumes_from_its_sidecar_and_refuses_a_hidden_completion_failure() {
    let pki = common::generate_test_tls_pki(8);
    let state = Arc::new(Mutex::new(MockS3State::new()));
    let router = Router::new()
        .fallback(handle_mock_s3)
        .with_state(Arc::clone(&state));
    let port = spawn_https_router(router, &pki).await;

    let dir = tempfile::tempdir().expect("temp dir");
    let sidecar_path = dir.path().join("resume.json");

    let connect_with = |store: Arc<MultipartResumeStore>, key: &'static str| {
        let ca_cert_pem = pki.ca_cert_pem.clone();
        let pin = pki.server_spki_pin.clone();
        let port = port;
        async move {
            S3Session::connect(
                S3ConnectConfig {
                    use_https: true,
                    host: "localhost".to_string(),
                    port,
                    region: Some("us-east-1".to_string()),
                    access_key_id: key.to_string(),
                    secret_access_key: Zeroizing::new(
                        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
                    ),
                    path_style: true,
                    multipart_threshold: 16 * 1024,
                    min_part_size: 8 * 1024,
                    abort_multipart_on_error: false,
                    resume_store: store,
                    tls: TlsSettings {
                        pinned_public_key: Some(pin),
                        ca_cert_pem: Some(ca_cert_pem),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                None,
                0,
            )
            .await
        }
    };

    // Credentials the server does not accept are refused by the server.
    let wrong_key = connect_with(
        MultipartResumeStore::new_in_memory(),
        "AKIAWRONGKEYEXAMPLE",
    )
    .await
    .expect("the connection itself is established");
    let refused = upload_bytes(
        &wrong_key,
        "/alpha-bucket/releases/refused.txt",
        b"wrong credentials",
        TransferRequest::default(),
    )
    .await
    .expect_err("a request signed with the wrong key must be refused");
    assert!(
        refused.to_string().contains("SignatureDoesNotMatch"),
        "the refusal must name the reason: {refused}"
    );
    wrong_key.close().await.unwrap();

    let payload: Vec<u8> = (0..(20 * 1024)).map(|i| (i % 251) as u8).collect();

    // The first attempt is interrupted after its first part.
    let store = MultipartResumeStore::with_sidecar_file(sidecar_path.clone());
    let s3 = connect_with(Arc::clone(&store), "AKIAIOSFODNN7EXAMPLE")
        .await
        .expect("connect");
    let interrupted = upload_bytes(
        &s3,
        "/alpha-bucket/releases/bundle.bin",
        &payload,
        TransferRequest::default(),
    )
    .await;
    assert!(interrupted.is_err(), "the interrupted upload must fail");
    assert_eq!(
        state.lock().await.part_1_uploads.load(Ordering::SeqCst),
        1,
        "the first part was uploaded once"
    );
    assert!(
        sidecar_path.exists(),
        "the finished part must be kept in a local sidecar"
    );

    // A later run, with a store built over that sidecar, resumes the upload.
    let resumed_store = MultipartResumeStore::with_sidecar_file(sidecar_path.clone());
    let resumed = connect_with(Arc::clone(&resumed_store), "AKIAIOSFODNN7EXAMPLE")
        .await
        .expect("connect");
    upload_bytes(
        &resumed,
        "/alpha-bucket/releases/bundle.bin",
        &payload,
        TransferRequest::default(),
    )
    .await
    .expect("the resumed upload succeeds");
    assert_eq!(
        state.lock().await.part_1_uploads.load(Ordering::SeqCst),
        1,
        "the resumed upload must not send the first part again"
    );
    let reassembled = download_bytes(
        &resumed,
        "/alpha-bucket/releases/bundle.bin",
        TransferRequest::default(),
    )
    .await
    .unwrap();
    assert_eq!(reassembled, payload);

    // An older, hashless checkpoint must reupload its part after restart.
    state.lock().await.fail_part_2_once.store(true, Ordering::SeqCst);
    let target = "/alpha-bucket/releases/hashless.bin";
    let before = state.lock().await.part_1_uploads.load(Ordering::SeqCst);
    assert!(upload_bytes(&resumed, target, &payload, TransferRequest::default()).await.is_err());
    let mut sidecar: serde_json::Value = serde_json::from_slice(&std::fs::read(&sidecar_path).unwrap()).unwrap();
    for checkpoint in sidecar.as_object_mut().unwrap().values_mut() {
        checkpoint.as_object_mut().unwrap().remove("completed_part_sha256");
    }
    std::fs::write(&sidecar_path, serde_json::to_vec(&sidecar).unwrap()).unwrap();
    let legacy = connect_with(MultipartResumeStore::with_sidecar_file(sidecar_path.clone()), "AKIAIOSFODNN7EXAMPLE").await.unwrap();
    upload_bytes(&legacy, target, &payload, TransferRequest::default()).await.unwrap();
    assert_eq!(state.lock().await.part_1_uploads.load(Ordering::SeqCst), before + 2,
        "hashless parts must not be silently reused");
    assert_eq!(download_bytes(&legacy, target, TransferRequest::default()).await.unwrap(), payload);

    // A failure the server reports inside a successful status still fails.
    state.lock().await.complete_reports_error.store(true, Ordering::SeqCst);
    let hidden = upload_bytes(
        &resumed,
        "/alpha-bucket/releases/hidden-failure.bin",
        &payload,
        TransferRequest::default(),
    )
    .await;
    assert!(
        hidden.is_err(),
        "a completion error inside a successful status must fail the upload"
    );
    assert!(
        state.lock().await.multiparts.is_empty(),
        "the failed multipart upload must be aborted, not left behind"
    );

    // A copy of an object over the threshold is a server-side multipart copy.
    upload_bytes(
        &resumed,
        "/alpha-bucket/releases/large.bin",
        &payload,
        TransferRequest::default(),
    )
    .await
    .unwrap();
    resumed
        .copy_file(
            "/alpha-bucket/releases/large.bin",
            "/alpha-bucket/releases/large-copy.bin",
        )
        .await
        .expect("a large copy succeeds");
    let ranges = state.lock().await.copy_ranges.clone();
    assert!(
        !ranges.is_empty(),
        "a copy of an object over the threshold must use multipart UploadPartCopy"
    );
    let copied = download_bytes(
        &resumed,
        "/alpha-bucket/releases/large-copy.bin",
        TransferRequest::default(),
    )
    .await
    .unwrap();
    assert_eq!(copied, payload, "the copy must be byte-exact");

    resumed.close().await.unwrap();
}
