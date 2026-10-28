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

mod common;

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
use linscp_proto::{download_bytes, upload_bytes, RemoteSession, TransferRequest};
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
                        let slice = res.data[off.min(res.data.len())..].to_vec();
                        return (StatusCode::PARTIAL_CONTENT, slice).into_response();
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

    dav.set_etag_precondition(
        "project/spec.txt",
        Some(DavEtagPrecondition {
            if_match: Some(current_etag),
            if_none_match: None,
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

struct MockS3State {
    buckets: HashMap<String, BTreeMap<String, Vec<MockS3VersionEntry>>>,
    multiparts: HashMap<String, BTreeMap<u32, (String, Vec<u8>)>>,
    next_ver: u64,
    next_upload: u64,
    fail_part_2_once: AtomicBool,
    part_1_uploads: AtomicUsize,
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
        if method == Method::PUT {
            state.lock().await.buckets.entry(bucket).or_default();
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
            xml.push_str("</ListBucketResult>");
            return (StatusCode::OK, xml).into_response();
        }
    }

    // Multipart upload endpoints
    if method == Method::POST && qmap.contains_key("uploads") {
        let mut guard = state.lock().await;
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
    s3.close().await.unwrap();
}
