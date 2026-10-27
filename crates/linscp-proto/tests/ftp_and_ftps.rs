//! End-to-end loopback integration suite for Phase 2d (`ftp` and `listing`):
//! - Plain `ftp://`, Explicit FTPS (`ftpes://`: `AUTH TLS` + `PBSZ 0` + `PROT P`
//!   on BOTH control and data sockets), and Implicit FTPS (`ftps://`)
//! - Custom `rustls` SPKI SHA-256 `PinnedPublicKey` verified across FTPS control
//!   and data TLS handshakes (and rejecting mismatched pins)
//! - `MLSD` / `MLST` structured facts AND `LIST` fallback dialects (Unix, DOS/IIS,
//!   and OpenVMS)
//! - Passive (`EPSV` + `PASV` with unroutable IPv4 rescued by `FtpForcePasvIp`)
//!   AND Active (`PORT` / `EPRT`) data channels
//! - `RETR` + `REST` resume, `STOR`, `APPE`, `MKD`, `RMD`, `DELE`, `RNFR`/`RNTO`,
//!   and `SITE CHMOD`

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use linscp_proto::ftp::{FtpConnectConfig, FtpSession};
use linscp_proto::tls::TlsSettings;
use linscp_proto::{download_bytes, upload_bytes, RemoteSession, TransferRequest};
use linscp_types::ProtocolScheme;
use rustls::ServerConfig;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ListDialect {
    Mlsd,
    Dos,
    Vms,
}

#[derive(Clone)]
struct MockFtpNode {
    is_dir: bool,
    data: Vec<u8>,
    mode: u32,
}

struct MockFtpServerState {
    nodes: HashMap<String, MockFtpNode>,
    dialect: ListDialect,
    /// When `true`, rejects `EPSV` and answers `PASV` with unroutable `10.99.88.77`
    /// so `FtpForcePasvIp` must rewrite the data host to `127.0.0.1`!
    simulate_unroutable_pasv: bool,
}

impl MockFtpServerState {
    fn new(dialect: ListDialect, simulate_unroutable_pasv: bool) -> Self {
        let mut nodes = HashMap::new();
        nodes.insert(
            "/".to_string(),
            MockFtpNode {
                is_dir: true,
                data: Vec::new(),
                mode: 0o755,
            },
        );
        Self {
            nodes,
            dialect,
            simulate_unroutable_pasv,
        }
    }
}

fn norm_ftp(p: &str) -> String {
    if p.is_empty() || p == "." {
        return "/".to_string();
    }
    let clean = p.trim_end_matches('/');
    if clean.is_empty() {
        "/".to_string()
    } else if clean.starts_with('/') {
        clean.to_string()
    } else {
        format!("/{clean}")
    }
}

enum ServerCtrl {
    Plain(BufReader<TcpStream>),
    Tls(Box<BufReader<ServerTlsStream<TcpStream>>>),
    Empty,
}

impl ServerCtrl {
    async fn read_line(&mut self) -> std::io::Result<String> {
        let mut s = String::new();
        let n = match self {
            Self::Plain(r) => r.read_line(&mut s).await?,
            Self::Tls(r) => r.read_line(&mut s).await?,
            Self::Empty => 0,
        };
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof",
            ));
        }
        Ok(s)
    }

    async fn send(&mut self, text: &str) -> std::io::Result<()> {
        match self {
            Self::Plain(r) => {
                r.get_mut().write_all(text.as_bytes()).await?;
                r.get_mut().flush().await
            }
            Self::Tls(r) => {
                r.get_mut().write_all(text.as_bytes()).await?;
                r.get_mut().flush().await
            }
            Self::Empty => Ok(()),
        }
    }

    async fn upgrade(&mut self, acceptor: &TlsAcceptor) -> std::io::Result<()> {
        let prev = std::mem::replace(self, Self::Empty);
        if let Self::Plain(br) = prev {
            let tls = acceptor.accept(br.into_inner()).await?;
            *self = Self::Tls(Box::new(BufReader::new(tls)));
        }
        Ok(())
    }
}

enum PendingData {
    Passive(TcpListener),
    Active(String, u16),
}

async fn open_server_data(
    pending: PendingData,
    tls_acceptor: Option<&TlsAcceptor>,
) -> std::io::Result<ServerData> {
    let tcp = match pending {
        PendingData::Passive(listener) => listener.accept().await?.0,
        PendingData::Active(host, port) => TcpStream::connect((host.as_str(), port)).await?,
    };
    if let Some(acc) = tls_acceptor {
        let tls = acc.accept(tcp).await?;
        Ok(ServerData::Tls(Box::new(tls)))
    } else {
        Ok(ServerData::Plain(tcp))
    }
}

enum ServerData {
    Plain(TcpStream),
    Tls(Box<ServerTlsStream<TcpStream>>),
}

impl ServerData {
    async fn write_all_and_close(self, bytes: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Plain(mut s) => {
                s.write_all(bytes).await?;
                s.shutdown().await
            }
            Self::Tls(mut s) => {
                s.write_all(bytes).await?;
                s.shutdown().await
            }
        }
    }

    async fn read_all(self) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            Self::Plain(mut s) => {
                s.read_to_end(&mut out).await?;
            }
            Self::Tls(mut s) => {
                s.read_to_end(&mut out).await?;
            }
        }
        Ok(out)
    }
}

async fn start_mock_ftp_server(
    implicit_tls: bool,
    tls_cfg: Option<Arc<ServerConfig>>,
    dialect: ListDialect,
    simulate_unroutable_pasv: bool,
) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let state = Arc::new(Mutex::new(MockFtpServerState::new(
        dialect,
        simulate_unroutable_pasv,
    )));

    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let st = Arc::clone(&state);
            let tcfg = tls_cfg.clone();
            tokio::spawn(async move {
                let _ = run_mock_ftp_client(tcp, implicit_tls, tcfg, st).await;
            });
        }
    });
    port
}

async fn run_mock_ftp_client(
    tcp: TcpStream,
    implicit_tls: bool,
    tls_cfg: Option<Arc<ServerConfig>>,
    state: Arc<Mutex<MockFtpServerState>>,
) -> std::io::Result<()> {
    let acceptor = tls_cfg.map(TlsAcceptor::from);
    let mut ctrl = if implicit_tls {
        let tls = acceptor.as_ref().unwrap().accept(tcp).await?;
        ServerCtrl::Tls(Box::new(BufReader::new(tls)))
    } else {
        ServerCtrl::Plain(BufReader::new(tcp))
    };

    ctrl.send("220 LinSCP Pure-Rust Mock FTP Ready\r\n").await?;

    let mut prot_p = false;
    let mut rest_offset = 0usize;
    let mut rnfr_path: Option<String> = None;
    let mut pending_data: Option<PendingData> = None;

    loop {
        let Ok(raw_line) = ctrl.read_line().await else {
            return Ok(());
        };
        let line = raw_line.trim_end_matches(['\r', '\n']);
        let (verb, arg) = match line.split_once(' ') {
            Some((v, a)) => (v.to_ascii_uppercase(), a.trim()),
            None => (line.to_ascii_uppercase(), ""),
        };

        match verb.as_str() {
            "AUTH" if arg.eq_ignore_ascii_case("TLS") => {
                if let Some(acc) = &acceptor {
                    ctrl.send("234 Proceed with TLS negotiation\r\n").await?;
                    ctrl.upgrade(acc).await?;
                } else {
                    ctrl.send("502 TLS not configured\r\n").await?;
                }
            }
            "USER" => ctrl.send("331 Password required\r\n").await?,
            "PASS" => ctrl.send("230 Logged in\r\n").await?,
            "PBSZ" => ctrl.send("200 PBSZ=0\r\n").await?,
            "PROT" => {
                prot_p = arg.eq_ignore_ascii_case("P");
                ctrl.send("200 Protection level set\r\n").await?;
            }
            "FEAT" => {
                let dialect = state.lock().await.dialect;
                if dialect == ListDialect::Mlsd {
                    ctrl.send("211-Features:\r\n MLST type*;size*;modify*;unix.mode*;\r\n SIZE\r\n MDTM\r\n UTF8\r\n REST STREAM\r\n211 End\r\n").await?;
                } else {
                    ctrl.send("211-Features:\r\n SIZE\r\n MDTM\r\n UTF8\r\n REST STREAM\r\n211 End\r\n").await?;
                }
            }
            "OPTS" | "TYPE" => ctrl.send("200 OK\r\n").await?,
            "PWD" => ctrl.send("257 \"/\" is current directory\r\n").await?,
            "EPSV" => {
                if state.lock().await.simulate_unroutable_pasv {
                    ctrl.send("502 EPSV disabled to test PASV\r\n").await?;
                } else {
                    let dl = TcpListener::bind("127.0.0.1:0").await?;
                    let dport = dl.local_addr()?.port();
                    pending_data = Some(PendingData::Passive(dl));
                    ctrl.send(&format!(
                        "229 Entering Extended Passive Mode (|||{dport}|)\r\n"
                    ))
                    .await?;
                }
            }
            "PASV" => {
                let dl = TcpListener::bind("127.0.0.1:0").await?;
                let dport = dl.local_addr()?.port();
                let unroutable = state.lock().await.simulate_unroutable_pasv;
                pending_data = Some(PendingData::Passive(dl));
                let ip_part = if unroutable {
                    "10,99,88,77"
                } else {
                    "127,0,0,1"
                };
                ctrl.send(&format!(
                    "227 Entering Passive Mode ({ip_part},{},{}).\r\n",
                    dport / 256,
                    dport % 256
                ))
                .await?;
            }
            "PORT" => {
                let nums: Vec<u16> = arg
                    .split(',')
                    .filter_map(|t| t.trim().parse().ok())
                    .collect();
                if nums.len() == 6 {
                    let host = format!("{}.{}.{}.{}", nums[0], nums[1], nums[2], nums[3]);
                    let port = nums[4] * 256 + nums[5];
                    pending_data = Some(PendingData::Active(host, port));
                    ctrl.send("200 PORT command successful\r\n").await?;
                } else {
                    ctrl.send("501 Syntax error\r\n").await?;
                }
            }
            "EPRT" => {
                let parts: Vec<&str> = arg.split('|').collect();
                if parts.len() >= 4 {
                    let host = parts[2].to_string();
                    let port: u16 = parts[3].parse().unwrap_or(0);
                    pending_data = Some(PendingData::Active(host, port));
                    ctrl.send("200 EPRT command successful\r\n").await?;
                } else {
                    ctrl.send("501 Syntax error\r\n").await?;
                }
            }
            "REST" => {
                rest_offset = arg.parse().unwrap_or(0);
                ctrl.send("350 Restarting at offset\r\n").await?;
            }
            "SIZE" => {
                let p = norm_ftp(arg);
                let guard = state.lock().await;
                match guard.nodes.get(&p) {
                    Some(n) if !n.is_dir => {
                        ctrl.send(&format!("213 {}\r\n", n.data.len())).await?
                    }
                    _ => ctrl.send("550 Not a plain file\r\n").await?,
                }
            }
            "MDTM" => {
                let p = norm_ftp(arg);
                if state.lock().await.nodes.contains_key(&p) {
                    ctrl.send("213 20260315120000\r\n").await?;
                } else {
                    ctrl.send("550 Missing\r\n").await?;
                }
            }
            "MLST" => {
                let p = norm_ftp(arg);
                let guard = state.lock().await;
                if let Some(n) = guard.nodes.get(&p) {
                    let kind = if n.is_dir { "dir" } else { "file" };
                    let leaf = p.rsplit('/').next().filter(|s| !s.is_empty()).unwrap_or("/");
                    ctrl.send(&format!(
                        "250-Listing\r\n type={kind};size={};modify=20260315120000;unix.mode={:04o}; {leaf}\r\n250 End\r\n",
                        n.data.len(),
                        n.mode
                    ))
                    .await?;
                } else {
                    ctrl.send("550 Missing\r\n").await?;
                }
            }
            "MLSD" | "LIST" => {
                let dir = norm_ftp(arg);
                let Some(pd) = pending_data.take() else {
                    ctrl.send("425 Use PASV or PORT first\r\n").await?;
                    continue;
                };
                ctrl.send("150 Opening data connection\r\n").await?;
                let dstream =
                    open_server_data(pd, if prot_p { acceptor.as_ref() } else { None }).await?;

                let guard = state.lock().await;
                let prefix = if dir == "/" {
                    "/".to_string()
                } else {
                    format!("{dir}/")
                };
                let mut payload = String::new();
                for (k, v) in &guard.nodes {
                    if k == &dir {
                        continue;
                    }
                    if let Some(name) = k.strip_prefix(&prefix) {
                        if !name.is_empty() && !name.contains('/') {
                            if verb == "MLSD" {
                                let t = if v.is_dir { "dir" } else { "file" };
                                payload.push_str(&format!(
                                    "type={t};size={};modify=20260315120000;unix.mode={:04o}; {name}\r\n",
                                    v.data.len(),
                                    v.mode
                                ));
                            } else {
                                match guard.dialect {
                                    ListDialect::Dos => {
                                        if v.is_dir {
                                            payload.push_str(&format!(
                                                "03-15-26  12:00 PM       <DIR>          {name}\r\n"
                                            ));
                                        } else {
                                            payload.push_str(&format!(
                                                "03-15-26  12:00 PM             {} {name}\r\n",
                                                v.data.len()
                                            ));
                                        }
                                    }
                                    ListDialect::Vms => {
                                        if v.is_dir {
                                            payload.push_str(&format!(
                                                "{name}.DIR;1   1  15-MAR-2026 12:00:00 [OWNER] (RWED,RWED,RE,RE)\r\n"
                                            ));
                                        } else {
                                            let blocks = (v.data.len() / 512).max(1);
                                            payload.push_str(&format!(
                                                "{name};1   {blocks}  15-MAR-2026 12:00:00 [OWNER] (RWED,RWED,RE,R)\r\n"
                                            ));
                                        }
                                    }
                                    ListDialect::Mlsd => {
                                        let kind_ch = if v.is_dir { 'd' } else { '-' };
                                        payload.push_str(&format!(
                                            "{kind_ch}rw-r--r-- 1 ftp ftp {} Mar 15 12:00 {name}\r\n",
                                            v.data.len()
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
                drop(guard);
                dstream.write_all_and_close(payload.as_bytes()).await?;
                ctrl.send("226 Directory send OK\r\n").await?;
            }
            "RETR" => {
                let p = norm_ftp(arg);
                let Some(pd) = pending_data.take() else {
                    ctrl.send("425 Use PASV or PORT first\r\n").await?;
                    continue;
                };
                let bytes_opt = state
                    .lock()
                    .await
                    .nodes
                    .get(&p)
                    .map(|n| n.data[rest_offset.min(n.data.len())..].to_vec());
                rest_offset = 0;
                let Some(bytes) = bytes_opt else {
                    ctrl.send("550 Missing file\r\n").await?;
                    continue;
                };
                ctrl.send("150 Opening BINARY data connection\r\n").await?;
                let dstream =
                    open_server_data(pd, if prot_p { acceptor.as_ref() } else { None }).await?;
                dstream.write_all_and_close(&bytes).await?;
                ctrl.send("226 Transfer complete\r\n").await?;
            }
            "STOR" | "APPE" => {
                let p = norm_ftp(arg);
                let Some(pd) = pending_data.take() else {
                    ctrl.send("425 Use PASV or PORT first\r\n").await?;
                    continue;
                };
                ctrl.send("150 Ready to receive data\r\n").await?;
                let dstream =
                    open_server_data(pd, if prot_p { acceptor.as_ref() } else { None }).await?;
                let incoming = dstream.read_all().await?;
                let mut guard = state.lock().await;
                let entry = guard.nodes.entry(p).or_insert(MockFtpNode {
                    is_dir: false,
                    data: Vec::new(),
                    mode: 0o644,
                });
                if verb == "APPE" {
                    entry.data.extend_from_slice(&incoming);
                } else if rest_offset > 0 {
                    if rest_offset > entry.data.len() {
                        entry.data.resize(rest_offset, 0);
                    }
                    entry.data.truncate(rest_offset);
                    entry.data.extend_from_slice(&incoming);
                } else {
                    entry.data = incoming;
                }
                rest_offset = 0;
                drop(guard);
                ctrl.send("226 Transfer complete\r\n").await?;
            }
            "MKD" => {
                state.lock().await.nodes.insert(
                    norm_ftp(arg),
                    MockFtpNode {
                        is_dir: true,
                        data: Vec::new(),
                        mode: 0o755,
                    },
                );
                ctrl.send("257 Directory created\r\n").await?;
            }
            "DELE" | "RMD" => {
                if state.lock().await.nodes.remove(&norm_ftp(arg)).is_some() {
                    ctrl.send("250 Deleted\r\n").await?;
                } else {
                    ctrl.send("550 Missing\r\n").await?;
                }
            }
            "RNFR" => {
                rnfr_path = Some(norm_ftp(arg));
                ctrl.send("350 Ready for RNTO\r\n").await?;
            }
            "RNTO" => {
                if let Some(src) = rnfr_path.take() {
                    let mut guard = state.lock().await;
                    if let Some(node) = guard.nodes.remove(&src) {
                        guard.nodes.insert(norm_ftp(arg), node);
                        ctrl.send("250 Rename successful\r\n").await?;
                        continue;
                    }
                }
                ctrl.send("550 Rename failed\r\n").await?;
            }
            "SITE" => {
                let mut sp = arg.splitn(3, ' ');
                let sub = sp.next().unwrap_or("");
                let mode_s = sp.next().unwrap_or("0644");
                let path_s = sp.next().unwrap_or("");
                if sub.eq_ignore_ascii_case("CHMOD") {
                    if let Some(n) = state.lock().await.nodes.get_mut(&norm_ftp(path_s)) {
                        n.mode = u32::from_str_radix(mode_s, 8).unwrap_or(0o644);
                        ctrl.send("200 SITE CHMOD ok\r\n").await?;
                        continue;
                    }
                }
                ctrl.send("500 Unsupported SITE\r\n").await?;
            }
            "QUIT" => {
                let _ = ctrl.send("221 Goodbye\r\n").await;
                return Ok(());
            }
            _ => ctrl.send("502 Command not implemented\r\n").await?,
        }
    }
}

#[tokio::test]
async fn plain_ftp_force_pasv_ip_active_port_and_dos_vms_listings_succeed() {
    // 1. Plain FTP with unroutable PASV `10.99.88.77` rescued by `force_pasv_ip` + Active mode!
    let port = start_mock_ftp_server(false, None, ListDialect::Mlsd, true).await;
    let ftp = FtpSession::connect(
        FtpConnectConfig {
            scheme: ProtocolScheme::Ftp,
            host: "127.0.0.1".to_string(),
            port,
            username: "ftpuser".to_string(),
            password: Some(Zeroizing::new("secret".to_string())),
            pasv_mode: true,
            force_pasv_ip: true,
            use_mlsd: true,
            ..Default::default()
        },
        None,
        0,
    )
    .await
    .expect("connect plain FTP");

    ftp.mkdir("/incoming").await.unwrap();
    upload_bytes(
        &ftp,
        "/incoming/report.txt",
        b"First half -- ",
        TransferRequest::default(),
    )
    .await
    .unwrap();
    upload_bytes(
        &ftp,
        "/incoming/report.txt",
        b"Appended second half!",
        TransferRequest {
            append: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let items = ftp.list_dir("/incoming").await.unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].name, "report.txt");
    assert_eq!(items[0].size, 35);

    let tail = download_bytes(
        &ftp,
        "/incoming/report.txt",
        TransferRequest {
            resume_offset: 14,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(tail, b"Appended second half!");

    ftp.chmod("/incoming/report.txt", 0o600).await.unwrap();
    let st = ftp.stat("/incoming/report.txt").await.unwrap().unwrap();
    assert_eq!(st.permissions, "-rw-------");

    ftp.rename("/incoming/report.txt", "/incoming/final.txt")
        .await
        .unwrap();
    ftp.remove_file("/incoming/final.txt").await.unwrap();
    ftp.remove_dir("/incoming").await.unwrap();
    ftp.close().await.unwrap();

    // 2. Active mode (`pasv_mode = false` -> `PORT`) + DOS/IIS and OpenVMS `LIST` fallback!
    let dos_port = start_mock_ftp_server(false, None, ListDialect::Dos, false).await;
    let active_dos = FtpSession::connect(
        FtpConnectConfig {
            scheme: ProtocolScheme::Ftp,
            host: "127.0.0.1".to_string(),
            port: dos_port,
            username: "ftpuser".to_string(),
            password: Some(Zeroizing::new("secret".to_string())),
            pasv_mode: false,
            ..Default::default()
        },
        None,
        0,
    )
    .await
    .unwrap();
    active_dos.mkdir("/WinDir").await.unwrap();
    upload_bytes(
        &active_dos,
        "/invoice.csv",
        b"a,b,c\n1,2,3\n",
        TransferRequest::default(),
    )
    .await
    .unwrap();
    let dos_entries = active_dos.list_dir("/").await.unwrap();
    assert_eq!(dos_entries.len(), 2);
    assert!(dos_entries.iter().any(|e| e.name == "WinDir" && e.is_dir));
    assert!(dos_entries
        .iter()
        .any(|e| e.name == "invoice.csv" && e.size == 12));
    active_dos.close().await.unwrap();

    let vms_port = start_mock_ftp_server(false, None, ListDialect::Vms, false).await;
    let vms_ftp = FtpSession::connect(
        FtpConnectConfig {
            scheme: ProtocolScheme::Ftp,
            host: "127.0.0.1".to_string(),
            port: vms_port,
            username: "ftpuser".to_string(),
            password: Some(Zeroizing::new("secret".to_string())),
            ..Default::default()
        },
        None,
        0,
    )
    .await
    .unwrap();
    vms_ftp.mkdir("/SYS").await.unwrap();
    upload_bytes(
        &vms_ftp,
        "/LOGIN.COM",
        &vec![b'X'; 1024],
        TransferRequest::default(),
    )
    .await
    .unwrap();
    let vms_entries = vms_ftp.list_dir("/").await.unwrap();
    assert!(vms_entries.iter().any(|e| e.name == "SYS" && e.is_dir));
    assert!(vms_entries
        .iter()
        .any(|e| e.name == "LOGIN.COM" && !e.is_dir && e.size == 1024));
    vms_ftp.close().await.unwrap();
}

#[tokio::test]
async fn explicit_ftpes_and_implicit_ftps_enforce_spki_pinning_on_control_and_data() {
    let pki = common::generate_test_tls_pki(3);
    let ftpes_port = start_mock_ftp_server(
        false,
        Some(Arc::clone(&pki.server_config)),
        ListDialect::Mlsd,
        false,
    )
    .await;
    let ftps_port = start_mock_ftp_server(
        true,
        Some(Arc::clone(&pki.server_config)),
        ListDialect::Mlsd,
        false,
    )
    .await;

    // 1. Wrong SPKI pin on `ftpes://` MUST fail `AUTH TLS`!
    let bad_res = FtpSession::connect(
        FtpConnectConfig {
            scheme: ProtocolScheme::Ftpes,
            host: "localhost".to_string(),
            port: ftpes_port,
            username: "ftpuser".to_string(),
            password: Some(Zeroizing::new("secret".to_string())),
            tls: TlsSettings {
                pinned_public_key: Some(
                    "sha256//BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=".to_string(),
                ),
                ca_cert_pem: Some(pki.ca_cert_pem.clone()),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
        0,
    )
    .await;
    assert!(bad_res.is_err());

    // 2. Explicit `ftpes://` with valid SPKI pin upgrades BOTH control & data channels!
    let ftpes = FtpSession::connect(
        FtpConnectConfig {
            scheme: ProtocolScheme::Ftpes,
            host: "localhost".to_string(),
            port: ftpes_port,
            username: "ftpuser".to_string(),
            password: Some(Zeroizing::new("secret".to_string())),
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
    .expect("FTPES AUTH TLS + PROT P");

    let secret_bytes = b"Encrypted over Explicit FTPS (PROT P) data socket!";
    upload_bytes(
        &ftpes,
        "/vault.bin",
        secret_bytes,
        TransferRequest::default(),
    )
    .await
    .unwrap();
    let round_trip = download_bytes(&ftpes, "/vault.bin", TransferRequest::default())
        .await
        .unwrap();
    assert_eq!(round_trip, secret_bytes);
    ftpes.close().await.unwrap();

    // 3. Implicit `ftps://` (TLS from byte 0) with valid SPKI pin!
    let ftps = FtpSession::connect(
        FtpConnectConfig {
            scheme: ProtocolScheme::Ftps,
            host: "localhost".to_string(),
            port: ftps_port,
            username: "ftpuser".to_string(),
            password: Some(Zeroizing::new("secret".to_string())),
            tls: TlsSettings {
                pinned_public_key: Some(pki.server_spki_pin),
                ca_cert_pem: Some(pki.ca_cert_pem),
                ..Default::default()
            },
            ..Default::default()
        },
        None,
        0,
    )
    .await
    .expect("Implicit FTPS");

    upload_bytes(
        &ftps,
        "/implicit.txt",
        b"Implicit FTPS payload",
        TransferRequest::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        download_bytes(&ftps, "/implicit.txt", TransferRequest::default())
            .await
            .unwrap(),
        b"Implicit FTPS payload"
    );
    ftps.close().await.unwrap();
}
