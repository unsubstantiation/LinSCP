#![allow(dead_code)]
//! Shared in-memory fixtures for LinSCP's integration tests: a mock SSH server
//! speaking SFTP v3 (plus the OpenSSH `posix-rename`, `copy-data` and
//! `check-file-name` extensions), an SCP sink/source and shell-command handler,
//! and the TLS/SSH key material the WebDAV and SFTP suites need.
//!
//! This crate exists so integration tests in different crates can drive the
//! same mock instead of growing private copies. It is never linked into a
//! shipped build: only `[dev-dependencies]` reference it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use linscp_crypto::digests::{compute_digest, DigestAlgorithm};
use linscp_proto::listing::{permissions_string, S_IFDIR, S_IFLNK, S_IFREG};
use linscp_proto::sftp::{
    SftpPacketReader, SftpPacketWriter, SftpWireAttrs,
    SSH_FILEXFER_ATTR_ACMODTIME, SSH_FILEXFER_ATTR_PERMISSIONS, SSH_FILEXFER_ATTR_SIZE,
    SSH_FXF_APPEND, SSH_FXF_CREAT, SSH_FXF_TRUNC, SSH_FXP_ATTRS, SSH_FXP_CLOSE,
    SSH_FXP_DATA, SSH_FXP_EXTENDED, SSH_FXP_EXTENDED_REPLY, SSH_FXP_HANDLE, SSH_FXP_INIT,
    SSH_FXP_LSTAT, SSH_FXP_MKDIR, SSH_FXP_NAME, SSH_FXP_OPEN, SSH_FXP_OPENDIR, SSH_FXP_READ,
    SSH_FXP_READDIR, SSH_FXP_READLINK, SSH_FXP_REALPATH, SSH_FXP_REMOVE, SSH_FXP_RENAME,
    SSH_FXP_RMDIR, SSH_FXP_SETSTAT, SSH_FXP_STAT, SSH_FXP_STATUS, SSH_FXP_SYMLINK,
    SSH_FXP_VERSION, SSH_FXP_WRITE, SSH_FX_EOF, SSH_FX_NO_SUCH_FILE, SSH_FX_OK,
    SSH_FX_OP_UNSUPPORTED,
};
use linscp_proto::ssh::compute_ssh_fingerprints;
use linscp_proto::tls::spki_sha256_pin;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use p256::pkcs8::EncodePrivateKey;
use russh::keys::{decode_secret_key, PrivateKey, PublicKey};
use russh::server::{Auth, ChannelOpenHandle, Msg, Server as _, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId, ChannelStream};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

pub struct GeneratedSshKey {
    pub private_key: PrivateKey,
    pub openssh_pem: String,
    pub sha256_fingerprint: String,
    pub md5_fingerprint: String,
}

fn push_ssh_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn push_ssh_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    push_ssh_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

fn build_ed25519_openssh_pem(secret: &[u8; 32], public: &[u8; 32], comment: &str) -> String {
    let mut pub_blob = Vec::new();
    push_ssh_bytes(&mut pub_blob, b"ssh-ed25519");
    push_ssh_bytes(&mut pub_blob, public);

    let mut priv_section = Vec::new();
    let check_int: u32 = 0xa1b2_c3d4;
    push_ssh_u32(&mut priv_section, check_int);
    push_ssh_u32(&mut priv_section, check_int);
    push_ssh_bytes(&mut priv_section, b"ssh-ed25519");
    push_ssh_bytes(&mut priv_section, public);
    let mut keypair64 = [0u8; 64];
    keypair64[..32].copy_from_slice(secret);
    keypair64[32..].copy_from_slice(public);
    push_ssh_bytes(&mut priv_section, &keypair64);
    push_ssh_bytes(&mut priv_section, comment.as_bytes());
    let pad_len = (8 - (priv_section.len() % 8)) % 8;
    for p in 1..=pad_len {
        priv_section.push(p as u8);
    }

    let mut wire = Vec::new();
    wire.extend_from_slice(b"openssh-key-v1\0");
    push_ssh_bytes(&mut wire, b"none");
    push_ssh_bytes(&mut wire, b"none");
    push_ssh_bytes(&mut wire, b"");
    push_ssh_u32(&mut wire, 1);
    push_ssh_bytes(&mut wire, &pub_blob);
    push_ssh_bytes(&mut wire, &priv_section);

    let b64 = BASE64.encode(&wire);
    let mut pem = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    pem
}

pub fn generate_ed25519_ssh_key(seed_byte: u8, comment: &str) -> GeneratedSshKey {
    let secret = [seed_byte; 32];
    let dalek = Ed25519SigningKey::from_bytes(&secret);
    let public = dalek.verifying_key().to_bytes();
    let openssh_pem = build_ed25519_openssh_pem(&secret, &public, comment);
    let private_key = decode_secret_key(&openssh_pem, None).expect("decode russh PrivateKey");
    let (_alg, sha256_fingerprint, md5_fingerprint) =
        compute_ssh_fingerprints(private_key.public_key()).expect("compute fingerprints");
    GeneratedSshKey {
        private_key,
        openssh_pem,
        sha256_fingerprint,
        md5_fingerprint,
    }
}

pub struct GeneratedTlsPki {
    pub ca_cert_pem: Vec<u8>,
    pub server_cert_der: Vec<u8>,
    pub server_key_der: Vec<u8>,
    pub server_spki_pin: String,
    pub server_config: Arc<ServerConfig>,
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let len_bytes = der_len(content.len());
    let mut out = Vec::with_capacity(1 + len_bytes.len() + content.len());
    out.push(tag);
    out.extend_from_slice(&len_bytes);
    out.extend_from_slice(content);
    out
}

fn der_seq(items: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for item in items {
        body.extend_from_slice(item);
    }
    der_tlv(0x30, &body)
}

fn der_oid(oid: &[u8]) -> Vec<u8> {
    der_tlv(0x06, oid)
}

fn der_int(positive_be: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    if positive_be.first().is_some_and(|b| (b & 0x80) != 0) {
        v.push(0x00);
    }
    v.extend_from_slice(positive_be);
    der_tlv(0x02, &v)
}

fn der_bit_string(unused_bits: u8, bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + bytes.len());
    body.push(unused_bits);
    body.extend_from_slice(bytes);
    der_tlv(0x03, &body)
}

fn der_cn_name(cn: &str) -> Vec<u8> {
    // OID 2.5.4.3 (commonName) = 55 04 03
    let atv = der_seq(&[der_oid(&[0x55, 0x04, 0x03]), der_tlv(0x0c, cn.as_bytes())]);
    let rdn = der_tlv(0x31, &atv);
    der_seq(&[rdn])
}

fn der_p256_spki(signing_key: &P256SigningKey) -> Vec<u8> {
    // id-ecPublicKey (1.2.840.10045.2.1) + secp256r1 (1.2.840.10045.3.1.7)
    let alg = der_seq(&[
        der_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
        der_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
    ]);
    let point = signing_key.verifying_key().to_encoded_point(false);
    der_seq(&[alg, der_bit_string(0, point.as_bytes())])
}

fn sign_x509_tbs(tbs: &[u8], issuer_key: &P256SigningKey) -> Vec<u8> {
    // ecdsa-with-SHA256 (1.2.840.10045.4.3.2) without NULL parameters per RFC 5758
    let sig_alg = der_seq(&[der_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])]);
    let sig: P256Signature = issuer_key.sign(tbs);
    let sig_der = sig.to_der();
    der_seq(&[tbs.to_vec(), sig_alg, der_bit_string(0, sig_der.as_bytes())])
}

fn encode_pem(label: &str, der: &[u8]) -> Vec<u8> {
    let mut s = format!("-----BEGIN {label}-----\n");
    let b64 = BASE64.encode(der);
    for chunk in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(chunk).unwrap());
        s.push('\n');
    }
    s.push_str(&format!("-----END {label}-----\n"));
    s.into_bytes()
}

/// Generates a valid 2-certificate X.509 v3 PKI in pure Rust (Root CA + Leaf
/// TLS server certificate with `DNS:localhost` and `IP:127.0.0.1` SANs) signed
/// with ECDSA P-256 so `rustls-webpki` validates full chain + hostname checks
/// without `CaUsedAsEndEntity`.
pub fn generate_test_tls_pki(seed_offset: u8) -> GeneratedTlsPki {
    let ca_key = P256SigningKey::from_bytes(&[0x21u8.wrapping_add(seed_offset); 32].into())
        .expect("valid P-256 CA key");
    let srv_key = P256SigningKey::from_bytes(&[0x53u8.wrapping_add(seed_offset); 32].into())
        .expect("valid P-256 server key");

    let sig_alg = der_seq(&[der_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])]);
    let version_v3 = der_tlv(0xa0, &der_int(&[0x02]));
    let validity = der_seq(&[
        der_tlv(0x17, b"250101000000Z"),
        der_tlv(0x17, b"350101000000Z"),
    ]);
    let ca_name = der_cn_name("LinSCP Test Root CA");
    let srv_name = der_cn_name("localhost");

    // CA extensions: BasicConstraints(critical, CA=TRUE) + KeyUsage(critical, keyCertSign | cRLSign)
    let bc_ca = der_seq(&[
        der_oid(&[0x55, 0x1d, 0x13]),
        der_tlv(0x01, &[0xff]),
        der_tlv(0x04, &der_seq(&[der_tlv(0x01, &[0xff])])),
    ]);
    // KeyUsage bits: keyCertSign (bit 5 = 0x04) | cRLSign (bit 6 = 0x02) -> 0x06, 1 unused bit
    let ku_ca = der_seq(&[
        der_oid(&[0x55, 0x1d, 0x0f]),
        der_tlv(0x01, &[0xff]),
        der_tlv(0x04, &der_bit_string(1, &[0x06])),
    ]);
    let ca_exts = der_tlv(0xa3, &der_seq(&[bc_ca, ku_ca]));

    let ca_tbs = der_seq(&[
        version_v3.clone(),
        der_int(&[0x01, seed_offset.wrapping_add(1)]),
        sig_alg.clone(),
        ca_name.clone(),
        validity.clone(),
        ca_name.clone(),
        der_p256_spki(&ca_key),
        ca_exts,
    ]);
    let ca_cert_der = sign_x509_tbs(&ca_tbs, &ca_key);
    let ca_cert_pem = encode_pem("CERTIFICATE", &ca_cert_der);

    // Server leaf extensions:
    // 1. BasicConstraints(critical, CA=FALSE -> empty SEQUENCE)
    let bc_leaf = der_seq(&[
        der_oid(&[0x55, 0x1d, 0x13]),
        der_tlv(0x01, &[0xff]),
        der_tlv(0x04, &der_seq(&[])),
    ]);
    // 2. KeyUsage(critical, digitalSignature = bit 0 = 0x80, 7 unused bits)
    let ku_leaf = der_seq(&[
        der_oid(&[0x55, 0x1d, 0x0f]),
        der_tlv(0x01, &[0xff]),
        der_tlv(0x04, &der_bit_string(7, &[0x80])),
    ]);
    // 3. ExtendedKeyUsage(id-kp-serverAuth = 1.3.6.1.5.5.7.3.1)
    let eku_leaf = der_seq(&[
        der_oid(&[0x55, 0x1d, 0x25]),
        der_tlv(
            0x04,
            &der_seq(&[der_oid(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01])]),
        ),
    ]);
    // 4. SubjectAltName(DNS:"localhost" [2], IP:127.0.0.1 [7])
    let san_val = der_seq(&[
        der_tlv(0x82, b"localhost"),
        der_tlv(0x87, &[127, 0, 0, 1]),
    ]);
    let san_leaf = der_seq(&[der_oid(&[0x55, 0x1d, 0x11]), der_tlv(0x04, &san_val)]);
    let srv_exts = der_tlv(0xa3, &der_seq(&[bc_leaf, ku_leaf, eku_leaf, san_leaf]));

    let srv_tbs = der_seq(&[
        version_v3,
        der_int(&[0x02, seed_offset.wrapping_add(1)]),
        sig_alg,
        ca_name,
        validity,
        srv_name,
        der_p256_spki(&srv_key),
        srv_exts,
    ]);
    let server_cert_der = sign_x509_tbs(&srv_tbs, &ca_key);
    let server_spki_pin = spki_sha256_pin(&server_cert_der).expect("compute SPKI pin");

    let pkcs8_doc = srv_key.to_pkcs8_der().expect("encode server PKCS#8 DER");
    let server_key_der = pkcs8_doc.as_bytes().to_vec();

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("server TLS versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![
                CertificateDer::from(server_cert_der.clone()),
                CertificateDer::from(ca_cert_der),
            ],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key_der.clone())),
        )
        .expect("build rustls ServerConfig");

    GeneratedTlsPki {
        ca_cert_pem,
        server_cert_der,
        server_key_der,
        server_spki_pin,
        server_config: Arc::new(server_config),
    }
}

#[derive(Clone, Debug)]
pub enum MemNode {
    Dir {
        mode: u32,
        mtime: u32,
    },
    File {
        data: Vec<u8>,
        mode: u32,
        mtime: u32,
    },
    Symlink {
        target: String,
        mtime: u32,
    },
}

pub struct MemFs {
    pub nodes: HashMap<String, MemNode>,
}

impl MemFs {
    pub fn new() -> Self {
        let mut nodes = HashMap::new();
        nodes.insert(
            "/".to_string(),
            MemNode::Dir {
                mode: 0o755,
                mtime: 1_760_000_000,
            },
        );
        nodes.insert(
            "/home".to_string(),
            MemNode::Dir {
                mode: 0o755,
                mtime: 1_760_000_000,
            },
        );
        nodes.insert(
            "/home/tester".to_string(),
            MemNode::Dir {
                mode: 0o755,
                mtime: 1_760_000_000,
            },
        );
        Self { nodes }
    }

    pub fn normalize(path: &str) -> String {
        if path.is_empty() || path == "." {
            return "/home/tester".to_string();
        }
        let abs = if let Some(rel) = path.strip_prefix("./") {
            format!("/home/tester/{rel}")
        } else if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/home/tester/{path}")
        };
        let mut segs: Vec<&str> = Vec::new();
        for seg in abs.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    let _ = segs.pop();
                }
                s => segs.push(s),
            }
        }
        if segs.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", segs.join("/"))
        }
    }

    pub fn resolve_target(&self, path: &str) -> Option<String> {
        let norm = Self::normalize(path);
        match self.nodes.get(&norm)? {
            MemNode::Symlink { target, .. } => {
                let resolved = if target.starts_with('/') {
                    Self::normalize(target)
                } else {
                    let parent = norm.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
                    Self::normalize(&format!("{parent}/{target}"))
                };
                if self.nodes.contains_key(&resolved) {
                    Some(resolved)
                } else {
                    None
                }
            }
            _ => Some(norm),
        }
    }

    pub fn attrs_for(&self, path: &str, follow_links: bool) -> Option<SftpWireAttrs> {
        let key = if follow_links {
            self.resolve_target(path)?
        } else {
            Self::normalize(path)
        };
        let node = self.nodes.get(&key)?;
        match node {
            MemNode::Dir { mode, mtime } => Some(SftpWireAttrs {
                flags: SSH_FILEXFER_ATTR_SIZE
                    | SSH_FILEXFER_ATTR_PERMISSIONS
                    | SSH_FILEXFER_ATTR_ACMODTIME,
                size: 0,
                uid: 1000,
                gid: 1000,
                permissions: S_IFDIR | (*mode & 0o7777),
                atime: *mtime,
                mtime: *mtime,
            }),
            MemNode::File { data, mode, mtime } => Some(SftpWireAttrs {
                flags: SSH_FILEXFER_ATTR_SIZE
                    | SSH_FILEXFER_ATTR_PERMISSIONS
                    | SSH_FILEXFER_ATTR_ACMODTIME,
                size: data.len() as u64,
                uid: 1000,
                gid: 1000,
                permissions: S_IFREG | (*mode & 0o7777),
                atime: *mtime,
                mtime: *mtime,
            }),
            MemNode::Symlink { target, mtime } => Some(SftpWireAttrs {
                flags: SSH_FILEXFER_ATTR_SIZE
                    | SSH_FILEXFER_ATTR_PERMISSIONS
                    | SSH_FILEXFER_ATTR_ACMODTIME,
                size: target.len() as u64,
                uid: 1000,
                gid: 1000,
                permissions: S_IFLNK | 0o777,
                atime: *mtime,
                mtime: *mtime,
            }),
        }
    }

    pub fn children_of(&self, dir: &str) -> Vec<(String, SftpWireAttrs, Option<String>)> {
        let norm = Self::normalize(dir);
        let prefix = if norm == "/" {
            "/".to_string()
        } else {
            format!("{norm}/")
        };
        let mut out = Vec::new();
        for (k, v) in &self.nodes {
            if k == &norm {
                continue;
            }
            if let Some(rest) = k.strip_prefix(&prefix) {
                if !rest.is_empty() && !rest.contains('/') {
                    let sym_target = match v {
                        MemNode::Symlink { target, .. } => Some(target.clone()),
                        _ => None,
                    };
                    if let Some(attrs) = self.attrs_for(k, false) {
                        out.push((rest.to_string(), attrs, sym_target));
                    }
                }
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

#[derive(Clone)]
pub struct MockSshServer {
    pub fs: Arc<Mutex<MemFs>>,
    pub allowed_user: String,
    pub allowed_password: String,
    pub allowed_pubkey: PublicKey,
    pub allow_forwarding: bool,
    pub check_file_name: bool,
    pub copy_data: bool,
}

impl russh::server::Server for MockSshServer {
    type Handler = MockSshSession;

    fn new_client(&mut self, _peer: Option<SocketAddr>) -> Self::Handler {
        MockSshSession {
            server: self.clone(),
            channels: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

pub struct MockSshSession {
    server: MockSshServer,
    channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
}

impl russh::server::Handler for MockSshSession {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if user == self.server.allowed_user && password == self.server.allowed_password {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        if user == self.server.allowed_user
            && key.public_key.key_data() == self.server.allowed_pubkey.key_data()
        {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.lock().await.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.server.allow_forwarding {
            return Ok(());
        }
        if let Ok(mut target_tcp) =
            TcpStream::connect((host_to_connect, port_to_connect as u16)).await
        {
            let _ = target_tcp.set_nodelay(true);
            reply.accept().await;
            let mut ssh_stream = channel.into_stream();
            tokio::spawn(async move {
                let _ = tokio::io::copy_bidirectional(&mut ssh_stream, &mut target_tcp).await;
            });
        }
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name == "sftp" {
            if let Some(channel) = self.channels.lock().await.remove(&channel_id) {
                session.channel_success(channel_id)?;
                let fs = Arc::clone(&self.server.fs);
                let check_file_name = self.server.check_file_name;
                let copy_data = self.server.copy_data;
                tokio::spawn(async move {
                    let _ = serve_mock_sftp(channel.into_stream(), fs, check_file_name, copy_data).await;
                });
                return Ok(());
            }
        }
        session.channel_failure(channel_id)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(data).into_owned();
        let Some(channel) = self.channels.lock().await.remove(&channel_id) else {
            session.channel_failure(channel_id)?;
            return Ok(());
        };
        session.channel_success(channel_id)?;
        let fs = Arc::clone(&self.server.fs);
        tokio::spawn(async move {
            handle_mock_exec(channel, cmd, fs).await;
        });
        Ok(())
    }
}

fn unquote_shell_args(cmd: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut in_sq = false;
    let mut chars = cmd.chars().peekable();
    let mut had_token = false;

    while let Some(ch) = chars.next() {
        if in_sq {
            if ch == '\'' {
                in_sq = false;
            } else {
                cur.push(ch);
            }
        } else if ch == '\'' {
            in_sq = true;
            had_token = true;
        } else if ch == '\\' {
            if let Some(nxt) = chars.next() {
                cur.push(nxt);
                had_token = true;
            }
        } else if ch.is_ascii_whitespace() {
            if had_token || !cur.is_empty() {
                args.push(std::mem::take(&mut cur));
                had_token = false;
            }
        } else {
            cur.push(ch);
            had_token = true;
        }
    }
    if had_token || !cur.is_empty() {
        args.push(cur);
    }
    args
}

fn format_ls_line(name: &str, attrs: &SftpWireAttrs, sym_target: Option<&str>) -> String {
    let pstr = permissions_string(attrs.permissions);
    let display = match sym_target {
        Some(t) => format!("{name} -> {t}"),
        None => name.to_string(),
    };
    format!(
        "{pstr} 1 tester tester {} 2026-03-15 12:00:00.000000000 +0000 {display}\n",
        attrs.size
    )
}

async fn handle_mock_exec(channel: Channel<Msg>, cmd: String, fs: Arc<Mutex<MemFs>>) {
    let tokens = unquote_shell_args(&cmd);
    let mut idx = 0usize;
    if tokens.get(idx).map(String::as_str) == Some("env") {
        idx += 1;
        while tokens.get(idx).is_some_and(|t| t.contains('=')) {
            idx += 1;
        }
    }
    let prog = tokens.get(idx).map(String::as_str).unwrap_or("");
    let args = &tokens[(idx + 1).min(tokens.len())..];

    if prog == "scp" {
        let is_source = args.iter().any(|a| a == "-f");
        let is_sink = args.iter().any(|a| a == "-t");
        let preserve = args.iter().any(|a| a == "-p");
        let target = args.last().cloned().unwrap_or_default();
        let mut stream = channel.into_stream();
        if is_source {
            let _ = run_mock_scp_source(&mut stream, &target, preserve, &fs).await;
        } else if is_sink {
            let _ = run_mock_scp_sink(&mut stream, &target, &fs).await;
        }
        let _ = stream.shutdown().await;
        return;
    }

    let mut code = 0u32;
    let mut stdout = String::new();
    let mut stderr = String::new();

    if cmd.contains("__LINSCP_MONITOR_STAT") {
        stdout.push_str("__LINSCP_MONITOR_STAT\ncpu 100 0 100 800 0 0 0 0\ncpu0 100 0 100 800 0 0 0 0\n__LINSCP_MONITOR_MEMORY\nMemTotal: 1024 kB\nMemAvailable: 512 kB\n__LINSCP_MONITOR_END\n");
    } else if cmd == "__LINSCP_TEST_HANG__" {
        let _ = channel.data(b"partial" as &[u8]).await;
        tokio::time::sleep(Duration::from_secs(60)).await;
        let _ = channel.close().await;
        return;
    } else if cmd == "__LINSCP_TEST_FLOOD__" {
        let block = vec![b'x'; 64 * 1024];
        for _ in 0..1024 {
            if channel.data(block.as_slice()).await.is_err() { return; }
        }
        let _ = channel.close().await;
        return;
    } else {
        match prog {
            "pwd" => {
                stdout.push_str("/home/tester\n");
            }
            "ls" => {
                let is_dir_self = args.iter().any(|a| a == "-d");
                let path = args.last().map(String::as_str).unwrap_or(".");
                let guard = fs.lock().await;
                let norm = MemFs::normalize(path);
                if is_dir_self {
                    match guard.attrs_for(&norm, false) {
                        Some(attrs) => {
                            let sym = match guard.nodes.get(&norm) {
                                Some(MemNode::Symlink { target, .. }) => Some(target.as_str()),
                                _ => None,
                            };
                            stdout.push_str(&format_ls_line(&norm, &attrs, sym));
                        }
                        None => {
                            code = 2;
                            stderr.push_str(&format!("ls: cannot access '{path}': No such file or directory\n"));
                        }
                    }
                } else if matches!(guard.nodes.get(&norm), Some(MemNode::Dir { .. })) {
                    stdout.push_str("total 4\n");
                    for (name, attrs, sym) in guard.children_of(&norm) {
                        stdout.push_str(&format_ls_line(&name, &attrs, sym.as_deref()));
                    }
                } else {
                    code = 2;
                    stderr.push_str(&format!("ls: cannot access '{path}': No such file or directory\n"));
                }
            }
            "mkdir" => {
                let path = args.last().map(String::as_str).unwrap_or("");
                fs.lock().await.nodes.insert(
                    MemFs::normalize(path),
                    MemNode::Dir {
                        mode: 0o755,
                        mtime: 1_760_000_000,
                    },
                );
            }
            "rm" => {
                let path = args.last().map(String::as_str).unwrap_or("");
                fs.lock().await.nodes.remove(&MemFs::normalize(path));
            }
            "rmdir" => {
                let path = args.last().map(String::as_str).unwrap_or("");
                let norm = MemFs::normalize(path);
                let mut guard = fs.lock().await;
                if guard.children_of(&norm).is_empty() {
                    guard.nodes.remove(&norm);
                } else {
                    code = 1;
                    stderr.push_str("rmdir: Directory not empty\n");
                }
            }
            "mv" => {
                if args.len() >= 2 {
                    let dst = MemFs::normalize(&args[args.len() - 1]);
                    let src = MemFs::normalize(&args[args.len() - 2]);
                    let mut guard = fs.lock().await;
                    if let Some(node) = guard.nodes.remove(&src) {
                        guard.nodes.insert(dst, node);
                    } else {
                        code = 1;
                        stderr.push_str("mv: No such file or directory\n");
                    }
                }
            }
            "cp" => {
                if args.len() >= 2 {
                    let dst = MemFs::normalize(&args[args.len() - 1]);
                    let src = MemFs::normalize(&args[args.len() - 2]);
                    let mut guard = fs.lock().await;
                    if let Some(node) = guard.nodes.get(&src).cloned() {
                        guard.nodes.insert(dst, node);
                    } else {
                        code = 1;
                        stderr.push_str("cp: No such file or directory\n");
                    }
                }
            }
            "chmod" => {
                if args.len() >= 2 {
                    let path = MemFs::normalize(&args[args.len() - 1]);
                    let mode_str = &args[0];
                    let parsed_mode = u32::from_str_radix(mode_str, 8).unwrap_or(0o644);
                    let mut guard = fs.lock().await;
                    match guard.nodes.get_mut(&path) {
                        Some(MemNode::File { mode, .. }) | Some(MemNode::Dir { mode, .. }) => {
                            *mode = parsed_mode;
                        }
                        _ => {
                            code = 1;
                            stderr.push_str("chmod: No such file or directory\n");
                        }
                    }
                }
            }
            "touch" => {}
            "ln" => {
                if args.len() >= 2 {
                    let link_path = MemFs::normalize(&args[args.len() - 1]);
                    let target = args[args.len() - 2].clone();
                    fs.lock().await.nodes.insert(
                        link_path,
                        MemNode::Symlink {
                            target,
                            mtime: 1_760_000_000,
                        },
                    );
                }
            }
            "sha256sum" => {
                let path = MemFs::normalize(args.last().map(String::as_str).unwrap_or(""));
                let guard = fs.lock().await;
                if let Some(MemNode::File { data, .. }) = guard.nodes.get(&path) {
                    let hex: String = compute_digest(DigestAlgorithm::Sha256, data)
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    stdout.push_str(&format!("{hex}  {path}\n"));
                } else {
                    code = 1;
                    stderr.push_str("sha256sum: No such file\n");
                }
            }
            _ => {
                code = 127;
                stderr.push_str(&format!("{prog}: command not found\n"));
            }
        }
    }

    if !stdout.is_empty() {
        let _ = channel.data(stdout.as_bytes()).await;
    }
    if !stderr.is_empty() {
        let _ = channel.extended_data(1, stderr.as_bytes()).await;
    }
    let _ = channel.exit_status(code).await;
    let _ = channel.eof().await;
    let _ = channel.close().await;
}

async fn run_mock_scp_source(
    stream: &mut ChannelStream<Msg>,
    target: &str,
    preserve: bool,
    fs: &Arc<Mutex<MemFs>>,
) -> Result<(), std::io::Error> {
    let mut ack = [0u8; 1];
    stream.read_exact(&mut ack).await?;

    // Special path simulating a hostile SCP server attempting `../` traversal!
    if target.ends_with("malicious_escape") {
        stream.write_all(b"C0644 5 ../pwned.txt\n").await?;
        stream.flush().await?;
        return Ok(());
    }

    let norm = MemFs::normalize(target);
    let node_opt = fs.lock().await.nodes.get(&norm).cloned();
    let Some(MemNode::File { data, mode, mtime }) = node_opt else {
        stream.write_all(b"\x01scp: No such file or directory\n").await?;
        stream.flush().await?;
        return Ok(());
    };
    if preserve {
        stream
            .write_all(format!("T{mtime} 0 {mtime} 0\n").as_bytes())
            .await?;
        stream.flush().await?;
        stream.read_exact(&mut ack).await?;
    }
    let leaf = norm.rsplit('/').next().unwrap_or("file");
    stream
        .write_all(format!("C{:04o} {} {leaf}\n", mode & 0o7777, data.len()).as_bytes())
        .await?;
    stream.flush().await?;
    stream.read_exact(&mut ack).await?;

    stream.write_all(&data).await?;
    stream.write_all(&[0u8]).await?;
    stream.flush().await?;
    let _ = stream.read_exact(&mut ack).await;
    Ok(())
}

async fn run_mock_scp_sink(
    stream: &mut ChannelStream<Msg>,
    target: &str,
    fs: &Arc<Mutex<MemFs>>,
) -> Result<(), std::io::Error> {
    stream.write_all(&[0u8]).await?;
    stream.flush().await?;

    let mut mtime = 1_760_000_000u32;
    loop {
        let mut line = Vec::new();
        let mut b = [0u8; 1];
        loop {
            if stream.read_exact(&mut b).await.is_err() {
                return Ok(());
            }
            line.push(b[0]);
            if b[0] == b'\n' {
                break;
            }
        }
        let s = String::from_utf8_lossy(&line);
        let trimmed = s.trim_end_matches(['\r', '\n']);
        if let Some(rest) = trimmed.strip_prefix('T') {
            mtime = rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(mtime);
            stream.write_all(&[0u8]).await?;
            stream.flush().await?;
        } else if let Some(rest) = trimmed.strip_prefix('C') {
            let mut sp = rest.splitn(3, ' ');
            let mode = u32::from_str_radix(sp.next().unwrap_or("0644"), 8).unwrap_or(0o644);
            let sz: usize = sp.next().and_then(|v| v.parse().ok()).unwrap_or(0);
            let leaf = sp.next().unwrap_or("upload");
            stream.write_all(&[0u8]).await?;
            stream.flush().await?;

            let mut data = vec![0u8; sz];
            stream.read_exact(&mut data).await?;
            let mut trailing = [0u8; 1];
            stream.read_exact(&mut trailing).await?;

            let dest_norm = MemFs::normalize(target);
            let mut guard = fs.lock().await;
            let final_path = if matches!(guard.nodes.get(&dest_norm), Some(MemNode::Dir { .. })) {
                MemFs::normalize(&format!("{dest_norm}/{leaf}"))
            } else {
                dest_norm
            };
            guard.nodes.insert(
                final_path,
                MemNode::File {
                    data,
                    mode,
                    mtime,
                },
            );
            drop(guard);

            stream.write_all(&[0u8]).await?;
            stream.flush().await?;
            return Ok(());
        } else {
            return Ok(());
        }
    }
}

enum OpenSftpHandle {
    File { path: String, pflags: u32 },
    Dir { entries: Vec<(String, SftpWireAttrs)>, returned: bool },
}

fn sftp_status_packet(req_id: u32, code: u32, msg: &str) -> Vec<u8> {
    let mut w = SftpPacketWriter::new();
    w.push_u32(code);
    w.push_str(msg);
    w.push_str("en");
    w.into_framed_packet(SSH_FXP_STATUS, Some(req_id))
}

async fn serve_mock_sftp(
    mut stream: ChannelStream<Msg>,
    fs: Arc<Mutex<MemFs>>,
    check_file_name: bool,
    copy_data: bool,
) -> Result<(), std::io::Error> {
    let mut handles: HashMap<String, OpenSftpHandle> = HashMap::new();
    let mut next_h = 1u64;

    loop {
        let mut len_b = [0u8; 4];
        if stream.read_exact(&mut len_b).await.is_err() {
            return Ok(());
        }
        let len = u32::from_be_bytes(len_b) as usize;
        let mut pkt = vec![0u8; len];
        stream.read_exact(&mut pkt).await?;
        let ptype = pkt[0];
        let body = &pkt[1..];

        if ptype == SSH_FXP_INIT {
            let mut w = SftpPacketWriter::new();
            w.push_u32(3);
            w.push_str("posix-rename@openssh.com");
            w.push_str("1");
            if copy_data {
                w.push_str("copy-data");
                w.push_str("1");
            }
            let reply = w.into_framed_packet(SSH_FXP_VERSION, None);
            stream.write_all(&reply).await?;
            stream.flush().await?;
            continue;
        }

        let mut r = SftpPacketReader::new(body);
        let Ok(req_id) = r.read_u32() else {
            return Ok(());
        };

        let response = match ptype {
            SSH_FXP_REALPATH => {
                let raw = r.read_string_lossy().unwrap_or_default();
                let norm = MemFs::normalize(&raw);
                let mut w = SftpPacketWriter::new();
                w.push_u32(1);
                w.push_str(&norm);
                w.push_str(&norm);
                w.push_attrs(&SftpWireAttrs::default());
                w.into_framed_packet(SSH_FXP_NAME, Some(req_id))
            }
            SSH_FXP_STAT | SSH_FXP_LSTAT => {
                let raw = r.read_string_lossy().unwrap_or_default();
                let follow = ptype == SSH_FXP_STAT;
                match fs.lock().await.attrs_for(&raw, follow) {
                    Some(attrs) => {
                        let mut w = SftpPacketWriter::new();
                        w.push_attrs(&attrs);
                        w.into_framed_packet(SSH_FXP_ATTRS, Some(req_id))
                    }
                    None => sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "No such file"),
                }
            }
            SSH_FXP_OPENDIR => {
                let raw = r.read_string_lossy().unwrap_or_default();
                let norm = MemFs::normalize(&raw);
                let guard = fs.lock().await;
                if matches!(guard.nodes.get(&norm), Some(MemNode::Dir { .. })) {
                    let entries = guard
                        .children_of(&norm)
                        .into_iter()
                        .map(|(n, a, _)| (n, a))
                        .collect();
                    let hid = format!("d{next_h}");
                    next_h += 1;
                    handles.insert(
                        hid.clone(),
                        OpenSftpHandle::Dir {
                            entries,
                            returned: false,
                        },
                    );
                    let mut w = SftpPacketWriter::new();
                    w.push_str(&hid);
                    w.into_framed_packet(SSH_FXP_HANDLE, Some(req_id))
                } else {
                    sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "No such directory")
                }
            }
            SSH_FXP_READDIR => {
                let hid = r.read_string_lossy().unwrap_or_default();
                match handles.get_mut(&hid) {
                    Some(OpenSftpHandle::Dir { entries, returned }) if !*returned => {
                        *returned = true;
                        let mut w = SftpPacketWriter::new();
                        w.push_u32(entries.len() as u32);
                        for (name, attrs) in entries {
                            w.push_str(name);
                            w.push_str(name);
                            w.push_attrs(attrs);
                        }
                        w.into_framed_packet(SSH_FXP_NAME, Some(req_id))
                    }
                    Some(OpenSftpHandle::Dir { .. }) => sftp_status_packet(req_id, SSH_FX_EOF, "EOF"),
                    _ => sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Invalid handle"),
                }
            }
            SSH_FXP_OPEN => {
                let raw = r.read_string_lossy().unwrap_or_default();
                let pflags = r.read_u32().unwrap_or(0);
                let attrs = r.read_attrs().unwrap_or_default();
                let norm = MemFs::normalize(&raw);
                let mut guard = fs.lock().await;
                let exists = guard.nodes.contains_key(&norm);
                if (pflags & SSH_FXF_CREAT) != 0 {
                    if !exists || (pflags & SSH_FXF_TRUNC) != 0 {
                        let mode = if (attrs.flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0 {
                            attrs.permissions & 0o7777
                        } else {
                            0o644
                        };
                        guard.nodes.insert(
                            norm.clone(),
                            MemNode::File {
                                data: Vec::new(),
                                mode,
                                mtime: 1_760_000_000,
                            },
                        );
                    }
                } else if !exists {
                    drop(guard);
                    let pkt = sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "No such file");
                    stream.write_all(&pkt).await?;
                    stream.flush().await?;
                    continue;
                }
                drop(guard);
                let hid = format!("f{next_h}");
                next_h += 1;
                handles.insert(
                    hid.clone(),
                    OpenSftpHandle::File {
                        path: norm,
                        pflags,
                    },
                );
                let mut w = SftpPacketWriter::new();
                w.push_str(&hid);
                w.into_framed_packet(SSH_FXP_HANDLE, Some(req_id))
            }
            SSH_FXP_READ => {
                let hid = r.read_string_lossy().unwrap_or_default();
                let offset = r.read_u64().unwrap_or(0) as usize;
                let max_len = r.read_u32().unwrap_or(0) as usize;
                if let Some(OpenSftpHandle::File { path, .. }) = handles.get(&hid) {
                    let guard = fs.lock().await;
                    if let Some(MemNode::File { data, .. }) = guard.nodes.get(path) {
                        if offset >= data.len() {
                            sftp_status_packet(req_id, SSH_FX_EOF, "EOF")
                        } else {
                            let end = (offset + max_len).min(data.len());
                            let mut w = SftpPacketWriter::new();
                            w.push_bytes(&data[offset..end]);
                            w.into_framed_packet(SSH_FXP_DATA, Some(req_id))
                        }
                    } else {
                        sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Missing")
                    }
                } else {
                    sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Invalid handle")
                }
            }
            SSH_FXP_WRITE => {
                let hid = r.read_string_lossy().unwrap_or_default();
                let offset = r.read_u64().unwrap_or(0) as usize;
                let chunk = r.read_bytes().unwrap_or(&[]).to_vec();
                if let Some(OpenSftpHandle::File { path, pflags }) = handles.get(&hid) {
                    let mut guard = fs.lock().await;
                    if let Some(MemNode::File { data, .. }) = guard.nodes.get_mut(path) {
                        if (*pflags & SSH_FXF_APPEND) != 0 && offset >= data.len() {
                            data.extend_from_slice(&chunk);
                        } else {
                            if offset + chunk.len() > data.len() {
                                data.resize(offset + chunk.len(), 0);
                            }
                            data[offset..offset + chunk.len()].copy_from_slice(&chunk);
                        }
                        sftp_status_packet(req_id, SSH_FX_OK, "OK")
                    } else {
                        sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Missing")
                    }
                } else {
                    sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Invalid handle")
                }
            }
            SSH_FXP_CLOSE => {
                let hid = r.read_string_lossy().unwrap_or_default();
                handles.remove(&hid);
                sftp_status_packet(req_id, SSH_FX_OK, "OK")
            }
            SSH_FXP_MKDIR => {
                let raw = r.read_string_lossy().unwrap_or_default();
                let attrs = r.read_attrs().unwrap_or_default();
                let mode = if (attrs.flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0 {
                    attrs.permissions & 0o7777
                } else {
                    0o755
                };
                fs.lock().await.nodes.insert(
                    MemFs::normalize(&raw),
                    MemNode::Dir {
                        mode,
                        mtime: 1_760_000_000,
                    },
                );
                sftp_status_packet(req_id, SSH_FX_OK, "OK")
            }
            SSH_FXP_RMDIR | SSH_FXP_REMOVE => {
                let raw = r.read_string_lossy().unwrap_or_default();
                let norm = MemFs::normalize(&raw);
                if fs.lock().await.nodes.remove(&norm).is_some() {
                    sftp_status_packet(req_id, SSH_FX_OK, "OK")
                } else {
                    sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Missing")
                }
            }
            SSH_FXP_RENAME => {
                let from = MemFs::normalize(&r.read_string_lossy().unwrap_or_default());
                let to = MemFs::normalize(&r.read_string_lossy().unwrap_or_default());
                let mut guard = fs.lock().await;
                if let Some(node) = guard.nodes.remove(&from) {
                    guard.nodes.insert(to, node);
                    sftp_status_packet(req_id, SSH_FX_OK, "OK")
                } else {
                    sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Missing")
                }
            }
            SSH_FXP_SETSTAT => {
                let path = MemFs::normalize(&r.read_string_lossy().unwrap_or_default());
                let attrs = r.read_attrs().unwrap_or_default();
                let mut guard = fs.lock().await;
                match guard.nodes.get_mut(&path) {
                    Some(MemNode::File { mode, mtime, .. })
                    | Some(MemNode::Dir { mode, mtime }) => {
                        if (attrs.flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0 {
                            *mode = attrs.permissions & 0o7777;
                        }
                        if (attrs.flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0 {
                            *mtime = attrs.mtime;
                        }
                        sftp_status_packet(req_id, SSH_FX_OK, "OK")
                    }
                    _ => sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Missing"),
                }
            }
            SSH_FXP_SYMLINK => {
                let target = r.read_string_lossy().unwrap_or_default();
                let link_path = MemFs::normalize(&r.read_string_lossy().unwrap_or_default());
                fs.lock().await.nodes.insert(
                    link_path,
                    MemNode::Symlink {
                        target,
                        mtime: 1_760_000_000,
                    },
                );
                sftp_status_packet(req_id, SSH_FX_OK, "OK")
            }
            SSH_FXP_READLINK => {
                let link_path = MemFs::normalize(&r.read_string_lossy().unwrap_or_default());
                let guard = fs.lock().await;
                if let Some(MemNode::Symlink { target, .. }) = guard.nodes.get(&link_path) {
                    let mut w = SftpPacketWriter::new();
                    w.push_u32(1);
                    w.push_str(target);
                    w.push_str(target);
                    w.push_attrs(&SftpWireAttrs::default());
                    w.into_framed_packet(SSH_FXP_NAME, Some(req_id))
                } else {
                    sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Not a symlink")
                }
            }
            SSH_FXP_EXTENDED => {
                let ext_name = r.read_string_lossy().unwrap_or_default();
                match ext_name.as_str() {
                    "posix-rename@openssh.com" => {
                        let from = MemFs::normalize(&r.read_string_lossy().unwrap_or_default());
                        let to = MemFs::normalize(&r.read_string_lossy().unwrap_or_default());
                        let mut guard = fs.lock().await;
                        if let Some(node) = guard.nodes.remove(&from) {
                            guard.nodes.insert(to, node);
                            sftp_status_packet(req_id, SSH_FX_OK, "OK")
                        } else {
                            sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Missing")
                        }
                    }
                    "copy-data" => {
                        if !copy_data {
                            // A server without the extension reports it as unsupported
                            // so the client falls back to streaming through it.
                            sftp_status_packet(req_id, SSH_FX_OP_UNSUPPORTED, "copy-data is unsupported by this server")
                        } else {
                        let rh = r.read_string_lossy().unwrap_or_default();
                        let read_off = r.read_u64().unwrap_or(0) as usize;
                        let read_len = r.read_u64().unwrap_or(0) as usize;
                        let wh = r.read_string_lossy().unwrap_or_default();
                        let write_off = r.read_u64().unwrap_or(0) as usize;
                        let src_path = match handles.get(&rh) {
                            Some(OpenSftpHandle::File { path, .. }) => Some(path.clone()),
                            _ => None,
                        };
                        let dst_path = match handles.get(&wh) {
                            Some(OpenSftpHandle::File { path, .. }) => Some(path.clone()),
                            _ => None,
                        };
                        match (src_path, dst_path) {
                            (Some(sp), Some(dp)) => {
                                let mut guard = fs.lock().await;
                                let copied = match guard.nodes.get(&sp) {
                                    Some(MemNode::File { data, .. }) => {
                                        let end = if read_len == 0 {
                                            data.len()
                                        } else {
                                            (read_off + read_len).min(data.len())
                                        };
                                        Some(data[read_off.min(end)..end].to_vec())
                                    }
                                    _ => None,
                                };
                                match (copied, guard.nodes.get_mut(&dp)) {
                                    (Some(bytes), Some(MemNode::File { data, .. })) => {
                                        if write_off + bytes.len() > data.len() {
                                            data.resize(write_off + bytes.len(), 0);
                                        }
                                        data[write_off..write_off + bytes.len()]
                                            .copy_from_slice(&bytes);
                                        sftp_status_packet(req_id, SSH_FX_OK, "OK")
                                    }
                                    _ => sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Missing"),
                                }
                            }
                            _ => sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Bad handle"),
                        }
                        }
                    }
                    "check-file-name" => {
                        if !check_file_name {
                            // A server without the extension reports it as unsupported
                            // so the client falls back to download-and-hash.
                            sftp_status_packet(req_id, SSH_FX_OP_UNSUPPORTED, "check-file-name is unsupported by this server")
                        } else {
                        let path = MemFs::normalize(&r.read_string_lossy().unwrap_or_default());
                        let alg_list = r.read_string_lossy().unwrap_or_default();
                        let first_alg = alg_list.split(',').next().unwrap_or("sha256");
                        let parsed_alg =
                            DigestAlgorithm::parse(first_alg).unwrap_or(DigestAlgorithm::Sha256);
                        let guard = fs.lock().await;
                        if let Some(MemNode::File { data, .. }) = guard.nodes.get(&path) {
                            let digest = compute_digest(parsed_alg, data);
                            let mut w = SftpPacketWriter::new();
                            w.push_str(parsed_alg.canonical_name());
                            w.push_u32(0);
                            w.push_bytes(&digest);
                            w.into_framed_packet(SSH_FXP_EXTENDED_REPLY, Some(req_id))
                        } else {
                            sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Missing")
                        }
                        }
                    }
                    _ => sftp_status_packet(req_id, SSH_FX_OP_UNSUPPORTED, "Unsupported"),
                }
            }
            _ => sftp_status_packet(req_id, SSH_FX_OP_UNSUPPORTED, "Unsupported"),
        };

        stream.write_all(&response).await?;
        stream.flush().await?;
    }
}

/// Starts the mock with `check_file_name = true` and `copy_data = true`,
/// matching the historical default.
pub async fn start_mock_ssh_server(
    host_seed: u8,
    user_pubkey: PublicKey,
    allow_forwarding: bool,
) -> (u16, String, String, Arc<Mutex<MemFs>>) {
    start_mock_ssh_server_with(host_seed, user_pubkey, allow_forwarding, true, true).await
}

/// Starts the mock, optionally refusing the `check-file-name` and
/// `copy-data` extensions so callers can exercise the fallback paths.
pub async fn start_mock_ssh_server_with(
    host_seed: u8,
    user_pubkey: PublicKey,
    allow_forwarding: bool,
    check_file_name: bool,
    copy_data: bool,
) -> (u16, String, String, Arc<Mutex<MemFs>>) {
    let host_key = generate_ed25519_ssh_key(host_seed, "server-host-key");
    let fs = Arc::new(Mutex::new(MemFs::new()));
    let mut server = MockSshServer {
        fs: Arc::clone(&fs),
        allowed_user: "tester".to_string(),
        allowed_password: "correct-horse-battery".to_string(),
        allowed_pubkey: user_pubkey,
        allow_forwarding,
        check_file_name,
        copy_data,
    };
    let cfg = Arc::new(russh::server::Config {
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: vec![host_key.private_key],
        nodelay: true,
        ..Default::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind ssh");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = server.run_on_socket(cfg, &listener).await;
    });
    (
        port,
        host_key.sha256_fingerprint,
        host_key.md5_fingerprint,
        fs,
    )
}
