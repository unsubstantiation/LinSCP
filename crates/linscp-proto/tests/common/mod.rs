#![allow(dead_code)]

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use linscp_crypto::ppk::PrivateKeyMaterial;
use linscp_proto::ssh::compute_ssh_fingerprints;
use linscp_proto::tls::spki_sha256_pin;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use p256::pkcs8::EncodePrivateKey;
use russh::keys::{decode_secret_key, PrivateKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;

pub struct GeneratedSshKey {
    pub private_key: PrivateKey,
    pub openssh_pem: String,
    pub sha256_fingerprint: String,
    pub md5_fingerprint: String,
}

pub fn generate_ed25519_ssh_key(seed_byte: u8, comment: &str) -> GeneratedSshKey {
    let secret = [seed_byte; 32];
    let dalek = Ed25519SigningKey::from_bytes(&secret);
    let public = dalek.verifying_key().to_bytes();
    let mat = PrivateKeyMaterial::Ed25519 { secret, public };
    let openssh_pem = mat.to_openssh_pem(comment).expect("encode OpenSSH PEM");
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
