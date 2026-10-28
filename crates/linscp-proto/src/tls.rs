//! Pure-Rust `rustls` (`ring` crypto provider) client configuration builder
//! with custom `ServerCertVerifier` enforcing SPKI SHA-256 `PinnedPublicKey`,
//! `MinTlsVersion` / `MaxTlsVersion`, custom CA PEM bundles, and client
//! certificate authentication across WebDAV, S3, and FTPS/FTPES.

use std::io::BufReader;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore,
    SignatureScheme, SupportedProtocolVersion,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::ProtoError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

impl TlsVersion {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "1.2" | "tls1.2" | "tlsv1.2" | "tls12" | "12" => Some(Self::Tls12),
            "1.3" | "tls1.3" | "tlsv1.3" | "tls13" | "13" => Some(Self::Tls13),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TlsSettings {
    /// `sha256//<base64>` (or `sha256//<64-hex>`, or `;`-separated pin set)
    /// verified against the end-entity X.509 `SubjectPublicKeyInfo` DER.
    pub pinned_public_key: Option<String>,
    pub min_version: Option<TlsVersion>,
    pub max_version: Option<TlsVersion>,
    /// Additional trusted CA certificate bundle in PEM format.
    pub ca_cert_pem: Option<Vec<u8>>,
    /// Client certificate chain in PEM format (mTLS).
    pub client_cert_pem: Option<Vec<u8>>,
    /// Client private key in PEM format (mTLS).
    pub client_key_pem: Option<Vec<u8>>,
    /// Skip chain/hostname checks (explicit opt-in only; `pinned_public_key`
    /// is STILL strictly enforced when configured).
    pub accept_invalid_certs: bool,
}

type DerTlv<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

fn read_der_tlv(input: &[u8]) -> Result<DerTlv<'_>, ProtoError> {
    if input.len() < 2 {
        return Err(ProtoError::Transport(
            "Truncated ASN.1 DER certificate element.".to_string(),
        ));
    }
    let tag = input[0];
    let len_byte = input[1];
    let (hdr_len, content_len) = if (len_byte & 0x80) == 0 {
        (2usize, len_byte as usize)
    } else {
        let num_octets = (len_byte & 0x7f) as usize;
        if num_octets == 0 || num_octets > 4 || input.len() < 2 + num_octets {
            return Err(ProtoError::Transport(
                "Invalid ASN.1 DER length encoding in certificate.".to_string(),
            ));
        }
        let mut len = 0usize;
        for &b in &input[2..2 + num_octets] {
            len = (len << 8) | (b as usize);
        }
        (2 + num_octets, len)
    };
    let total_len = hdr_len.checked_add(content_len).ok_or_else(|| {
        ProtoError::Transport("ASN.1 DER length overflow in certificate.".to_string())
    })?;
    if input.len() < total_len {
        return Err(ProtoError::Transport(
            "ASN.1 DER element extends past certificate end.".to_string(),
        ));
    }
    let full_element = &input[..total_len];
    let value = &input[hdr_len..total_len];
    let rest = &input[total_len..];
    Ok((tag, full_element, value, rest))
}

/// Extracts the exact raw `SubjectPublicKeyInfo` (`SPKI`) DER TLV slice from
/// an X.509 DER-encoded certificate (RFC 5280 §4.1).
pub fn extract_spki_der(cert_der: &[u8]) -> Result<&[u8], ProtoError> {
    let (outer_tag, _, cert_seq, _) = read_der_tlv(cert_der)?;
    if outer_tag != 0x30 {
        return Err(ProtoError::Transport(
            "X.509 certificate outer element is not a SEQUENCE.".to_string(),
        ));
    }
    let (tbs_tag, _, mut tbs, _) = read_der_tlv(cert_seq)?;
    if tbs_tag != 0x30 {
        return Err(ProtoError::Transport(
            "X.509 tbsCertificate is not a SEQUENCE.".to_string(),
        ));
    }

    // Optional [0] EXPLICIT Version
    let (first_tag, _, _, after_first) = read_der_tlv(tbs)?;
    if first_tag == 0xa0 {
        tbs = after_first;
    }
    // Skip: serialNumber, signature, issuer, validity, subject (5 DER TLVs)
    for _ in 0..5 {
        let (_, _, _, next) = read_der_tlv(tbs)?;
        tbs = next;
    }
    let (spki_tag, spki_full, _, _) = read_der_tlv(tbs)?;
    if spki_tag != 0x30 {
        return Err(ProtoError::Transport(
            "X.509 SubjectPublicKeyInfo is not a SEQUENCE.".to_string(),
        ));
    }
    Ok(spki_full)
}

/// Computes the canonical `sha256//<base64>` SPKI pin of a DER-encoded X.509
/// certificate, matching `curl --pinnedpubkey`.
pub fn spki_sha256_pin(cert_der: &[u8]) -> Result<String, ProtoError> {
    let spki = extract_spki_der(cert_der)?;
    let digest = Sha256::digest(spki);
    Ok(format!("sha256//{}", BASE64.encode(digest)))
}

fn decode_hex_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn parse_pin_file_bytes(raw_item: &str, bytes: &[u8]) -> Result<Vec<[u8; 32]>, ProtoError> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        if text.contains("-----BEGIN ") {
            let mut pins = Vec::new();
            let mut in_pub = false;
            let mut pub_b64 = String::new();
            for line in text.lines() {
                let t = line.trim();
                if t == "-----BEGIN PUBLIC KEY-----" {
                    in_pub = true;
                    pub_b64.clear();
                } else if t == "-----END PUBLIC KEY-----" && in_pub {
                    in_pub = false;
                    let spki_der = BASE64.decode(pub_b64.as_bytes()).map_err(|_| {
                        ProtoError::Transport(format!(
                            "Malformed PEM PUBLIC KEY in PinnedPublicKey file '{raw_item}'."
                        ))
                    })?;
                    pins.push(Sha256::digest(&spki_der).into());
                } else if in_pub {
                    pub_b64.push_str(t);
                }
            }
            if text.contains("-----BEGIN CERTIFICATE-----") {
                let mut reader = BufReader::new(bytes);
                for cert_res in rustls_pemfile::certs(&mut reader) {
                    let cert = cert_res.map_err(|e| {
                        ProtoError::Transport(format!(
                            "Malformed PEM CERTIFICATE in PinnedPublicKey file '{raw_item}': {e}"
                        ))
                    })?;
                    let spki = extract_spki_der(cert.as_ref()).map_err(|e| {
                        ProtoError::Transport(format!(
                            "Failed to extract SPKI from PinnedPublicKey certificate '{raw_item}': {e}"
                        ))
                    })?;
                    pins.push(Sha256::digest(spki).into());
                }
            }
            if !pins.is_empty() {
                return Ok(pins);
            }
        }
    }
    if let Ok(spki) = extract_spki_der(bytes) {
        return Ok(vec![Sha256::digest(spki).into()]);
    }
    if bytes.first() == Some(&0x30) && bytes.len() >= 24 {
        return Ok(vec![Sha256::digest(bytes).into()]);
    }
    Err(ProtoError::Transport(format!(
        "Unrecognized PinnedPublicKey file '{raw_item}'."
    )))
}

/// Parses one or more `;`-separated SPKI SHA-256 public-key pins
/// (`sha256//<base64>`, `sha256//<64-hex>`, bare 44-char base64 SHA-256, or
/// a path to a PEM/DER public-key or certificate file).
/// Wildcards (`*`) or malformed pins fail closed.
pub fn parse_pinned_public_keys(spec: &str) -> Result<Vec<[u8; 32]>, ProtoError> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err(ProtoError::Transport(
            "PinnedPublicKey specification must not be empty.".to_string(),
        ));
    }
    let mut pins = Vec::new();
    for raw_item in trimmed.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        if raw_item == "*" {
            return Err(ProtoError::Transport(
                "Wildcard '*' is not a valid PinnedPublicKey.".to_string(),
            ));
        }
        let has_hash_prefix = raw_item.starts_with("sha256//")
            || raw_item.starts_with("SHA256//")
            || raw_item.starts_with("sha256:")
            || raw_item.starts_with("SHA256:");
        let body = raw_item
            .strip_prefix("sha256//")
            .or_else(|| raw_item.strip_prefix("SHA256//"))
            .or_else(|| raw_item.strip_prefix("sha256:"))
            .or_else(|| raw_item.strip_prefix("SHA256:"))
            .unwrap_or(raw_item);

        if let Some(hex_bytes) = decode_hex_32(body) {
            pins.push(hex_bytes);
            continue;
        }

        if !has_hash_prefix && std::path::Path::new(raw_item).is_file() {
            let file_bytes = std::fs::read(raw_item).map_err(|e| {
                ProtoError::Transport(format!("Failed to read PinnedPublicKey file '{raw_item}': {e}"))
            })?;
            pins.extend(parse_pin_file_bytes(raw_item, &file_bytes)?);
            continue;
        }

        let decoded = BASE64
            .decode(body.as_bytes())
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(body.as_bytes()))
            .map_err(|_| {
                ProtoError::Transport(format!("Malformed PinnedPublicKey entry '{raw_item}'."))
            })?;
        if decoded.len() != 32 {
            return Err(ProtoError::Transport(format!(
                "PinnedPublicKey '{raw_item}' decoded to {} bytes (expected 32-byte SHA-256).",
                decoded.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded);
        pins.push(arr);
    }
    if pins.is_empty() {
        return Err(ProtoError::Transport(
            "PinnedPublicKey specification held no valid SHA-256 pins.".to_string(),
        ));
    }
    Ok(pins)
}

#[derive(Debug)]
struct CustomServerVerifier {
    webpki: Arc<WebPkiServerVerifier>,
    provider: Arc<CryptoProvider>,
    pins: Vec<[u8; 32]>,
    explicit_ca_ders: Vec<Vec<u8>>,
    accept_invalid_certs: bool,
}

impl ServerCertVerifier for CustomServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if !self.accept_invalid_certs {
            if let Err(err) = self.webpki.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            ) {
                let ca_as_ee = format!("{err:?}").contains("CaUsedAsEndEntity");
                let explicitly_trusted = ca_as_ee
                    && self
                        .explicit_ca_ders
                        .iter()
                        .any(|der| der.as_slice() == end_entity.as_ref());
                if !explicitly_trusted {
                    return Err(err);
                }
            }
        }

        if !self.pins.is_empty() {
            let spki = extract_spki_der(end_entity.as_ref())
                .map_err(|_| TlsError::InvalidCertificate(CertificateError::BadEncoding))?;
            let observed: [u8; 32] = Sha256::digest(spki).into();
            let matched = self
                .pins
                .iter()
                .any(|pin| bool::from(pin.ct_eq(&observed)));
            if !matched {
                return Err(TlsError::InvalidCertificate(CertificateError::Other(
                    rustls::OtherError(Arc::new(std::io::Error::other(
                        "Server public key does not match PinnedPublicKey",
                    ))),
                )));
            }
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

static VERSIONS_BOTH: &[&SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];
static VERSIONS_12_ONLY: &[&SupportedProtocolVersion] = &[&rustls::version::TLS12];
static VERSIONS_13_ONLY: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];

fn select_protocol_versions(
    min_ver: Option<TlsVersion>,
    max_ver: Option<TlsVersion>,
) -> Result<&'static [&'static SupportedProtocolVersion], ProtoError> {
    let min_v = min_ver.unwrap_or(TlsVersion::Tls12);
    let max_v = max_ver.unwrap_or(TlsVersion::Tls13);
    if min_v > max_v {
        return Err(ProtoError::Transport(format!(
            "MinTlsVersion ({min_v:?}) exceeds MaxTlsVersion ({max_v:?})."
        )));
    }
    match (min_v, max_v) {
        (TlsVersion::Tls12, TlsVersion::Tls13) => Ok(VERSIONS_BOTH),
        (TlsVersion::Tls12, TlsVersion::Tls12) => Ok(VERSIONS_12_ONLY),
        (TlsVersion::Tls13, TlsVersion::Tls13) => Ok(VERSIONS_13_ONLY),
        (TlsVersion::Tls13, TlsVersion::Tls12) => unreachable!(),
    }
}

/// Builds a pure-Rust `rustls::ClientConfig` backed exclusively by `ring`,
/// enforcing optional SPKI SHA-256 public-key pins, TLS 1.2/1.3 bounds,
/// custom CA PEM certificates, and mTLS client certificates.
pub fn build_rustls_client_config(settings: &TlsSettings) -> Result<ClientConfig, ProtoError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let versions = select_protocol_versions(settings.min_version, settings.max_version)?;

    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut explicit_ca_ders = Vec::new();
    if let Some(ca_pem) = settings.ca_cert_pem.as_deref() {
        let mut reader = BufReader::new(ca_pem);
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ProtoError::Transport(format!("Failed to parse CA PEM: {e}")))?;
        if certs.is_empty() {
            return Err(ProtoError::Transport(
                "Configured CA PEM contained no certificates.".to_string(),
            ));
        }
        for cert in certs {
            explicit_ca_ders.push(cert.as_ref().to_vec());
            root_store.add(cert).map_err(|e| {
                ProtoError::Transport(format!("Failed to add CA certificate to root store: {e}"))
            })?;
        }
    }

    let pins = match settings.pinned_public_key.as_deref() {
        Some(spec) if !spec.trim().is_empty() => parse_pinned_public_keys(spec)?,
        _ => Vec::new(),
    };

    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(versions)
        .map_err(|e| ProtoError::Transport(format!("Invalid TLS version selection: {e}")))?;

    let client_certs = match (
        settings.client_cert_pem.as_deref(),
        settings.client_key_pem.as_deref(),
    ) {
        (Some(cert_pem), Some(key_pem)) => {
            let mut cert_reader = BufReader::new(cert_pem);
            let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    ProtoError::Transport(format!("Failed to parse client certificate PEM: {e}"))
                })?;
            if certs.is_empty() {
                return Err(ProtoError::Transport(
                    "Client certificate PEM contained no certificates.".to_string(),
                ));
            }
            let mut key_reader = BufReader::new(key_pem);
            let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
                .map_err(|e| ProtoError::Transport(format!("Failed to parse client key PEM: {e}")))?
                .ok_or_else(|| {
                    ProtoError::Transport(
                        "Client private key PEM contained no private key.".to_string(),
                    )
                })?;
            Some((certs, key))
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(ProtoError::Transport(
                "Both client certificate PEM and client key PEM must be supplied for mTLS."
                    .to_string(),
            ));
        }
        (None, None) => None,
    };

    let config = if pins.is_empty() && explicit_ca_ders.is_empty() && !settings.accept_invalid_certs
    {
        let step = builder.with_root_certificates(root_store);
        match client_certs {
            Some((certs, key)) => step.with_client_auth_cert(certs, key).map_err(|e| {
                ProtoError::Transport(format!("Invalid mTLS client credentials: {e}"))
            })?,
            None => step.with_no_client_auth(),
        }
    } else {
        let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(root_store), provider.clone())
            .build()
            .map_err(|e| ProtoError::Transport(format!("Failed to build TLS verifier: {e}")))?;
        let custom = Arc::new(CustomServerVerifier {
            webpki,
            provider,
            pins,
            explicit_ca_ders,
            accept_invalid_certs: settings.accept_invalid_certs,
        });
        let step = builder.dangerous().with_custom_certificate_verifier(custom);
        match client_certs {
            Some((certs, key)) => step.with_client_auth_cert(certs, key).map_err(|e| {
                ProtoError::Transport(format!("Invalid mTLS client credentials: {e}"))
            })?,
            None => step.with_no_client_auth(),
        }
    };

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pinned_keys_supports_base64_hex_multi_and_rejects_wildcard() {
        let sample = [0x42u8; 32];
        let b64 = format!("sha256//{}", BASE64.encode(sample));
        let hex: String = sample.iter().map(|b| format!("{b:02x}")).collect();
        let multi = format!("{b64}; sha256//{hex}");

        let parsed = parse_pinned_public_keys(&multi).unwrap();
        assert_eq!(parsed, vec![sample, sample]);

        assert!(parse_pinned_public_keys("*").is_err());
        assert!(parse_pinned_public_keys("sha256//abcd").is_err());
        assert!(select_protocol_versions(Some(TlsVersion::Tls13), Some(TlsVersion::Tls12)).is_err());
    }
}
