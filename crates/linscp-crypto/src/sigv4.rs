//! Pure-Rust AWS Signature Version 4 request signer and S3 region resolver,
//! matching `source/linux/S3SigV4.cpp` and `S3Client.cpp`.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::digests::{hex_encode, sha256_hex};

type HmacSha256 = Hmac<Sha256>;

/// SHA-256 hex digest of an empty request body.
pub const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// S3 streaming payload marker permitted over HTTPS.
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// Maximum representable UTC timestamp (`9999-12-31T23:59:59Z`).
const MAX_UTC_EPOCH_SECS: u64 = 253_402_300_799;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRequest {
    pub headers: Vec<(String, String)>,
    pub signed_headers: String,
    pub canonical_request: String,
    pub authorization: String,
}

pub struct S3SignParams<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub query: &'a str,
    pub host: &'a str,
    pub extra_headers: &'a [(String, String)],
    pub payload_hash: &'a str,
    pub epoch_seconds: u64,
    pub region: &'a str,
    pub access_key: &'a str,
    pub secret_access_key: &'a str,
}

fn hmac_raw(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn is_unreserved(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~')
}

/// AWS SigV4 URI encoding (uppercase `%XX`, `~` unescaped, `/` preserved when
/// `keep_slash` is true).
pub fn uri_encode(value: &str, keep_slash: bool) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for &b in value.as_bytes() {
        if is_unreserved(b) || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(DIGITS[(b >> 4) as usize] as char);
            out.push(DIGITS[(b & 0x0f) as usize] as char);
        }
    }
    out
}

/// Normalizes and sorts raw query-string parameters per AWS SigV4 rules.
pub fn canonical_query(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    for part in query.split('&') {
        if part.is_empty() {
            continue;
        }
        match part.split_once('=') {
            Some((k, v)) => pairs.push((k, v)),
            None => pairs.push((part, "")),
        }
    }
    pairs.sort_unstable();
    let mut out = String::with_capacity(query.len());
    for (idx, (k, v)) in pairs.into_iter().enumerate() {
        if idx > 0 {
            out.push('&');
        }
        out.push_str(k);
        out.push('=');
        out.push_str(v);
    }
    out
}

fn normalize_header_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut in_space = false;
    for ch in value.chars() {
        if matches!(ch, ' ' | '\t' | '\r' | '\n') {
            in_space = !out.is_empty();
            continue;
        }
        if in_space {
            out.push(' ');
            in_space = false;
        }
        out.push(ch);
    }
    out
}

pub fn credential_scope(date_stamp: &str, region: &str, service: &str) -> String {
    format!("{date_stamp}/{region}/{service}/aws4_request")
}

pub fn signing_key(
    secret_access_key: &str,
    date_stamp: &str,
    region: &str,
    service: &str,
) -> [u8; 32] {
    let mut initial = Vec::with_capacity(4 + secret_access_key.len());
    initial.extend_from_slice(b"AWS4");
    initial.extend_from_slice(secret_access_key.as_bytes());
    let k_date = hmac_raw(&initial, date_stamp.as_bytes());
    let k_region = hmac_raw(&k_date, region.as_bytes());
    let k_service = hmac_raw(&k_region, service.as_bytes());
    hmac_raw(&k_service, b"aws4_request")
}

pub fn canonical_request(
    method: &str,
    uri: &str,
    query: &str,
    headers: &[(String, String)],
    payload_hash: &str,
) -> String {
    let mut normalized: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), normalize_header_value(v)))
        .collect();
    normalized.sort_by(|a, b| a.0.cmp(&b.0));

    let mut folded: Vec<(String, String)> = Vec::with_capacity(normalized.len());
    for (name, val) in normalized {
        if let Some(last) = folded.last_mut().filter(|last| last.0 == name) {
            last.1.push(',');
            last.1.push_str(&val);
        } else {
            folded.push((name, val));
        }
    }

    let mut canonical = format!("{method}\n{uri}\n{}\n", canonical_query(query));
    let mut signed_names = String::new();
    for (idx, (name, val)) in folded.iter().enumerate() {
        if idx > 0 {
            signed_names.push(';');
        }
        signed_names.push_str(name);
        canonical.push_str(name);
        canonical.push(':');
        canonical.push_str(val);
        canonical.push('\n');
    }
    canonical.push('\n');
    canonical.push_str(&signed_names);
    canonical.push('\n');
    canonical.push_str(payload_hash);
    canonical
}

pub fn string_to_sign(amz_date: &str, scope: &str, canonical_req: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_req.as_bytes())
    )
}

pub fn signature_hex(string_to_sign_val: &str, key: &[u8; 32]) -> String {
    hex_encode(&hmac_raw(key, string_to_sign_val.as_bytes()))
}

pub fn authorization_header(
    access_key: &str,
    scope: &str,
    signed_headers: &str,
    sig_hex: &str,
) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={sig_hex}"
    )
}

fn decompose_utc(epoch_seconds: u64) -> Option<(u32, u32, u32, u32, u32, u32)> {
    if epoch_seconds > MAX_UTC_EPOCH_SECS {
        return None;
    }
    let days = (epoch_seconds / 86_400) as i64;
    let rem = (epoch_seconds % 86_400) as u32;
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;

    // Howard Hinnant's civil-from-days algorithm for the proleptic Gregorian calendar.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    if !(0..=9999).contains(&year) {
        return None;
    }
    Some((year as u32, month, day, hour, minute, second))
}

pub fn amz_date(epoch_seconds: u64) -> String {
    let Some((y, m, d, hh, mm, ss)) = decompose_utc(epoch_seconds) else {
        return String::new();
    };
    format!("{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z")
}

pub fn date_stamp(epoch_seconds: u64) -> String {
    let Some((y, m, d, _, _, _)) = decompose_utc(epoch_seconds) else {
        return String::new();
    };
    format!("{y:04}{m:02}{d:02}")
}

/// Extracts an AWS S3 region from standard `s3.<region>.amazonaws.com(.cn)`
/// hostnames, matching `RegionFromHost` in `S3Client.cpp`.
pub fn region_from_s3_host(host: &str) -> Option<String> {
    let lower = host.trim().to_ascii_lowercase();
    if lower != "amazonaws.com"
        && !lower.ends_with(".amazonaws.com")
        && !lower.ends_with(".amazonaws.com.cn")
    {
        return None;
    }
    let labels: Vec<&str> = lower.split('.').collect();
    for window in labels.windows(2) {
        if window[0] != "s3" {
            continue;
        }
        let candidate = window[1];
        if candidate == "amazonaws" {
            return Some("us-east-1".to_string());
        }
        if candidate.contains('-') {
            return Some(candidate.to_string());
        }
    }
    None
}

pub fn sign_s3_request(params: &S3SignParams<'_>) -> SignedRequest {
    let amz = amz_date(params.epoch_seconds);
    let stamp = date_stamp(params.epoch_seconds);
    let scope = credential_scope(&stamp, params.region, "s3");

    let mut headers = Vec::with_capacity(3 + params.extra_headers.len());
    headers.push(("host".to_string(), params.host.to_string()));
    headers.push(("x-amz-content-sha256".to_string(), params.payload_hash.to_string()));
    headers.push(("x-amz-date".to_string(), amz.clone()));
    headers.extend_from_slice(params.extra_headers);

    let canonical = canonical_request(
        params.method,
        params.uri,
        params.query,
        &headers,
        params.payload_hash,
    );
    let to_sign = string_to_sign(&amz, &scope, &canonical);
    let key = signing_key(params.secret_access_key, &stamp, params.region, "s3");
    let sig = signature_hex(&to_sign, &key);

    let mut names: Vec<String> = headers.iter().map(|(k, _)| k.to_ascii_lowercase()).collect();
    names.sort();
    names.dedup();
    let signed_headers = names.join(";");
    let authorization = authorization_header(params.access_key, &scope, &signed_headers, &sig);

    SignedRequest {
        headers,
        signed_headers,
        canonical_request: canonical,
        authorization,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_and_botocore_sigv4_vectors_match_cpp_unit_tests() {
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        assert_eq!(
            hex_encode(&signing_key(secret, "20150830", "us-east-1", "iam")),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );

        assert_eq!(uri_encode("a b/c+d~e", true), "a%20b/c%2Bd~e");
        assert_eq!(uri_encode("a b/c+d~e", false), "a%20b%2Fc%2Bd~e");
        assert_eq!(uri_encode("/a b/\u{00e9}", true), "/a%20b/%C3%A9");
        assert_eq!(canonical_query("b=2&a=1&a=0&a=10"), "a=0&a=1&a=10&b=2");
        assert_eq!(amz_date(1_768_473_000), "20260115T103000Z");
        assert_eq!(date_stamp(1_768_473_000), "20260115");
        assert_eq!(amz_date(u64::MAX), "");
        assert_eq!(date_stamp(u64::MAX), "");

        let signed = sign_s3_request(&S3SignParams {
            method: "GET",
            uri: "/bucket",
            query: "delimiter=%2F&list-type=2&max-keys=100&prefix=docs%2Fa",
            host: "s3.example.com",
            extra_headers: &[],
            payload_hash: EMPTY_PAYLOAD_SHA256,
            epoch_seconds: 1_768_473_000,
            region: "us-east-1",
            access_key: "AKIDEXAMPLE",
            secret_access_key: secret,
        });
        assert_eq!(signed.signed_headers, "host;x-amz-content-sha256;x-amz-date");
        assert_eq!(
            signed.authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260115/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=7d151aa653d4a54778780085f0edbe6d135ed056a28e85bada65053d6e2e35ba"
        );
    }

    #[test]
    fn s3_host_region_extraction_matches_cpp_rules() {
        assert_eq!(
            region_from_s3_host("s3.eu-west-1.amazonaws.com").as_deref(),
            Some("eu-west-1")
        );
        assert_eq!(
            region_from_s3_host("bucket.s3.dualstack.us-west-2.amazonaws.com").as_deref(),
            None
        );
        assert_eq!(
            region_from_s3_host("s3.amazonaws.com").as_deref(),
            Some("us-east-1")
        );
        assert_eq!(region_from_s3_host("minio.internal.local"), None);
    }
}
