//! Portable digest and checksum helpers (`SHA-256`, `SHA-1`, `MD5`, `CRC32`)
//! plus lowercase/uppercase hex codecs.

use crc32fast::Hasher as Crc32Hasher;
use md5::{Digest as _, Md5};
use sha1::Sha1;
use sha2::Sha256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Sha256,
    Sha1,
    Md5,
    Crc32,
}

impl DigestAlgorithm {
    /// Parses LinSCP / SFTP `check-file-name` algorithm identifiers.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "sha-256" | "sha256" => Some(Self::Sha256),
            "sha-1" | "sha1" => Some(Self::Sha1),
            "md5" => Some(Self::Md5),
            "crc32" => Some(Self::Crc32),
            _ => None,
        }
    }

    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha-256",
            Self::Sha1 => "sha-1",
            Self::Md5 => "md5",
            Self::Crc32 => "crc32",
        }
    }
}

pub enum StreamingHasher {
    Sha256(Sha256),
    Sha1(Sha1),
    Md5(Md5),
    Crc32(Crc32Hasher),
}

impl StreamingHasher {
    pub fn new(algorithm: DigestAlgorithm) -> Self {
        match algorithm {
            DigestAlgorithm::Sha256 => Self::Sha256(Sha256::new()),
            DigestAlgorithm::Sha1 => Self::Sha1(Sha1::new()),
            DigestAlgorithm::Md5 => Self::Md5(Md5::new()),
            DigestAlgorithm::Crc32 => Self::Crc32(Crc32Hasher::new()),
        }
    }

    pub fn update(&mut self, chunk: &[u8]) {
        match self {
            Self::Sha256(h) => h.update(chunk),
            Self::Sha1(h) => h.update(chunk),
            Self::Md5(h) => h.update(chunk),
            Self::Crc32(h) => h.update(chunk),
        }
    }

    pub fn finalize_hex(self) -> String {
        match self {
            Self::Sha256(h) => {
                let out: [u8; 32] = h.finalize().into();
                hex_encode(&out)
            }
            Self::Sha1(h) => {
                let out: [u8; 20] = h.finalize().into();
                hex_encode(&out)
            }
            Self::Md5(h) => {
                let out: [u8; 16] = h.finalize().into();
                hex_encode(&out)
            }
            Self::Crc32(h) => format!("{:08x}", h.finalize()),
        }
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if (text.len() & 1) != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&sha256_bytes(data))
}

pub fn sha1_bytes(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn sha1_hex(data: &[u8]) -> String {
    hex_encode(&sha1_bytes(data))
}

pub fn md5_bytes(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn md5_hex(data: &[u8]) -> String {
    hex_encode(&md5_bytes(data))
}

pub fn crc32_u32(data: &[u8]) -> u32 {
    let mut hasher = Crc32Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

pub fn crc32_hex(data: &[u8]) -> String {
    format!("{:08x}", crc32_u32(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_abc_vectors_match_published_digests() {
        let msg = b"abc";
        assert_eq!(
            sha256_hex(msg),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha1_hex(msg), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(md5_hex(msg), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(crc32_hex(b"123456789"), "cbf43926");
    }

    #[test]
    fn streaming_hasher_matches_oneshot() {
        for alg in [
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha1,
            DigestAlgorithm::Md5,
            DigestAlgorithm::Crc32,
        ] {
            let mut stream = StreamingHasher::new(alg);
            stream.update(b"hello ");
            stream.update(b"world");
            let streamed = stream.finalize_hex();
            let parsed = DigestAlgorithm::parse(alg.canonical_name()).unwrap();
            let mut full = StreamingHasher::new(parsed);
            full.update(b"hello world");
            assert_eq!(streamed, full.finalize_hex());
        }
    }
}
