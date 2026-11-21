//! Pure-Rust AES-128-OCB3 (RFC 7253, 96-bit nonce, 128-bit tag) and Mosh
//! datagram framing (`[8-byte direction_seq] || [ciphertext] || [16-byte tag]`).

use std::fmt;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use base64::engine::general_purpose::STANDARD_NO_PAD as BASE64_NO_PAD;
use base64::Engine as _;
use rand::RngCore;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const OCB3_KEY_BYTES: usize = 16;
pub const OCB3_NONCE_BYTES: usize = 12;
pub const OCB3_TAG_BYTES: usize = 16;
pub const MOSH_WIRE_NONCE_BYTES: usize = 8;
pub const MOSH_MIN_DATAGRAM_BYTES: usize = MOSH_WIRE_NONCE_BYTES + OCB3_TAG_BYTES;
pub const MOSH_MAX_DATAGRAM_BYTES: usize = 2048;

const DIRECTION_BIT: u64 = 1u64 << 63;
const SEQUENCE_MASK: u64 = !DIRECTION_BIT;
/// RFC 7253 / Mosh shared-key block limit (`2^47` blocks per endpoint).
const MAX_BLOCKS_ENCRYPTED: u64 = 1u64 << 47;
const L_TABLE_LEN: usize = 48;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Ocb3Error {
    #[error("Mosh key must be a canonical 22-character Base64 string representing 128 bits.")]
    InvalidKey,
    #[error("Mosh datagram size is outside allowed bounds.")]
    InvalidDatagramLength,
    #[error("OCB3 authentication tag verification failed.")]
    AuthenticationFailed,
    #[error("Mosh datagram direction bit does not match expected endpoint role.")]
    WrongDirection,
    #[error("Mosh sequence or block counter exhausted.")]
    CounterExhausted,
}

/// Direction bit encoded in the MSB of Mosh's 64-bit wire nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoshDirection {
    ToServer = 0,
    ToClient = 1,
}

impl MoshDirection {
    const fn bit(self) -> u64 {
        match self {
            Self::ToServer => 0,
            Self::ToClient => DIRECTION_BIT,
        }
    }
}

/// Canonical 128-bit Mosh session key (`22` unpadded Base64 characters),
/// zeroized on drop and redacted from `Debug`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MoshBase64Key([u8; OCB3_KEY_BYTES]);

impl PartialEq for MoshBase64Key {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for MoshBase64Key {}

impl fmt::Debug for MoshBase64Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MoshBase64Key([REDACTED])")
    }
}

impl MoshBase64Key {
    pub const fn from_array(raw: [u8; OCB3_KEY_BYTES]) -> Self {
        Self(raw)
    }

    pub fn generate() -> Self {
        let mut raw = [0u8; OCB3_KEY_BYTES];
        rand::thread_rng().fill_bytes(&mut raw);
        Self(raw)
    }

    pub fn from_printable(printable: &str) -> Result<Self, Ocb3Error> {
        if printable.len() != 22 {
            return Err(Ocb3Error::InvalidKey);
        }
        let decoded = Zeroizing::new(
            BASE64_NO_PAD
                .decode(printable.as_bytes())
                .map_err(|_| Ocb3Error::InvalidKey)?,
        );
        if decoded.len() != OCB3_KEY_BYTES {
            return Err(Ocb3Error::InvalidKey);
        }
        let mut raw = [0u8; OCB3_KEY_BYTES];
        raw.copy_from_slice(&decoded);
        let key = Self(raw);
        raw.zeroize();
        // Reject non-canonical trailing bits in the 22nd character.
        if key.printable().as_str() != printable {
            return Err(Ocb3Error::InvalidKey);
        }
        Ok(key)
    }

    pub fn printable(&self) -> Zeroizing<String> {
        Zeroizing::new(BASE64_NO_PAD.encode(self.0))
    }

    pub const fn as_bytes(&self) -> &[u8; OCB3_KEY_BYTES] {
        &self.0
    }
}

#[inline]
const fn gf128_double(val: u128) -> u128 {
    let mask = 0u128.wrapping_sub(val >> 127);
    (val << 1) ^ (mask & 0x87)
}

#[inline]
fn encipher_u128(cipher: &Aes128, block: u128) -> u128 {
    let mut bytes = block.to_be_bytes();
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut bytes));
    let out = u128::from_be_bytes(bytes);
    bytes.zeroize();
    out
}

#[inline]
fn decipher_u128(cipher: &Aes128, block: u128) -> u128 {
    let mut bytes = block.to_be_bytes();
    cipher.decrypt_block(GenericArray::from_mut_slice(&mut bytes));
    let out = u128::from_be_bytes(bytes);
    bytes.zeroize();
    out
}

/// RFC 7253 `OCB-AES128` instance with 96-bit nonces and 128-bit tags.
pub struct Aes128Ocb3 {
    cipher: Aes128,
    l_star: u128,
    l_dollar: u128,
    l_table: [u128; L_TABLE_LEN],
}

impl Drop for Aes128Ocb3 {
    fn drop(&mut self) {
        self.l_star.zeroize();
        self.l_dollar.zeroize();
        self.l_table.zeroize();
    }
}

impl fmt::Debug for Aes128Ocb3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Aes128Ocb3([REDACTED])")
    }
}

impl Aes128Ocb3 {
    pub fn new(key: &[u8; OCB3_KEY_BYTES]) -> Self {
        let cipher = Aes128::new(GenericArray::from_slice(key));
        let l_star = encipher_u128(&cipher, 0);
        let l_dollar = gf128_double(l_star);
        let mut l_table = [0u128; L_TABLE_LEN];
        l_table[0] = gf128_double(l_dollar);
        let mut idx = 1;
        while idx < L_TABLE_LEN {
            l_table[idx] = gf128_double(l_table[idx - 1]);
            idx += 1;
        }
        Self {
            cipher,
            l_star,
            l_dollar,
            l_table,
        }
    }

    fn initial_offset(&self, nonce: &[u8; OCB3_NONCE_BYTES]) -> u128 {
        // TAGLEN = 128 -> TAGLEN mod 128 == 0, |N| = 96 -> [0, 0, 0, 1, N[0..12]].
        let mut nonce_block = [0u8; 16];
        nonce_block[3] = 0x01;
        nonce_block[4..16].copy_from_slice(nonce);
        let bottom = (nonce_block[15] & 0x3f) as u32;
        nonce_block[15] &= 0xc0;
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut nonce_block));
        let top = u128::from_be_bytes(nonce_block);
        let first_u64 = u64::from_be_bytes([
            nonce_block[0],
            nonce_block[1],
            nonce_block[2],
            nonce_block[3],
            nonce_block[4],
            nonce_block[5],
            nonce_block[6],
            nonce_block[7],
        ]);
        let shifted_u64 = u64::from_be_bytes([
            nonce_block[1],
            nonce_block[2],
            nonce_block[3],
            nonce_block[4],
            nonce_block[5],
            nonce_block[6],
            nonce_block[7],
            nonce_block[8],
        ]);
        nonce_block.zeroize();
        let ext = first_u64 ^ shifted_u64;
        if bottom == 0 {
            top
        } else {
            (top << bottom) | ((ext >> (64 - bottom)) as u128)
        }
    }

    fn hash_aad(&self, aad: &[u8]) -> u128 {
        if aad.is_empty() {
            return 0;
        }
        let mut offset = 0u128;
        let mut sum = 0u128;
        let mut chunks = aad.chunks_exact(16);
        let mut block_index = 0u64;
        for chunk in &mut chunks {
            block_index += 1;
            let ntz = (block_index.trailing_zeros() as usize).min(L_TABLE_LEN - 1);
            offset ^= self.l_table[ntz];
            let mut arr = [0u8; 16];
            arr.copy_from_slice(chunk);
            let a_i = u128::from_be_bytes(arr);
            sum ^= encipher_u128(&self.cipher, a_i ^ offset);
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            offset ^= self.l_star;
            let mut padded = [0u8; 16];
            padded[..rem.len()].copy_from_slice(rem);
            padded[rem.len()] = 0x80;
            let a_star = u128::from_be_bytes(padded);
            sum ^= encipher_u128(&self.cipher, a_star ^ offset);
        }
        sum
    }

    /// Encrypts `plaintext` under `nonce` and `aad`, returning `ciphertext || 16-byte tag`.
    pub fn encrypt(&self, nonce: &[u8; OCB3_NONCE_BYTES], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut offset = self.initial_offset(nonce);
        let mut checksum = 0u128;
        let mut out = Vec::with_capacity(plaintext.len() + OCB3_TAG_BYTES);

        let mut chunks = plaintext.chunks_exact(16);
        let mut block_index = 0u64;
        for chunk in &mut chunks {
            block_index += 1;
            let ntz = (block_index.trailing_zeros() as usize).min(L_TABLE_LEN - 1);
            offset ^= self.l_table[ntz];
            let mut arr = [0u8; 16];
            arr.copy_from_slice(chunk);
            let p_i = u128::from_be_bytes(arr);
            arr.zeroize();
            let c_i = offset ^ encipher_u128(&self.cipher, p_i ^ offset);
            out.extend_from_slice(&c_i.to_be_bytes());
            checksum ^= p_i;
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            offset ^= self.l_star;
            let pad = encipher_u128(&self.cipher, offset).to_be_bytes();
            for (p_byte, pad_byte) in rem.iter().zip(pad.iter()) {
                out.push(p_byte ^ pad_byte);
            }
            let mut padded = [0u8; 16];
            padded[..rem.len()].copy_from_slice(rem);
            padded[rem.len()] = 0x80;
            checksum ^= u128::from_be_bytes(padded);
            padded.zeroize();
        }
        let tag = encipher_u128(&self.cipher, checksum ^ offset ^ self.l_dollar) ^ self.hash_aad(aad);
        out.extend_from_slice(&tag.to_be_bytes());
        checksum.zeroize();
        offset.zeroize();
        out
    }

    /// Decrypts `ciphertext_and_tag` and verifies the 128-bit authentication tag
    /// in constant time before returning any plaintext.
    pub fn decrypt(
        &self,
        nonce: &[u8; OCB3_NONCE_BYTES],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, Ocb3Error> {
        if ciphertext_and_tag.len() < OCB3_TAG_BYTES {
            return Err(Ocb3Error::AuthenticationFailed);
        }
        let ct_len = ciphertext_and_tag.len() - OCB3_TAG_BYTES;
        let ct = &ciphertext_and_tag[..ct_len];
        let received_tag = &ciphertext_and_tag[ct_len..];

        let mut offset = self.initial_offset(nonce);
        let mut checksum = 0u128;
        let mut pt = Vec::with_capacity(ct_len);

        let mut chunks = ct.chunks_exact(16);
        let mut block_index = 0u64;
        for chunk in &mut chunks {
            block_index += 1;
            let ntz = (block_index.trailing_zeros() as usize).min(L_TABLE_LEN - 1);
            offset ^= self.l_table[ntz];
            let mut arr = [0u8; 16];
            arr.copy_from_slice(chunk);
            let c_i = u128::from_be_bytes(arr);
            let p_i = offset ^ decipher_u128(&self.cipher, c_i ^ offset);
            pt.extend_from_slice(&p_i.to_be_bytes());
            checksum ^= p_i;
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            offset ^= self.l_star;
            let mut pad = encipher_u128(&self.cipher, offset).to_be_bytes();
            let start = pt.len();
            for (c_byte, pad_byte) in rem.iter().zip(pad.iter()) {
                pt.push(c_byte ^ pad_byte);
            }
            pad.zeroize();
            let mut padded = [0u8; 16];
            padded[..rem.len()].copy_from_slice(&pt[start..]);
            padded[rem.len()] = 0x80;
            checksum ^= u128::from_be_bytes(padded);
            padded.zeroize();
        }
        let expected_tag =
            (encipher_u128(&self.cipher, checksum ^ offset ^ self.l_dollar) ^ self.hash_aad(aad))
                .to_be_bytes();
        checksum.zeroize();
        offset.zeroize();

        if !bool::from(expected_tag.ct_eq(received_tag)) {
            pt.zeroize();
            return Err(Ocb3Error::AuthenticationFailed);
        }
        Ok(pt)
    }
}

/// Stateful Mosh datagram sealer/opener enforcing monotonic nonces, direction
/// separation (`ToServer` vs `ToClient`), MTU limits, and the `2^47`-block cap.
pub struct MoshCryptoSession {
    ocb: Aes128Ocb3,
    next_seq: u64,
    blocks_encrypted: u64,
}

impl fmt::Debug for MoshCryptoSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MoshCryptoSession")
            .field("next_seq", &self.next_seq)
            .finish()
    }
}

impl MoshCryptoSession {
    pub fn new(key: &MoshBase64Key) -> Self {
        Self {
            ocb: Aes128Ocb3::new(key.as_bytes()),
            next_seq: 0,
            blocks_encrypted: 0,
        }
    }

    /// Seals `plaintext` into a Mosh wire datagram `[8-byte direction_seq] || [ct + 16-byte tag]`.
    pub fn seal(&mut self, direction: MoshDirection, plaintext: &[u8]) -> Result<(u64, Vec<u8>), Ocb3Error> {
        if plaintext.len() + MOSH_MIN_DATAGRAM_BYTES > MOSH_MAX_DATAGRAM_BYTES {
            return Err(Ocb3Error::InvalidDatagramLength);
        }
        let seq = self.next_seq;
        if seq > SEQUENCE_MASK {
            return Err(Ocb3Error::CounterExhausted);
        }
        let add_blocks = ((plaintext.len() as u64) >> 4) + u64::from((plaintext.len() & 0x0f) != 0);
        let next_blocks = self
            .blocks_encrypted
            .checked_add(add_blocks)
            .ok_or(Ocb3Error::CounterExhausted)?;
        if next_blocks >= MAX_BLOCKS_ENCRYPTED {
            return Err(Ocb3Error::CounterExhausted);
        }
        self.next_seq = seq.checked_add(1).ok_or(Ocb3Error::CounterExhausted)?;
        self.blocks_encrypted = next_blocks;

        let direction_seq = direction.bit() | (seq & SEQUENCE_MASK);
        let cc = direction_seq.to_be_bytes();
        let mut nonce = [0u8; OCB3_NONCE_BYTES];
        nonce[4..12].copy_from_slice(&cc);
        let ct = self.ocb.encrypt(&nonce, &[], plaintext);

        let mut wire = Vec::with_capacity(MOSH_WIRE_NONCE_BYTES + ct.len());
        wire.extend_from_slice(&cc);
        wire.extend_from_slice(&ct);
        Ok((seq, wire))
    }

    /// Authenticates and opens a Mosh wire datagram, requiring `expected_direction`.
    pub fn open(
        &self,
        expected_direction: MoshDirection,
        datagram: &[u8],
    ) -> Result<(u64, Vec<u8>), Ocb3Error> {
        if !(MOSH_MIN_DATAGRAM_BYTES..=MOSH_MAX_DATAGRAM_BYTES).contains(&datagram.len()) {
            return Err(Ocb3Error::InvalidDatagramLength);
        }
        let mut cc = [0u8; MOSH_WIRE_NONCE_BYTES];
        cc.copy_from_slice(&datagram[..MOSH_WIRE_NONCE_BYTES]);
        let direction_seq = u64::from_be_bytes(cc);
        let mut nonce = [0u8; OCB3_NONCE_BYTES];
        nonce[4..12].copy_from_slice(&cc);

        let mut pt = self
            .ocb
            .decrypt(&nonce, &[], &datagram[MOSH_WIRE_NONCE_BYTES..])?;
        let actual_dir = if (direction_seq & DIRECTION_BIT) != 0 {
            MoshDirection::ToClient
        } else {
            MoshDirection::ToServer
        };
        if actual_dir != expected_direction {
            pt.zeroize();
            return Err(Ocb3Error::WrongDirection);
        }
        Ok((direction_seq & SEQUENCE_MASK, pt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digests::hex_decode;

    #[test]
    fn rfc7253_appendix_a_vectors_encrypt_decrypt_and_reject_tampering() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
        ];
        let ocb = Aes128Ocb3::new(&key);

        let b8 = hex_decode("0001020304050607").unwrap();
        let b16 = hex_decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let b24 = hex_decode("000102030405060708090a0b0c0d0e0f1011121314151617").unwrap();

        let cases: &[(&[u8], &[u8], &str)] = &[
            (&[], &[], "197b9c3c441d3c83eafb2bef633b9182"),
            (&b8, &b8, "92b657130a74b85a16dc76a46d47e1ead537209e8a96d14e"),
            (&b8, &[], "98b91552c8c009185044e30a6eb2fe21"),
            (&[], &b8, "92b657130a74b85a971effcae19ad4716f88e87b871fbeed"),
            (&b16, &b16, "bea5e8798dbe7110031c144da0b26122776c9924d6723a1fc4524532ac3e5beb"),
            (&b16, &[], "7ddb8e6cea6814866212509619b19cc6"),
            (&[], &b16, "bea5e8798dbe7110031c144da0b2612213cc8b747807121a4cbb3e4bd6b456af"),
            (&b24, &b24, "bea5e8798dbe7110031c144da0b26122fcfcee7a2a8d4d485fa94fc3f38820f1dc3f3d1fd4e55e1c"),
            (&b24, &[], "282026da3068bc9fa118681d559f10f6"),
            (&[], &b24, "bea5e8798dbe7110031c144da0b26122fcfcee7a2a8d4d486ef2f52587fda0ed97dc7eede241df68"),
        ];

        for (aad, pt, expected_hex) in cases {
            let expected = hex_decode(expected_hex).unwrap();
            let ct = ocb.encrypt(&nonce, aad, pt);
            assert_eq!(ct, expected);
            let recovered = ocb.decrypt(&nonce, aad, &ct).unwrap();
            assert_eq!(recovered, *pt);

            for i in 0..ct.len() {
                let mut tampered = ct.clone();
                tampered[i] ^= 0x01;
                assert_eq!(
                    ocb.decrypt(&nonce, aad, &tampered),
                    Err(Ocb3Error::AuthenticationFailed)
                );
            }
        }
    }

    #[test]
    fn mosh_base64_key_validates_canonical_encoding_and_redacts_debug() {
        let key = MoshBase64Key::from_array([0x41; 16]);
        let printable = key.printable();
        assert_eq!(printable.len(), 22);
        let parsed = MoshBase64Key::from_printable(&printable).unwrap();
        assert_eq!(parsed.as_bytes(), key.as_bytes());
        assert!(!format!("{parsed:?}").contains(&*printable));

        assert_eq!(MoshBase64Key::from_printable("short"), Err(Ocb3Error::InvalidKey));
        // Flipping low unused bit of 22nd Base64 char produces non-canonical encoding.
        let mut non_canonical = printable.to_string();
        non_canonical.pop();
        non_canonical.push('F');
        if non_canonical != *printable {
            assert_eq!(
                MoshBase64Key::from_printable(&non_canonical),
                Err(Ocb3Error::InvalidKey)
            );
        }
    }

    #[test]
    fn mosh_crypto_session_enforces_direction_and_monotonic_sequence() {
        let key = MoshBase64Key::generate();
        let mut client = MoshCryptoSession::new(&key);
        let mut server = MoshCryptoSession::new(&key);

        let (seq0, pkt0) = client.seal(MoshDirection::ToServer, b"\x00\x01\xff\xffhello").unwrap();
        assert_eq!(seq0, 0);
        // Reflecting a ToServer packet back to the client must fail with WrongDirection.
        assert_eq!(
            client.open(MoshDirection::ToClient, &pkt0),
            Err(Ocb3Error::WrongDirection)
        );
        let (srv_seq, pt) = server.open(MoshDirection::ToServer, &pkt0).unwrap();
        assert_eq!(srv_seq, 0);
        assert_eq!(pt, b"\x00\x01\xff\xffhello");

        let (seq_reply, reply_pkt) = server.seal(MoshDirection::ToClient, b"\x00\x02\x00\x01world").unwrap();
        assert_eq!(seq_reply, 0);
        let (cli_seq, reply_pt) = client.open(MoshDirection::ToClient, &reply_pkt).unwrap();
        assert_eq!(cli_seq, 0);
        assert_eq!(reply_pt, b"\x00\x02\x00\x01world");
    }
}
