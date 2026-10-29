"""Python shim for linscp_crypto (pure-Rust: delegates to crates/linscp-crypto logic)

Implements the same `lscp1$` token format as `crates/linscp-crypto/src/lib.rs`:
- 32-byte master key (base64 or raw)
- 16-byte nonce, HMAC-SHA256 keystream, 32-byte tag, base64 blob
- `encrypt(plain, key, nonce=None)` and `decrypt(token, key)`
"""

import base64
import hashlib
import hmac
import os
import pathlib

LSCP1_PREFIX = "lscp1$"
KEY_BYTES = 32
NONCE_BYTES = 16
TAG_BYTES = 32
MAX_PASSWORD_BYTES = 4096

TAG_LABEL = b"lscp1"
ENC_KEY_LABEL = b"LinSCP sessions file v1 encryption key"
MAC_KEY_LABEL = b"LinSCP sessions file v1 authentication key"

class PasswordError(Exception):
    pass

class CryptoError(PasswordError):
    pass

def _hmac_sha256(key, parts):
    m = hmac.new(key, digestmod=hashlib.sha256)
    for part in parts:
        m.update(part)
    return m.digest()

def _derive_subkeys(master):
    if len(master) != KEY_BYTES:
        raise PasswordError("The encryption key must be 32 bytes.")
    enc_key = _hmac_sha256(master, [ENC_KEY_LABEL])
    mac_key = _hmac_sha256(master, [MAC_KEY_LABEL])
    return enc_key, mac_key

def _xor_keystream(enc_key, nonce, data):
    out = bytearray()
    counter = 0
    offset = 0
    while offset < len(data):
        counter_be = counter.to_bytes(4, "big")
        block = _hmac_sha256(enc_key, [nonce, counter_be])
        take = min(len(data) - offset, len(block))
        for i in range(take):
            out.append(data[offset + i] ^ block[i])
        offset += take
        counter += 1
    return bytes(out)

def encrypt(plain, key, nonce=None):
    if isinstance(plain, str):
        data = plain.encode("utf-8")
    else:
        data = bytes(plain)
    if len(data) > MAX_PASSWORD_BYTES:
        raise PasswordError("The password is too long to store.")
    if len(key) != KEY_BYTES:
        raise PasswordError("The encryption key must be 32 bytes.")
    if nonce is None:
        nonce = os.urandom(NONCE_BYTES)
    else:
        if len(nonce) != NONCE_BYTES:
            raise PasswordError("The nonce must be 16 bytes.")
        nonce = bytes(nonce)
    enc_key, mac_key = _derive_subkeys(key)
    cipher = _xor_keystream(enc_key, nonce, data)
    tag = _hmac_sha256(mac_key, [TAG_LABEL, nonce, cipher])
    blob = nonce + cipher + tag
    return LSCP1_PREFIX + base64.b64encode(blob).decode("ascii")

def decrypt(token, key):
    if not isinstance(token, str) or not token.startswith(LSCP1_PREFIX):
        raise PasswordError("The stored password is not encrypted with a known format.")
    if len(key) != KEY_BYTES:
        raise PasswordError("The encryption key must be 32 bytes.")
    b64_part = token[len(LSCP1_PREFIX):]
    try:
        blob = base64.b64decode(b64_part, validate=True)
    except Exception:
        raise PasswordError("The stored password is corrupted: its encoding is not valid base64 of the expected shape.")
    if len(blob) < NONCE_BYTES + TAG_BYTES or len(blob) - NONCE_BYTES - TAG_BYTES > MAX_PASSWORD_BYTES:
        raise PasswordError("The stored password is corrupted: its encoding is not valid base64 of the expected shape.")
    nonce = blob[:NONCE_BYTES]
    cipher = blob[NONCE_BYTES:-TAG_BYTES] if TAG_BYTES else blob[NONCE_BYTES:]
    tag = blob[-TAG_BYTES:]
    enc_key, mac_key = _derive_subkeys(key)
    expected_tag = _hmac_sha256(mac_key, [TAG_LABEL, nonce, cipher])
    if not hmac.compare_digest(tag, expected_tag):
        raise PasswordError("The stored password does not match this key file: it was encrypted somewhere else, or the value was modified.")
    plain_bytes = _xor_keystream(enc_key, nonce, cipher)
    try:
        return plain_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise PasswordError("The stored password decrypted to bytes that are not text.")

def load_key(path):
    p = pathlib.Path(path)
    try:
        data = p.read_bytes()
    except FileNotFoundError:
        raise PasswordError(f"The encryption key file '{path}' does not exist")
    # Trim whitespace
    trimmed = data.strip()
    if len(trimmed) == KEY_BYTES:
        return bytes(trimmed)
    # Try base64
    try:
        decoded = base64.b64decode(trimmed, validate=True)
        if len(decoded) == KEY_BYTES:
            return decoded
    except Exception:
        pass
    # Also handle raw with newline
    if len(data) == KEY_BYTES or len(data.strip()) == KEY_BYTES:
        return bytes(data.strip()[:KEY_BYTES])
    raise PasswordError(f"The encryption key file '{path}' does not contain a 32-byte key")

def key_path_for(ini_path):
    if not ini_path:
        return ""
    if ini_path.endswith(".ini"):
        return ini_path[:-4] + ".key"
    return ini_path + ".key"
