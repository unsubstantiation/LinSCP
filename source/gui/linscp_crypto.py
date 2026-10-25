"""Encrypted stored passwords for ``sessions.ini`` - the Python side.

This mirrors the ``lscp1$`` format in ``source/linux/SessionStore.cpp``:
the console client encrypts a stored password on save, this module
decrypts it when the graphical client lists sessions. Both sides must
produce and consume exactly the same bytes - a version prefix, then
base64 of ``nonce[16] || ciphertext || tag[32]``:

* encryption key / authentication key: HMAC-SHA256 of the raw 32-byte
  key file under fixed labels (the same strings the C++ side uses),
* keystream: HMAC-SHA256(enc_key, nonce || block_counter big endian),
* tag: HMAC-SHA256(mac_key, b"lscp1" || nonce || ciphertext).

The key file sits next to ``sessions.ini`` (``sessions.ini`` ->
``sessions.key``, anything else gains ``.key``) and holds base64 of 32
random bytes (or the raw 32 bytes). The test suites pin both
implementations to shared test vectors and cross-language round trips.

Only the standard library is used, and this file is importable without
starting anything (the GUI server imports it at module load).
"""

import base64
import hashlib
import hmac
import os

PREFIX = "lscp1$"
PREFIX_BYTES = b"lscp1$"
TAG_LABEL = b"lscp1"
ENC_KEY_LABEL = b"LinSCP sessions file v1 encryption key"
MAC_KEY_LABEL = b"LinSCP sessions file v1 authentication key"
KEY_BYTES = 32
NONCE_BYTES = 16
TAG_BYTES = 32
MAX_PASSWORD_BYTES = 4096


class PasswordError(ValueError):
    """A stored password could not be decrypted (or is malformed)."""


def key_path_for(ini_path):
    """The key file that pairs with a sessions file path."""
    if not ini_path:
        return ""
    if ini_path.endswith(".ini"):
        return ini_path[:-4] + ".key"
    return ini_path + ".key"


def load_key(key_path):
    """Read the key file: raw 32 bytes or base64 of them.

    Raises PasswordError with the same wording the console client uses
    for the failure modes users see.
    """
    if not key_path:
        raise PasswordError(
            "There is no configuration directory to keep a key file in")
    try:
        with open(key_path, "rb") as handle:
            content = handle.read()
    except FileNotFoundError:
        raise PasswordError(
            "the encryption key file '%s' does not exist (it is created "
            "when the first password is stored); restore it from a copy or "
            "store the password again" % key_path) from None
    except OSError as exc:
        raise PasswordError(
            "The encryption key file '%s' cannot be read (%s)." %
            (key_path, exc)) from None

    if len(content) == KEY_BYTES:
        return content
    trimmed = content.strip()
    if len(trimmed) == KEY_BYTES:
        return trimmed
    try:
        decoded = base64.b64decode(trimmed, validate=True)
    except Exception:
        decoded = b""
    if len(decoded) == KEY_BYTES:
        return decoded
    raise PasswordError(
        "The encryption key file '%s' does not contain a 32-byte key "
        "(base64 or raw); remove it to have a new one created, or restore "
        "it from a copy." % key_path)


def _derive_keys(master):
    if len(master) != KEY_BYTES:
        raise PasswordError("The encryption key must be 32 bytes.")
    enc_key = hmac.new(master, ENC_KEY_LABEL, hashlib.sha256).digest()
    mac_key = hmac.new(master, MAC_KEY_LABEL, hashlib.sha256).digest()
    return enc_key, mac_key


def _keystream_block(enc_key, nonce, counter):
    return hmac.new(
        enc_key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()


def encrypt(plain, key, nonce=None):
    """Encrypt a password into a ``lscp1$...`` value.

    'nonce' is only for the test suites, which need a fixed vector;
    production callers get fresh randomness per encryption.
    """
    if not isinstance(plain, str):
        plain = plain.decode("utf-8")
    data = plain.encode("utf-8")
    if len(data) > MAX_PASSWORD_BYTES:
        raise PasswordError("The password is too long to store.")
    enc_key, mac_key = _derive_keys(key)
    if nonce is None:
        nonce = os.urandom(NONCE_BYTES)
    if len(nonce) != NONCE_BYTES:
        raise PasswordError("The nonce must be 16 bytes.")

    out = bytearray()
    counter = 0
    done = 0
    while done < len(data):
        block = _keystream_block(enc_key, nonce, counter)
        take = min(len(block), len(data) - done)
        for i in range(take):
            out.append(data[done + i] ^ block[i])
        done += take
        counter += 1
    cipher = bytes(out)

    tag = hmac.new(
        mac_key, TAG_LABEL + nonce + cipher, hashlib.sha256).digest()
    blob = nonce + cipher + tag
    return PREFIX + base64.b64encode(blob).decode("ascii")


def decrypt(encoded, key):
    """Decrypt a ``lscp1$...`` value back to the password string.

    Raises PasswordError when the value is not in the expected shape or
    does not authenticate under this key.
    """
    if not isinstance(encoded, str):
        encoded = encoded.decode("ascii", "replace")
    if not encoded.startswith(PREFIX):
        raise PasswordError(
            "The stored password is not encrypted with a known format.")
    try:
        blob = base64.b64decode(encoded[len(PREFIX):].encode("ascii"),
                                validate=True)
    except Exception:
        blob = b""
    if (len(blob) < NONCE_BYTES + TAG_BYTES or
            len(blob) - NONCE_BYTES - TAG_BYTES > MAX_PASSWORD_BYTES):
        raise PasswordError(
            "The stored password is corrupted: its encoding is not valid "
            "base64 of the expected shape.")

    nonce = blob[:NONCE_BYTES]
    cipher = blob[NONCE_BYTES:-TAG_BYTES]
    tag = blob[-TAG_BYTES:]

    enc_key, mac_key = _derive_keys(key)
    expected = hmac.new(
        mac_key, TAG_LABEL + nonce + cipher, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise PasswordError(
            "The stored password does not match this key file: it was "
            "encrypted somewhere else, or the value was modified.")

    out = bytearray()
    counter = 0
    done = 0
    while done < len(cipher):
        block = _keystream_block(enc_key, nonce, counter)
        take = min(len(block), len(cipher) - done)
        for i in range(take):
            out.append(cipher[done + i] ^ block[i])
        done += take
        counter += 1
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        raise PasswordError(
            "The stored password decrypted to bytes that are not text.") \
            from None
