"""Cryptography through one door (CRYPTO-LIB, CIPHER, NONCE, HASH, PWD-HASH, CSPRNG, CONST-TIME, CRYPTO-FAIL,
CRYPTO-STRENGTH, CRYPTO-AGILITY). Algorithms are named in ALGORITHMS, so changing one is a configuration change."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ALGORITHMS = {"digest": "sha256", "mac": "sha256", "aead": "AES-256-GCM", "kdf": "scrypt"}
SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1, "maxmem": 64 * 1024 * 1024}
TOKEN_BYTES = 32                                     # 256 bits, above the 128 the rules ask


class CryptoError(ValueError):
    """One error for every failure of decryption or verification: nothing tells a padding from a tag."""


def digest(data: bytes) -> str:
    return hashlib.new(ALGORITHMS["digest"], data).hexdigest()


def mac(key: bytes, data: bytes) -> str:
    if len(key) < 32:
        raise CryptoError("a MAC key has at least 256 bits")
    return hmac.new(key, data, ALGORITHMS["mac"]).hexdigest()


def same(a, b) -> bool:
    """Constant-time comparison of two secrets (str or bytes)."""
    a = a.encode() if isinstance(a, str) else a
    b = b.encode() if isinstance(b, str) else b
    return hmac.compare_digest(a, b)


def token(nbytes: int = TOKEN_BYTES) -> str:
    """A URL-safe random token from the operating system's CSPRNG."""
    if nbytes < 16:
        raise CryptoError("a token has at least 128 bits")
    return secrets.token_urlsafe(nbytes)


def key() -> bytes:
    """A fresh 256-bit key."""
    return AESGCM.generate_key(bit_length=256)


def seal(key_: bytes, data: bytes, context: bytes = b"") -> str:
    """AES-256-GCM with a fresh 96-bit nonce per message; `context` is authenticated, not encrypted."""
    if len(key_) != 32:
        raise CryptoError("an AES-256 key has 32 bytes")
    nonce = os.urandom(12)
    return base64.urlsafe_b64encode(nonce + AESGCM(key_).encrypt(nonce, data, context)).decode()


def open_(key_: bytes, box: str, context: bytes = b"") -> bytes:
    try:
        raw = base64.urlsafe_b64decode(box.encode())
        return AESGCM(key_).decrypt(raw[:12], raw[12:], context)
    except (InvalidTag, ValueError, TypeError):
        raise CryptoError("cannot open") from None


def derive(secret: str, salt: bytes | None = None) -> str:
    """A slow, salted derivation for anything a person types or holds (API keys, recovery codes): `scrypt$…`."""
    salt = salt or os.urandom(16)
    out = hashlib.scrypt(secret.encode(), salt=salt, dklen=32, **SCRYPT)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(out).decode()


def check(secret: str, derived: str) -> bool:
    try:
        kind, salt, expected = derived.split("$")
        if kind != "scrypt":
            return False
        out = hashlib.scrypt(secret.encode(), salt=base64.b64decode(salt), dklen=32, **SCRYPT)
        return same(base64.b64encode(out).decode(), expected)
    except (ValueError, TypeError):
        return False
