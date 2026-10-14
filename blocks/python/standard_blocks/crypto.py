"""Cryptography through one door (CRYPTO-LIB, CIPHER, NONCE, HASH, PWD-HASH, CSPRNG, CONST-TIME, CRYPTO-FAIL,
CRYPTO-STRENGTH, CRYPTO-AGILITY). Algorithms are named in ALGORITHMS, so changing one is a configuration change.

Beyond the checklists, and built to last:
    - every output says what made it (`sv1.<key id>.…`, `scrypt$n$r$p$…`, `tk1.…`): algorithms and parameters can
      change without breaking what was stored, and `needs_rehash` tells when to upgrade a stored value;
    - keys rotate: a Keyring seals with its current key and opens with any key it still holds;
    - sealing derives a fresh key per message (HKDF-SHA-256 over a 256-bit salt) before AES-256-GCM, so the GCM
      limit of 2^32 random nonces per key never binds, and a nonce collision cannot happen in practice;
    - signed tokens carry a purpose and an expiry, so a token minted for one thing (an e-mail link) is refused for
      another (a password reset);
    - every failure is one CryptoError: nothing tells a wrong key from a wrong tag or a bad encoding.
Symmetric primitives (AES-256, SHA-256, HMAC) keep their margin against quantum attacks; the only asymmetric
cryptography the product verifies is the identity provider's signatures (session block), whose algorithm list is
where post-quantum signatures (ML-DSA) will be added when providers issue them.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ALGORITHMS = {"digest": "sha256", "mac": "sha256", "aead": "AES-256-GCM", "kdf": "scrypt", "subkey": "HKDF-SHA256"}
SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1}
SCRYPT_LIMITS = {"n": 2 ** 20, "r": 32, "p": 16}            # a stored hash cannot ask for unbounded work
TOKEN_BYTES = 32                                             # 256 bits, above the 128 the rules ask
SEAL = "sv1"


class CryptoError(ValueError):
    """One error for every failure of decryption or verification: nothing tells a padding from a tag."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


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


def _subkey(key_: bytes, salt: bytes, purpose: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"standard/" + purpose).derive(key_)


class Keyring:
    """Keys by id; seals with `current`, opens with whichever key a box names. Rotation: add the new key, make it
    current, re-seal at leisure (`needs_reseal`), then drop the old one.

        ring = Keyring({"2026-10": secret("data-key-2026-10").reveal().encode()}, current="2026-10")
    """

    def __init__(self, keys: dict, current: str):
        if current not in keys:
            raise CryptoError("the current key is in the ring")
        for kid, k in keys.items():
            if not kid or not all(c.isalnum() or c in "-_" for c in kid) or len(k) != 32:
                raise CryptoError("a key id is [A-Za-z0-9_-] and a key has 32 bytes")
        self.keys, self.current = dict(keys), current

    def seal(self, data: bytes, context: bytes = b"") -> str:
        return _seal(self.keys[self.current], data, context, self.current)

    def open(self, box: str, context: bytes = b"") -> bytes:
        try:
            kid = box.split(".")[1]
        except (AttributeError, IndexError):
            raise CryptoError("cannot open") from None
        if kid not in self.keys:
            raise CryptoError("cannot open")
        return _open(self.keys[kid], box, context, kid)

    def needs_reseal(self, box: str) -> bool:
        return not box.startswith(f"{SEAL}.{self.current}.")


def _seal(key_: bytes, data: bytes, context: bytes, kid: str) -> str:
    if len(key_) != 32:
        raise CryptoError("an AES-256 key has 32 bytes")
    salt, nonce = os.urandom(32), os.urandom(12)
    aad = f"{SEAL}.{kid}.".encode() + context
    sealed = AESGCM(_subkey(key_, salt, b"seal")).encrypt(nonce, data, aad)
    return f"{SEAL}.{kid}.{_b64(salt + nonce + sealed)}"


def _open(key_: bytes, box: str, context: bytes, kid: str) -> bytes:
    try:
        if box.startswith(f"{SEAL}."):
            version, named, body = box.split(".")
            if named != kid:
                raise CryptoError("cannot open")
            raw = _unb64(body)
            aad = f"{SEAL}.{kid}.".encode() + context
            return AESGCM(_subkey(key_, raw[:32], b"seal")).decrypt(raw[32:44], raw[44:], aad)
        raw = base64.urlsafe_b64decode(box.encode())             # boxes sealed before versioning
        return AESGCM(key_).decrypt(raw[:12], raw[12:], context)
    except (InvalidTag, ValueError, TypeError, IndexError):
        raise CryptoError("cannot open") from None


def seal(key_: bytes, data: bytes, context: bytes = b"") -> str:
    """AES-256-GCM under a per-message key derived from `key_`; `context` is authenticated, not encrypted."""
    return _seal(key_, data, context, "0")


def open_(key_: bytes, box: str, context: bytes = b"") -> bytes:
    return _open(key_, box, context, "0")


def derive(secret: str, salt: bytes | None = None) -> str:
    """A slow, salted derivation for anything a person types or holds (API keys, recovery codes):
    `scrypt$n$r$p$salt$hash`, so the cost can rise later without breaking stored values."""
    salt = salt or os.urandom(16)
    p = SCRYPT
    out = hashlib.scrypt(secret.encode(), salt=salt, dklen=32, n=p["n"], r=p["r"], p=p["p"],
                         maxmem=256 * p["n"] * p["r"])
    return f"scrypt${p['n']}${p['r']}${p['p']}${_b64(salt)}${_b64(out)}"


def check(secret: str, derived: str) -> bool:
    try:
        parts = derived.split("$")
        if parts[0] != "scrypt":
            return False
        if len(parts) == 3:                                      # before parameters were stored
            n, r, p, salt, expected = SCRYPT["n"], SCRYPT["r"], SCRYPT["p"], base64.b64decode(parts[1]), \
                base64.b64decode(parts[2])
        else:
            n, r, p = (int(x) for x in parts[1:4])
            salt, expected = _unb64(parts[4]), _unb64(parts[5])
        if not (2 <= n <= SCRYPT_LIMITS["n"] and n & (n - 1) == 0 and 1 <= r <= SCRYPT_LIMITS["r"]
                and 1 <= p <= SCRYPT_LIMITS["p"]):
            return False
        out = hashlib.scrypt(secret.encode(), salt=salt, dklen=len(expected), n=n, r=r, p=p, maxmem=256 * n * r)
        return same(out, expected)
    except (ValueError, TypeError, IndexError):
        return False


def needs_rehash(derived: str) -> bool:
    """True when a stored derivation was made with weaker parameters than today's: re-derive at next use."""
    parts = derived.split("$")
    if len(parts) != 6 or parts[0] != "scrypt":
        return True
    return (int(parts[1]), int(parts[2]), int(parts[3])) < (SCRYPT["n"], SCRYPT["r"], SCRYPT["p"])


def sign_token(key_: bytes, purpose: str, data: dict, ttl_s: int) -> str:
    """A signed, expiring token bound to one purpose: `tk1.<payload>.<mac>` (payload readable, not secret)."""
    if len(key_) < 32 or not purpose or ttl_s <= 0:
        raise CryptoError("a 256-bit key, a purpose and a lifetime")
    payload = _b64(json.dumps({"p": purpose, "e": int(time.time()) + int(ttl_s), "d": data},
                              separators=(",", ":"), sort_keys=True).encode())
    tag = hmac.new(_subkey(key_, b"", b"token/" + purpose.encode()), f"tk1.{payload}".encode(), "sha256").digest()
    return f"tk1.{payload}.{_b64(tag)}"


def verify_token(key_: bytes, purpose: str, value: str) -> dict:
    """The data of a token signed for this purpose and not expired; CryptoError otherwise."""
    try:
        version, payload, tag = value.split(".")
        if version != "tk1" or len(value) > 8192:
            raise CryptoError("invalid")
        expected = hmac.new(_subkey(key_, b"", b"token/" + purpose.encode()), f"tk1.{payload}".encode(),
                            "sha256").digest()
        if not hmac.compare_digest(expected, _unb64(tag)):
            raise CryptoError("invalid")
        body = json.loads(_unb64(payload))
        if body.get("p") != purpose or int(body.get("e", 0)) < time.time():
            raise CryptoError("invalid")
        return body["d"]
    except (ValueError, TypeError, KeyError, AttributeError):
        raise CryptoError("invalid") from None
