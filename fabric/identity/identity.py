"""The identity the gateway hands to the product (D68): a short JWS (EdDSA) signed by the platform's key service.

The gateway removes every identity header a client sent, then states who the request is from in one header,
`x-standard-identity`, as a compact JWS: standard, so any JOSE library verifies it (the access block does). It
lives a minute and names its audience, the product. Even if a wall gave way and a forged header reached the
product, it would not verify: the key never enters the bac.

The signer is pluggable: a local Ed25519 key for the prototype, the key service (OpenBao transit) otherwise.
"""
from __future__ import annotations

import base64
import json
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

HEADER = "x-standard-identity"
TTL_S = 60
CLAIMS = ("sub", "email", "groups", "acr", "amr")


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class LocalSigner:
    """An Ed25519 key in a file the platform owns (created on first use, mode 0600). Prototype only."""

    def __init__(self, path):
        path = Path(path)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            path.chmod(0o600)
        self._key = serialization.load_pem_private_key(path.read_bytes(), password=None)

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)

    def public_pem(self) -> str:
        return self._key.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def mint(signer, claims: dict, *, audience: str, now: float | None = None) -> str:
    """A compact JWS for these claims, valid TTL_S seconds, for this audience only."""
    issued = int(now if now is not None else time.time())
    payload = {**{k: claims[k] for k in CLAIMS if claims.get(k) not in (None, "", [])},
               "aud": audience, "iss": "standard-gateway", "iat": issued, "exp": issued + TTL_S}
    head = b64(json.dumps({"alg": "EdDSA", "typ": "JWT"}, separators=(",", ":")).encode())
    body = b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{head}.{body}".encode()
    return f"{head}.{body}.{b64(signer.sign(signing_input))}"


def verify(token: str, public_pem: str, *, audience: str, now: float | None = None) -> dict:
    """The claims of a token this platform signed for this audience, or ValueError. Reference verifier."""
    try:
        head, body, sig = token.split(".")
        key = serialization.load_pem_public_key(public_pem.encode())
        if not isinstance(key, Ed25519PublicKey) or json.loads(unb64(head)).get("alg") != "EdDSA":
            raise ValueError("not an EdDSA token")
        key.verify(unb64(sig), f"{head}.{body}".encode())
        claims = json.loads(unb64(body))
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"identity refused: {type(exc).__name__}") from None
    at = now if now is not None else time.time()
    if claims.get("aud") != audience or claims.get("iss") != "standard-gateway" or not claims["iat"] <= at < claims["exp"]:
        raise ValueError("identity refused: audience, issuer or time")
    return claims
