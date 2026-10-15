"""The key service and the secret broker (D68): OpenBao, reached only by the platform.

Keys never leave OpenBao: the platform asks it to sign, encrypt, decrypt or MAC by key name (the transit engine).
Secrets are read from its key-value store by the egress proxy at the moment it injects them into a call to a host
the rules allow, and by nothing else; they never enter the bac. The product reaches the key service only through
the egress door, at `http://keys.standard/`, restricted to its own keys (`product-*`); it never holds a token.

    bao = OpenBao("http://127.0.0.1:8200", token)
    bao.sign("identity", data) ; bao.public_pem("identity") ; bao.secret("stripe")

`dev(state)` starts an in-memory development server for the prototype and tests: nothing it holds survives it.
A production installation runs OpenBao with sealed persistent storage and a token scoped by policy.
"""
from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PRODUCT_KEYS = "product-"


class KeyServiceError(RuntimeError):
    pass


class OpenBao:
    def __init__(self, address: str, token: str, *, timeout: float = 5.0):
        self.address, self.token, self.timeout = address.rstrip("/"), token, timeout

    def call(self, method: str, path: str, body: dict | None = None) -> dict:
        request = urllib.request.Request(f"{self.address}/v1/{path}", method=method,
                                         data=json.dumps(body).encode() if body is not None else None,
                                         headers={"X-Vault-Token": self.token, "content-type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            raise KeyServiceError(f"{method} {path}: {e.code}") from None
        except OSError as e:
            raise KeyServiceError(f"{method} {path}: unreachable ({type(e).__name__})") from None
        return json.loads(raw) if raw else {}

    # ---- set-up (the platform, at installation) ------------------------------------------------------------------
    def enable(self, path: str, kind: str) -> None:
        try:
            self.call("POST", f"sys/mounts/{path}", {"type": kind})
        except KeyServiceError as exc:
            if ": 400" not in str(exc):                     # already mounted
                raise

    def create_key(self, name: str, kind: str = "ed25519") -> None:
        self.call("POST", f"transit/keys/{name}", {"type": kind})

    def put_secret(self, name: str, value: str) -> None:
        self.call("POST", f"secret/data/{name}", {"data": {"value": value}})

    # ---- use -------------------------------------------------------------------------------------------------------
    def sign(self, key: str, data: bytes) -> bytes:
        out = self.call("POST", f"transit/sign/{key}", {"input": base64.b64encode(data).decode()})
        return base64.b64decode(out["data"]["signature"].split(":", 2)[2])

    def public_pem(self, key: str) -> str:
        keys = self.call("GET", f"transit/keys/{key}")["data"]["keys"]
        raw = base64.b64decode(keys[str(max(int(v) for v in keys))]["public_key"])
        return Ed25519PublicKey.from_public_bytes(raw).public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def secret(self, name: str) -> str:
        return self.call("GET", f"secret/data/{name}")["data"]["data"]["value"]

    def product_operation(self, operation: str, key: str, body: dict) -> dict:
        """What a product may ask of the key service: its own keys only, four operations only."""
        if not key.startswith(PRODUCT_KEYS) or operation not in ("encrypt", "decrypt", "hmac", "sign", "verify"):
            raise KeyServiceError("not a product key or not a product operation")
        allowed = {k: body[k] for k in ("plaintext", "ciphertext", "input", "signature", "hmac") if k in body}
        return self.call("POST", f"transit/{operation}/{key}", allowed)["data"]


def service_certificates(bao: OpenBao, names, *, ttl: str = "72h") -> dict:
    """mTLS between the platform's services on different machines (D68): a private authority in OpenBao's PKI
    engine, and one short-lived certificate per service, usable as client and server. On one machine the services
    speak over Unix sockets, which no network reaches; these certificates are for the managed service."""
    bao.enable("pki", "pki")
    bao.call("POST", "sys/mounts/pki/tune", {"max_lease_ttl": "87600h"})
    root = bao.call("POST", "pki/root/generate/internal", {"common_name": "standard-platform", "ttl": "87600h",
                                                           "key_type": "ec", "key_bits": 256})
    bao.call("POST", "pki/roles/service", {"allowed_domains": "standard.internal", "allow_subdomains": True,
                                           "server_flag": True, "client_flag": True, "key_type": "ec",
                                           "key_bits": 256, "max_ttl": ttl})
    out = {"ca": root["data"]["certificate"]}
    for name in names:
        issued = bao.call("POST", "pki/issue/service", {"common_name": f"{name}.standard.internal", "ttl": ttl})["data"]
        out[name] = {"certificate": issued["certificate"], "private_key": issued["private_key"]}
    return out


class OpenBaoSigner:
    """The identity signer of `enclosure/identity.py`, with the key held by the key service."""

    def __init__(self, bao: OpenBao, key: str = "identity"):
        self.bao, self.key = bao, key

    def sign(self, data: bytes) -> bytes:
        return self.bao.sign(self.key, data)

    def public_pem(self) -> str:
        return self.bao.public_pem(self.key)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def dev(state, binary: str) -> tuple[OpenBao, subprocess.Popen]:
    """An in-memory development OpenBao with transit and KV ready, its token random and kept by the platform."""
    port, token = _free_port(), base64.urlsafe_b64encode(os.urandom(24)).decode()
    log = open(Path(state) / "openbao.log", "ab")
    process = subprocess.Popen([binary, "server", "-dev", f"-dev-root-token-id={token}",
                                f"-dev-listen-address=127.0.0.1:{port}"], stdout=log, stderr=subprocess.STDOUT)
    log.close()
    bao = OpenBao(f"http://127.0.0.1:{port}", token)
    end = time.monotonic() + 20
    while time.monotonic() < end:
        try:
            bao.call("GET", "sys/health")
            break
        except KeyServiceError:
            time.sleep(0.1)
    else:
        process.kill()
        raise KeyServiceError("the development key service did not start")
    bao.enable("transit", "transit")
    return bao, process
