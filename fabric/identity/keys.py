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
import hashlib
import os
import re
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

    def restrict(self, secrets, keys: dict, *, ttl_s: int = 3600) -> "OpenBao":
        """Provision a native child token for one egress instance, with no inherited default policy.

        The provisioning credential stays with the control process. The proxy receives only
        the child token. Expiry fails closed; this prototype deliberately does not auto-renew it.
        """
        if type(ttl_s) is not int or not 1 <= ttl_s <= 3600:
            raise ValueError("egress token TTL must be 1..3600 seconds")
        policy = egress_policy(secrets, keys)
        name = "standard-egress-" + hashlib.sha256(policy.encode()).hexdigest()
        self.call("PUT", f"sys/policies/acl/{name}", {"policy": policy})
        result = self.call("POST", "auth/token/create", {
            "policies": [name], "no_default_policy": True, "renewable": False,
            "ttl": f"{ttl_s}s", "explicit_max_ttl": f"{ttl_s}s",
        })
        return OpenBao(self.address, result["auth"]["client_token"], timeout=self.timeout)

    def revoke(self) -> None:
        self.call("POST", "auth/token/revoke-self")

    def product_operation(self, operation: str, key: str, body: dict, *, capabilities: dict) -> dict:
        """A product may use only the exact keys and operations granted to its instance."""
        if not key.startswith(PRODUCT_KEYS) or operation not in capabilities.get(key, ()):
            raise KeyServiceError("not a product key or not a product operation")
        allowed = {k: body[k] for k in ("plaintext", "ciphertext", "input", "signature", "hmac") if k in body}
        return self.call("POST", f"transit/{operation}/{key}", allowed)["data"]


def egress_policy(secrets, keys: dict) -> str:
    """Translate explicit capabilities to OpenBao ACLs; wildcards and path injection are refused."""
    paths = {"auth/token/revoke-self": {"capabilities": ["update"]}}
    safe = re.compile(r"[A-Za-z0-9_-]{1,128}")
    for name in secrets:
        if not isinstance(name, str) or not safe.fullmatch(name):
            raise ValueError("invalid secret name")
        paths[f"secret/data/{name}"] = {"capabilities": ["read"]}
    for key, operations in keys.items():
        if not isinstance(key, str) or not safe.fullmatch(key) or not key.startswith(PRODUCT_KEYS):
            raise ValueError("invalid product key")
        if not isinstance(operations, (list, tuple)) or not operations:
            raise ValueError("explicit key operations required")
        for operation in operations:
            if operation not in ("encrypt", "decrypt", "hmac", "sign", "verify"):
                raise ValueError("invalid key operation")
            paths[f"transit/{operation}/{key}"] = {"capabilities": ["update"]}
    return json.dumps({"path": paths}, sort_keys=True)


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
    """The identity signer of `fabric/identity/identity.py`, with the key held by the key service."""

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
