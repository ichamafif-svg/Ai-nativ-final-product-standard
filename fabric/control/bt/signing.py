"""Producing signed statements (Ed25519). Used by the guard and by clients; the kernel never signs.

A Signer holds one private key. In production it lives in the process (or HSM) of the role it signs for, never in U.
A KeyServiceSigner holds none: the key stays in a key service (OpenBao's transit engine, an instance dedicated to
Standard's own keys, never the product's), which signs by key name; the process only holds a token scoped to sign.
Both produce the same Ed25519 signatures; the kernel cannot tell them apart and need not.
"""
from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from fabric.control.kernel.canon import canon
from fabric.control.kernel.identity import PAYLOAD_TYPE, keyid, pae, statement


class Signer:
    def __init__(self, identity: str, private_key: Ed25519PrivateKey):
        self.identity, self._key = identity, private_key
        raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.public = base64.b64encode(raw).decode()
        self.keyid = keyid(self.public)

    def root_key(self) -> dict:
        return {"alg": "ed25519", "public": self.public, "keyid": self.keyid}

    def sign(self, message: bytes) -> dict:
        return {"keyid": self.keyid, "sig": base64.b64encode(self._key.sign(message)).decode()}


class KeyServiceSigner:
    """Signs through the key service: the private key never enters this process (D68, trust core)."""

    def __init__(self, identity: str, address: str, token: str, key: str, *, timeout: float = 5.0):
        self.identity, self.address, self.token, self.key = identity, address.rstrip("/"), token, key
        self.timeout = timeout
        keys = self._call("GET", f"transit/keys/{key}")["data"]
        if keys.get("type") != "ed25519":
            raise ValueError(f"key {key} is not an Ed25519 key")
        latest = str(max(int(v) for v in keys["keys"]))
        self.public = keys["keys"][latest]["public_key"]
        self.keyid = keyid(self.public)

    def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        request = urllib.request.Request(f"{self.address}/v1/{path}", method=method,
                                         data=json.dumps(body).encode() if body is not None else None,
                                         headers={"X-Vault-Token": self.token, "content-type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as r:
                return json.loads(r.read())
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise RuntimeError(f"key service unavailable for {self.identity}: {type(exc).__name__}") from None

    def root_key(self) -> dict:
        return {"alg": "ed25519", "public": self.public, "keyid": self.keyid}

    def sign(self, message: bytes) -> dict:
        out = self._call("POST", f"transit/sign/{self.key}", {"input": base64.b64encode(message).decode()})
        return {"keyid": self.keyid, "sig": out["data"]["signature"].split(":", 2)[2]}


def envelope(domain: str, kind: str, body: dict, signers) -> dict:
    """Several signers co-sign one statement (thresholds); signatures in key order, one per key."""
    payload = canon(statement(domain, kind, body))
    message = pae(payload)
    sigs = sorted((s.sign(message) for s in {s.keyid: s for s in signers}.values()), key=lambda s: s["keyid"])
    return {"payloadType": PAYLOAD_TYPE, "payload": base64.b64encode(payload).decode(), "signatures": sigs}


def entry(state: dict, kind: str, body: dict, signers) -> dict:
    domain = "genesis" if kind == "genesis" else state["domain"]
    return {"seq": state["size"], "prev": state["head"], "envelope": envelope(domain, kind, body, signers)}
