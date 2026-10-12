"""Producing signed statements (Ed25519). Used by the guard and by clients; the kernel never signs.

A Signer holds one private key. In production it lives in the process (or HSM) of the role it signs for, never in U.
"""
from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from kernel.canon import canon
from kernel.identity import PAYLOAD_TYPE, keyid, pae, statement


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


def envelope(domain: str, kind: str, body: dict, signers) -> dict:
    """Several signers co-sign one statement (thresholds); signatures in key order, one per key."""
    payload = canon(statement(domain, kind, body))
    message = pae(payload)
    sigs = sorted((s.sign(message) for s in {s.keyid: s for s in signers}.values()), key=lambda s: s["keyid"])
    return {"payloadType": PAYLOAD_TYPE, "payload": base64.b64encode(payload).decode(), "signatures": sigs}


def entry(state: dict, kind: str, body: dict, signers) -> dict:
    domain = "genesis" if kind == "genesis" else state["domain"]
    return {"seq": state["size"], "prev": state["head"], "envelope": envelope(domain, kind, body, signers)}
