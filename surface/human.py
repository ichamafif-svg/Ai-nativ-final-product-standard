"""What a human signs from the surface (§11.4, §12, D16): a review of one exact transition, or an organisational
attestation. Each is an observation under the human's own capability, signed with the human's own key; the kernel
decides whether it is independent enough to permit anything. In production a human signs with a passkey; a key file
is the stand-in for this version.
"""
from __future__ import annotations

import base64
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trusted.signing import Signer, envelope

REVIEW = ("approved", "changes_requested")


def load_signer(identity: str, key_path) -> Signer:
    """A key file holds the base64 of a raw 32-byte Ed25519 private key, readable only by its owner."""
    path = Path(key_path)
    if path.stat().st_mode & 0o077:
        raise PermissionError(f"{path} must be readable by its owner only")
    return Signer(identity, Ed25519PrivateKey.from_private_bytes(base64.b64decode(path.read_text().strip())))


def _at(view: dict, at) -> int:
    return max(int(time.time() * 1000) if at is None else at, view["health"]["as_of"] + 1)


def _observation(view, signer: Signer, under: str, resource: str, prop: str, status: str, at=None) -> dict:
    body = {"id": f"{prop}-{uuid.uuid4().hex}", "at": _at(view, at), "author": signer.identity, "under": under,
            "resource": resource, "property": prop, "status": status, "level": "real"}
    return envelope(view["prefix"]["genesis"], "observation", body, [signer])


def review(view: dict, signer: Signer, under: str, target_id: str, base: str, head: str, verdict: str,
           at=None) -> dict:
    """A review binds the exact transition base → head of one remediable target, never a mutable pointer."""
    if verdict not in REVIEW:
        raise ValueError(f"a review is one of {REVIEW}")
    target = next(t for t in view["law"]["effective"]["targets"] if t["id"] == target_id)
    _, area, item = target["resource"].split(":", 2)
    return _observation(view, signer, under, f"repo:{area}:{item}/{base}/{head}", "review", verdict, at)


def attest(view: dict, signer: Signer, under: str, target_id: str, at=None) -> dict:
    """An organisational attestation: the procedure or register named by the target is current."""
    target = next(t for t in view["law"]["effective"]["targets"] if t["id"] == target_id)
    return _observation(view, signer, under, target["resource"], target["property"], target["expect"], at)
