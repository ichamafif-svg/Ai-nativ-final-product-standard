"""The human's three gestures (§11.4, §12, D51), each one statement signed with the human's own key.

    yes      decide(resource)      `decision = approve` on the exact resource of one move: its human route may hold
    no       refuse(scope)         freeze the move's resource, or a whole scope: nothing acts on it any more
    rules    rules(client)         put new rules in force (a widening: the human signs it)

Lifting a no (`release`) is a widening too. The kernel decides whether a statement is admitted and what it permits.
In production the human signs with a passkey in the console; a key file is the stand-in for the command line.
"""
from __future__ import annotations

import base64
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bt.signing import Signer, envelope


def load_signer(identity: str, key_path) -> Signer:
    """A key file holds the base64 of a raw 32-byte Ed25519 private key, readable only by its owner."""
    path = Path(key_path)
    if path.stat().st_mode & 0o077:
        raise PermissionError(f"{path} must be readable by its owner only")
    return Signer(identity, Ed25519PrivateKey.from_private_bytes(base64.b64decode(path.read_text().strip())))


def _at(view: dict, at) -> int:
    return max(int(time.time() * 1000) if at is None else at, view["health"]["as_of"] + 1)


def _statement(view: dict, signer: Signer, kind: str, at=None, **fields) -> dict:
    body = {"id": f"{kind}-{uuid.uuid4().hex}", "at": _at(view, at), "author": signer.identity, **fields}
    return envelope(view["prefix"]["genesis"], kind, body, [signer])


def decide(view: dict, signer: Signer, under: str, resource: str, at=None) -> dict:
    """Yes to one move, on its exact resource (a transition base/head, a switch from/to): never a mutable pointer."""
    if "/" not in resource:
        raise ValueError("a decision names the exact resource of a move")
    return _statement(view, signer, "observation", at, under=under, resource=resource, property="decision",
                      status="approve", level="real")


def refuse(view: dict, signer: Signer, scope: str, at=None) -> dict:
    """No: freeze one move's resource, or a scope (`run:release:*` stops every deployment)."""
    return _statement(view, signer, "freeze", at, scope=scope)


def release(view: dict, signer: Signer, scope: str, at=None) -> dict:
    """Lift a no: unfreeze a scope the human froze."""
    return _statement(view, signer, "unfreeze", at, scope=scope)


def rules(view: dict, signer: Signer, client: dict, at=None) -> dict:
    """New rules of the game, in force with this entry unless the rules in force ask widenings to wait."""
    return _statement(view, signer, "law", at, client=client)
