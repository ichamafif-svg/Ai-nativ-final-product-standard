"""T03 — trusted time from independently provisioned signing witnesses (ARCHITECTURE.md §7.2, D07).

A fresh random challenge per reading prevents replay; at least two distinct witness keys must agree exactly (the
kernel consumes one integer, so a non-zero uncertainty is refused); time never moves backwards. The witnesses' keys
and transport must be protected outside the agent; their independence is a deployment property to qualify.
"""
from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from kernel.canon import canon

PREFIX = b"standard:time-witness:v1\x00"


class ClockError(ValueError):
    pass


class WitnessClock:
    """Callable: returns trusted milliseconds, or raises ClockError."""

    def __init__(self, *, genesis: str, public_keys: dict, quorum: int, fetch):
        if (not isinstance(genesis, str) or not genesis or not isinstance(public_keys, dict) or len(public_keys) < 2
                or any(not isinstance(v, bytes) or len(v) != 32 for v in public_keys.values())
                or type(quorum) is not int or not 2 <= quorum <= len(public_keys) or not callable(fetch)):
            raise ClockError("TIME.CONFIGURATION")
        self.genesis, self.keys, self.quorum, self.fetch, self.last = genesis, dict(public_keys), quorum, fetch, -1

    def __call__(self) -> int:
        nonce = base64.b64encode(os.urandom(24)).decode()
        try:
            quotes = self.fetch(nonce)
        except Exception as exc:
            raise ClockError("TIME.UNAVAILABLE") from exc
        if not isinstance(quotes, list) or not self.quorum <= len(quotes) <= len(self.keys):
            raise ClockError("TIME.QUORUM")
        seen, times = set(), set()
        for quote in quotes:
            if not isinstance(quote, dict) or set(quote) != {"claim", "signature"}:
                raise ClockError("TIME.QUOTE")
            claim = quote["claim"]
            if not isinstance(claim, dict) or set(claim) != {"genesis", "nonce", "witness", "at"}:
                raise ClockError("TIME.CLAIM")
            key = self.keys.get(claim["witness"])
            if (key is None or claim["witness"] in seen or claim["genesis"] != self.genesis or claim["nonce"] != nonce
                    or type(claim["at"]) is not int or claim["at"] < 0):
                raise ClockError("TIME.BINDING")
            try:
                signature = base64.b64decode(quote["signature"], validate=True)
                Ed25519PublicKey.from_public_bytes(key).verify(signature, PREFIX + canon(claim))
            except (InvalidSignature, ValueError, TypeError) as exc:
                raise ClockError("TIME.SIGNATURE") from exc
            seen.add(claim["witness"])
            times.add(claim["at"])
        if len(times) != 1 or min(times) < self.last:
            raise ClockError("TIME.DISAGREEMENT_OR_ROLLBACK")
        self.last = min(times)
        return self.last
