"""T03 — trusted time from independently provisioned signing witnesses (ARCHITECTURE.md §7.2, D07).

A fresh random challenge per reading prevents replay; at least two distinct witness keys must agree within a bounded
spread (`tolerance_ms`, 0 by default: exact agreement). The kernel consumes one integer: the clock returns the latest
quote, the conservative reading for every use of this time (a departure window, an expiry, the horizon of a health
verdict: a later instant only closes or escalates sooner; widening delays run on witnessed checkpoints, never on this
clock). Time never moves backwards, across restarts too when `state` names a file. The witnesses' keys and transport
must be protected outside the agent; their independence is a deployment property to qualify.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from kernel.canon import canon

PREFIX = b"standard:time-witness:v1\x00"


class ClockError(ValueError):
    pass


class WitnessClock:
    """Callable: returns trusted milliseconds, or raises ClockError."""

    MAX_TOLERANCE_MS = 5_000

    def __init__(self, *, genesis: str, public_keys: dict, quorum: int, fetch, tolerance_ms: int = 0, state=None):
        if (not isinstance(genesis, str) or not genesis or not isinstance(public_keys, dict) or len(public_keys) < 2
                or any(not isinstance(v, bytes) or len(v) != 32 for v in public_keys.values())
                or type(quorum) is not int or not 2 <= quorum <= len(public_keys) or not callable(fetch)
                or type(tolerance_ms) is not int or not 0 <= tolerance_ms <= self.MAX_TOLERANCE_MS):
            raise ClockError("TIME.CONFIGURATION")
        self.genesis, self.keys, self.quorum, self.fetch = genesis, dict(public_keys), quorum, fetch
        self.tolerance, self.state = tolerance_ms, Path(state) if state else None
        self.last = self._load()

    def _load(self) -> int:
        if self.state is None or not self.state.exists():
            return -1
        try:
            saved = json.loads(self.state.read_text())
        except (OSError, ValueError) as exc:
            raise ClockError("TIME.STATE") from exc
        if not isinstance(saved, dict) or saved.get("genesis") != self.genesis or type(saved.get("last")) is not int:
            raise ClockError("TIME.STATE")
        return saved["last"]

    def _save(self, value: int) -> None:
        if self.state is None:
            return
        tmp = self.state.with_suffix(".tmp")
        with open(tmp, "w") as f:
            f.write(json.dumps({"genesis": self.genesis, "last": value}))
            f.flush()
            os.fsync(f.fileno())
        tmp.replace(self.state)

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
        if max(times) - min(times) > self.tolerance:
            raise ClockError("TIME.DISAGREEMENT")
        now = max(times)
        if now < self.last:
            raise ClockError("TIME.ROLLBACK")
        self._save(now)
        self.last = now
        return now
