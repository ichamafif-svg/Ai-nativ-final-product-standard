"""T09 — escalation delivery (ARCHITECTURE.md §9.3, §10).

Persist before send, mark *attempted* before the network call, confirm by a signed readback that binds the key, the
payload and the recipients. A lost answer never causes a second send: a later pass only reads back. Without a valid
receipt the delivery stays UNKNOWN. A provider signature does not prove that a person read the alert.
"""
from __future__ import annotations

import base64
import os
import sqlite3
from contextlib import closing
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from kernel.canon import canon, digest, parse

PREFIX = b"standard:delivery-receipt:v1\x00"


class DeliveryError(ValueError):
    pass


class EscalationOutbox:
    def __init__(self, path, *, transport, provider_keys: dict, genesis: str, create: bool = False):
        if not callable(getattr(transport, "send", None)) or not callable(getattr(transport, "readback", None)):
            raise DeliveryError("DELIVERY.TRANSPORT")
        if not provider_keys or any(not isinstance(v, bytes) or len(v) != 32 for v in provider_keys.values()):
            raise DeliveryError("DELIVERY.PROVIDER_KEYS")
        self.path, self.transport, self.keys, self.genesis = Path(path).resolve(), transport, dict(provider_keys), genesis
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            os.close(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
            with closing(self._db()) as db:
                db.execute("CREATE TABLE deliveries (key TEXT PRIMARY KEY, payload BLOB NOT NULL, status TEXT NOT NULL,"
                           " receipt BLOB)")
        elif not self.path.is_file():
            raise DeliveryError("DELIVERY.OUTBOX_MISSING")

    def _db(self):
        db = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, isolation_level=None, timeout=10)
        db.execute("PRAGMA synchronous=FULL")
        return db

    def enqueue(self, verdict: dict) -> list:
        """Stage every escalated gap of a current, authenticated health verdict, under a key stable per gap."""
        if (not isinstance(verdict, dict) or verdict.get("state") not in ("PROVEN", "IN_PROGRESS", "ESCALATED")
                or not isinstance(verdict.get("head"), str) or not isinstance(verdict.get("escalated"), list)):
            raise DeliveryError("DELIVERY.UNTRUSTED_HEALTH")
        staged = []
        for gap in verdict["escalated"]:
            recipients = gap.get("escalated_to") if isinstance(gap, dict) else None
            if (not isinstance(recipients, list) or not recipients or not all(isinstance(r, str) and r for r in recipients)
                    or type(gap.get("opened")) is not int or type(gap.get("due")) is not int
                    or not isinstance(gap.get("obligation"), str)):
                raise DeliveryError("DELIVERY.GAP")
            key = digest({"genesis": self.genesis, "obligation": gap["obligation"], "opened": gap["opened"],
                          "recipients": recipients})
            payload = canon({"key": key, "genesis": self.genesis, "head": verdict["head"], "obligation": gap["obligation"],
                             "opened": gap["opened"], "due": gap["due"], "recipients": recipients})
            staged.append((key, payload))
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            db.executemany("INSERT OR IGNORE INTO deliveries VALUES (?, ?, 'pending', NULL)", staged)
            db.commit()
        return [key for key, _ in staged]

    def deliver(self, key: str) -> str:
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT payload, status FROM deliveries WHERE key=?", (key,)).fetchone()
            if row is None:
                db.rollback()
                raise DeliveryError("DELIVERY.UNKNOWN_KEY")
            raw, status = bytes(row[0]), row[1]
            if status == "pending":
                db.execute("UPDATE deliveries SET status='attempted' WHERE key=?", (key,))
            db.commit()
        if status == "delivered":
            return status
        if status == "pending":
            try:
                self.transport.send(key, parse(raw))
            except Exception:
                pass                                  # an exception may follow a successful send: read back
        try:
            receipt = self.transport.readback(key)
        except Exception:
            return "UNKNOWN"
        if not self._valid(receipt, raw, key):
            return "UNKNOWN"
        with closing(self._db()) as db:
            db.execute("UPDATE deliveries SET status='delivered', receipt=? WHERE key=?", (canon(receipt), key))
        return "delivered"

    def _valid(self, receipt, raw: bytes, key: str) -> bool:
        try:
            payload, claim = parse(raw), receipt["claim"]
            if (set(receipt) != {"claim", "signature"}
                    or set(claim) != {"key", "payload_digest", "recipients_digest", "provider", "delivered_at"}
                    or claim["key"] != key or claim["payload_digest"] != digest(payload)
                    or claim["recipients_digest"] != digest(payload["recipients"])
                    or type(claim["delivered_at"]) is not int or claim["delivered_at"] < payload["due"]):
                return False
            public = self.keys.get(claim["provider"])
            signature = base64.b64decode(receipt["signature"], validate=True)
            Ed25519PublicKey.from_public_bytes(public).verify(signature, PREFIX + canon(claim))
            return True
        except (InvalidSignature, ValueError, TypeError, KeyError, AttributeError):
            return False

    def deliver_due(self, verdict: dict) -> dict:
        return {key: self.deliver(key) for key in self.enqueue(verdict)}
