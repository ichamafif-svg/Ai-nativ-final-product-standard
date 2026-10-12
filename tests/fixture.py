"""Test fixture: a small constitution with real Ed25519 keys and a ledger driven through the one judgment.

Signing lives here because the kernel never signs. Times are explicit milliseconds.
"""
from __future__ import annotations

import base64
import copy
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from product.floors import RELEASE  # noqa: E402
from kernel import Kernel, Refused, apply, canon, digest, empty  # noqa: E402
from kernel.identity import PAYLOAD_TYPE, keyid, pae, statement  # noqa: E402
from bt.checker import Checker  # noqa: E402

CODE = digest({"code": "test-release"})
HOUR = 3_600_000
IDENTITIES = {"h1": "human", "h2": "human", "h3": "human", "h4": "human", "w1": "witness", "w2": "witness",
              "guard": "guard", "agent": "agent", "scanner": "service", "oracle": "oracle", "sentinel": "sentinel",
              "tester": "service", "reproducer": "service"}


def client_law(**extra) -> dict:
    law = {"format": "standard-client/1", "floors": RELEASE.digest,
           "bindings": {"owner": "h1", "inventory_source": "oracle", "scanner": "scanner",
                        "compliance_officer": "h2"}}
    law.update(copy.deepcopy(extra))
    return law


class Keys:
    def __init__(self):
        self.private, self.root = {}, {"threshold": 2, "identities": {}}
        for ident, kind in IDENTITIES.items():
            self.add(ident, kind)

    def add(self, ident, kind):
        sk = Ed25519PrivateKey.generate()
        pub = base64.b64encode(sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
        self.private[ident] = (keyid(pub), sk)
        self.root["identities"][ident] = {"kind": kind, "keys": [{"alg": "ed25519", "public": pub, "keyid": keyid(pub)}]}


def envelope(domain: str, kind: str, body: dict, signers, keys: Keys) -> dict:
    payload = canon(statement(domain, kind, body))
    message = pae(payload)
    sigs = sorted((keys.private[s] for s in signers), key=lambda p: p[0])
    return {"payloadType": PAYLOAD_TYPE, "payload": base64.b64encode(payload).decode(),
            "signatures": [{"keyid": kid, "sig": base64.b64encode(sk.sign(message)).decode()} for kid, sk in sigs]}


class Ledger:
    """Drives one kernel state. `at` defaults to one millisecond after the last entry."""

    def __init__(self, law=None, keys=None, kernel=None, at=1_000):
        self.keys = keys or Keys()
        self.kernel = kernel or Kernel(RELEASE, CODE)
        self.state, self.entries, self.n = empty(), [], 0
        self.records = []
        self.checker = Checker()        # every admitted entry is also checked by the independent judge
        self.genesis(law or client_law(), at)

    def entry(self, kind, body, signers):
        domain = "genesis" if kind == "genesis" else self.state["domain"]
        return {"seq": self.state["size"], "prev": self.state["head"],
                "envelope": envelope(domain, kind, body, signers, self.keys)}

    def submit(self, kind, author, signers=None, at=None, **fields):
        self.n += 1
        body = {"id": fields.pop("id", f"{kind}-{self.n}"), "at": self.state["last_at"] + 1 if at is None else at,
                "author": author, **fields}
        entry = self.entry(kind, body, signers or [author])
        record, delta = self.kernel.decide(self.state, entry)
        law = self.kernel.law_by_digest(record["law"])
        self.checker.check(self.state, record, copy.deepcopy(delta), entry, law.raw, law.digest)
        apply(self.state, delta)
        self.entries.append(entry)
        self.records.append(record)
        return body["id"]

    def measure(self, author, under, resource, prop, status, level="real"):
        """A pinned instrument's measurement (D33): method and coverage from the floors, measured now."""
        from product.floors import INSTRUMENTS
        method, coverage, _ = INSTRUMENTS[prop]
        at = self.state["last_at"] + 1
        return self.submit("measurement", author, at=at, under=under, resource=resource, property=prop,
                           status=status, level=level, method=method, coverage=coverage, measured_at=at,
                           artifact="sha256:" + "0" * 64)

    def refused(self, kind, author, signers=None, at=None, **fields) -> str:
        before = copy.deepcopy(self.state)
        try:
            self.submit(kind, author, signers, at, **fields)
        except Refused as r:
            assert self.state == before
            return r.code
        raise AssertionError(f"{kind} was admitted")

    def genesis(self, law, at):
        self.submit("genesis", "h1", ["h1", "h2"], at, root=self.keys.root, law=law, code=CODE)

    def checkpoint(self, at=None):
        at = self.state["last_at"] + 1 if at is None else at
        return self.submit("checkpoint", "w1", ["w1", "w2"], at, size=self.state["size"], head=self.state["head"])

    def advance(self, ms):
        """Witnessed time moves forward by ms."""
        return self.checkpoint(self.state["last_at"] + ms)

    def grant(self, holder, actions, resources, conditions=(), budget=None, not_after=10 ** 12):
        fields = {"holder": holder, "actions": list(actions), "resources": list(resources),
                  "conditions": list(conditions), "not_after": not_after}
        if budget:
            fields["budget"] = budget
        pid = self.submit("grant", "h1", ["h1", "h2"], **fields)
        self.advance(HOUR + 1)
        self.submit("activate", "h1", ["h1", "h2"], proposal=pid)
        return pid
