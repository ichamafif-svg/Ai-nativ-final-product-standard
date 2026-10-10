"""Which Trusted External contracts an operation needs, and the installation's evidence that they hold (§10).

Nine responsibilities, grouped as the installation chooses. An operation only needs the contracts it depends on: a T09
outage never blocks an ordinary admission, a T03 outage never blocks a signed freeze or revocation. Nothing here
proves a physical property: a signed assessment authenticates an assessor's statement, bound to this release,
genesis and ledger, and nothing more. Assessor keys are pinned by the installation, out of the agent's reach.
"""
from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from kernel import SHAPES
from kernel.canon import canon, digest
from kernel.floor0 import POLARITY

CONTRACTS = tuple(f"T{i:02}" for i in range(1, 10))
BASE = frozenset({"T01", "T02", "T04", "T05"})
TIMED = BASE | {"T03"}
PREFIX = b"standard:trusted-external-assessment:v1\x00"


class TrustUnavailable(RuntimeError):
    pass


def required_for(kind) -> frozenset:
    """The contracts an entry of this kind depends on. Unknown kinds are law-declared evidence."""
    if POLARITY.get(kind) == "restrict":
        return BASE
    need = set(TIMED)
    if kind in ("observation", "measurement") or kind not in SHAPES:
        need.add("T06")
    if kind == "reconciliation":
        need.add("T08")
    if kind in ("token", "reservation", "execution"):
        need |= {"T07", "T08"}
    return frozenset(need)


class SignedAssessment:
    """A boundary backed by one signed assessment of the installation.

    payload = {schema, assessor, release, genesis, ledger, issued_at, expires_at, contracts: {Txx: "VERIFIED" | ...}}
    """

    SCHEMA = "standard.t-assessment/1"

    def __init__(self, bundle: dict, pinned_assessors: dict):
        if not pinned_assessors or any(not isinstance(k, bytes) or len(k) != 32 for k in pinned_assessors.values()):
            raise TrustUnavailable("TRUST.ASSESSORS")
        self.bundle, self.pinned = bundle, dict(pinned_assessors)

    def check(self, required, *, release: str, genesis: str, ledger: str, now) -> None:
        try:
            payload = self.bundle["payload"]
            if set(self.bundle) != {"payload", "signature"} or set(payload) != {
                    "schema", "assessor", "release", "genesis", "ledger", "issued_at", "expires_at", "contracts"} \
                    or payload["schema"] != self.SCHEMA:
                raise TrustUnavailable("TRUST.SHAPE")
            key = self.pinned.get(payload["assessor"])
            if key is None:
                raise TrustUnavailable("TRUST.UNPINNED_ASSESSOR")
            Ed25519PublicKey.from_public_bytes(key).verify(
                base64.b64decode(self.bundle["signature"], validate=True), PREFIX + canon(payload))
        except (InvalidSignature, KeyError, TypeError, ValueError) as exc:
            raise TrustUnavailable("TRUST.INVALID_ASSESSMENT") from exc
        if (payload["release"], payload["genesis"], payload["ledger"]) != (release, genesis, digest(ledger)):
            raise TrustUnavailable("TRUST.BINDING")
        # Without trusted time, only narrowing paths ask; the assessment is checked at its signed issuance.
        at = payload["issued_at"] if now is None else now
        if not (type(at) is int and payload["issued_at"] <= at < payload["expires_at"]):
            raise TrustUnavailable("TRUST.EXPIRED")
        missing = [t for t in sorted(required) if payload["contracts"].get(t) != "VERIFIED"]
        if missing:
            raise TrustUnavailable("TRUST.UNVERIFIED:" + ",".join(missing))
