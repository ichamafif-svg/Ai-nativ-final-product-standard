"""Identity: closed DSSE envelopes over in-toto statements, verified with Ed25519 (machines) or a WebAuthn ES256
assertion (humans), and the root that names who may sign (K02).

One key has one encoding; one envelope has one meaning: no unsigned field, one signature per key, in key order.
Nothing here holds a secret or generates a key.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .canon import CanonError, canon, parse
from .floor0 import HUMANS, KINDS
from .types import ID

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_PREFIX = "urn:standard:kernel:1:"
ALGORITHMS = ("ed25519", "webauthn-es256")
_SIGNATURE_FIELDS = ({"keyid", "sig"}, {"keyid", "sig", "webauthn"})


class IdentityError(ValueError):
    pass


def b64d(text) -> bytes:
    """Standard base64 in its one canonical spelling: unused bits zero, exact padding (one value, one encoding)."""
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, TypeError, ValueError):
        raise IdentityError("bad base64") from None
    if base64.b64encode(raw).decode() != text:
        raise IdentityError("non-canonical base64")
    return raw


def _b64u(text: str) -> bytes:
    """URL-safe base64 without padding, canonical only."""
    if not isinstance(text, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", text):
        raise IdentityError("bad base64url")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if _b64u_enc(raw) != text:
        raise IdentityError("non-canonical base64url")
    return raw


P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def low_s_der(sig: bytes) -> bool:
    """An ECDSA signature in its one encoding: strict DER and s in the lower half (s and n - s verify alike)."""
    try:
        r, s_ = decode_dss_signature(sig)
    except ValueError:
        return False
    return encode_dss_signature(r, s_) == sig and 0 < s_ <= P256_N // 2


def _b64u_enc(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def keyid(public_b64: str) -> str:
    return "sha256:" + hashlib.sha256(b64d(public_b64)).hexdigest()


def pae(payload: bytes) -> bytes:
    kind = PAYLOAD_TYPE.encode()
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)


def subject_name(domain: str, kind: str, rid: str) -> str:
    return f"{domain}/{kind}:{rid}"


def statement(domain: str, kind: str, body: dict) -> dict:
    return {"_type": STATEMENT_TYPE, "predicateType": PREDICATE_PREFIX + kind, "predicate": body,
            "subject": [{"name": subject_name(domain, kind, body["id"]),
                         "digest": {"sha256": hashlib.sha256(canon(body)).hexdigest()}}]}


def canonical_public(alg: str, public_b64: str) -> bool:
    """One key, one encoding: Ed25519 is 32 raw bytes; a passkey is an uncompressed P-256 point on the curve."""
    raw = b64d(public_b64)
    if alg == "ed25519":
        return len(raw) == 32
    try:
        point = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError:
        return False
    return raw == point.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def open_envelope(envelope) -> tuple[str, dict, bytes, str]:
    """(kind, body, signed message, subject name) of a closed envelope whose payload is a canonical statement."""
    if (not isinstance(envelope, dict) or set(envelope) != {"payloadType", "payload", "signatures"}
            or envelope["payloadType"] != PAYLOAD_TYPE or not isinstance(envelope["signatures"], list)):
        raise IdentityError("not a closed DSSE envelope")
    sigs = envelope["signatures"]
    if (not sigs or len(sigs) > 64
            or not all(isinstance(s, dict) and set(s) in _SIGNATURE_FIELDS and isinstance(s["keyid"], str) for s in sigs)
            or [s["keyid"] for s in sigs] != sorted({s["keyid"] for s in sigs})
            or any(not isinstance(s.get("webauthn", {}), dict)
                   or ("webauthn" in s and set(s["webauthn"]) != {"authenticatorData", "clientDataJSON"}) for s in sigs)):
        raise IdentityError("signatures are closed, one per key, in key order")
    payload = b64d(envelope["payload"])
    try:
        st = parse(payload)
    except CanonError as exc:
        raise IdentityError(f"payload: {exc}") from None
    if not isinstance(st, dict) or set(st) != {"_type", "predicateType", "predicate", "subject"} or st["_type"] != STATEMENT_TYPE:
        raise IdentityError("not an in-toto statement")
    kind = str(st["predicateType"]).removeprefix(PREDICATE_PREFIX)
    body, subjects = st["predicate"], st["subject"]
    if kind == st["predicateType"] or not isinstance(body, dict) or not isinstance(subjects, list) or len(subjects) != 1:
        raise IdentityError("unknown predicate or subject")
    subject = subjects[0]
    if not isinstance(subject, dict) or set(subject) != {"name", "digest"} or not isinstance(subject["name"], str):
        raise IdentityError("malformed subject")
    if subject["digest"] != {"sha256": hashlib.sha256(canon(body)).hexdigest()}:
        raise IdentityError("subject digest does not bind the predicate")
    return kind, body, pae(payload), subject["name"]


def verify(key: dict, message: bytes, signature: dict) -> bool:
    try:
        if key["alg"] == "ed25519":
            Ed25519PublicKey.from_public_bytes(b64d(key["public"])).verify(b64d(signature["sig"]), message)
            return True
        if key["alg"] == "webauthn-es256":
            return _webauthn(key, message, signature)
    except (InvalidSignature, IdentityError, ValueError, KeyError, TypeError, AttributeError):
        return False
    return False


def _webauthn(key: dict, message: bytes, signature: dict) -> bool:
    """A passkey signs authenticatorData || sha256(clientDataJSON); the challenge is sha256(PAE)."""
    w = signature["webauthn"]
    auth, client_json = _b64u(w["authenticatorData"]), _b64u(w["clientDataJSON"])
    client = json.loads(client_json)
    if client.get("type") != "webauthn.get" or client.get("origin") not in key["origins"]:
        return False
    if client.get("challenge") != _b64u_enc(hashlib.sha256(message).digest()):
        return False
    if len(auth) < 37 or auth[:32] != hashlib.sha256(key["rp_id"].encode()).digest() or (auth[32] & 0x05) != 0x05:
        return False                                   # wrong relying party, or user not present and verified
    sig = _b64u(signature["sig"])
    if not low_s_der(sig):
        return False                                   # a relay could otherwise flip s and change the head
    public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b64d(key["public"]))
    public.verify(sig, auth + hashlib.sha256(client_json).digest(), ec.ECDSA(hashes.SHA256()))
    return True


# ---- the root -------------------------------------------------------------------------------------------------------
def check_root(root) -> None:
    """A root is {identities}: known kinds, canonical keys never repeated, exactly one human (F0-1: one human, up to
    eight keys for their devices) and at least one witness. Raises IdentityError."""
    if not isinstance(root, dict) or set(root) != {"identities"}:
        raise IdentityError("a root is {identities}")
    ids = root["identities"]
    if not isinstance(ids, dict) or not 0 < len(ids) <= 256:
        raise IdentityError("a root lists one to 256 identities")
    seen = set()
    for ident, decl in ids.items():
        if not ID.fullmatch(ident) or not isinstance(decl, dict) or set(decl) != {"kind", "keys"} or decl["kind"] not in KINDS:
            raise IdentityError(f"{ident}: {{kind, keys}} with a known kind")
        if not isinstance(decl["keys"], list) or not 0 < len(decl["keys"]) <= 8:
            raise IdentityError(f"{ident}: one to eight keys")
        for key in decl["keys"]:
            if not isinstance(key, dict) or key.get("alg") not in ALGORITHMS or not isinstance(key.get("public"), str):
                raise IdentityError(f"{ident}: bad key")
            extra = {"rp_id", "origins"} if key["alg"] == "webauthn-es256" else set()
            if set(key) != {"alg", "public", "keyid"} | extra:
                raise IdentityError(f"{ident}: key fields")
            if extra and (not isinstance(key["rp_id"], str) or not isinstance(key["origins"], list) or not key["origins"]
                          or not all(isinstance(o, str) for o in key["origins"])):
                raise IdentityError(f"{ident}: a passkey names its relying party and origins")
            if not canonical_public(key["alg"], key["public"]):
                raise IdentityError(f"{ident}: a public key in its one canonical encoding")
            kid = keyid(key["public"])
            if key["keyid"] != kid or kid in seen:
                raise IdentityError(f"{ident}: bad or repeated key")
            seen.add(kid)
    if len(humans(root)) != HUMANS:
        raise IdentityError("F0-1: a root holds exactly one human")
    if not any(d["kind"] == "witness" for d in ids.values()):
        raise IdentityError("a root holds a witness to state time")


def humans(root) -> set:
    return {i for i, d in root["identities"].items() if d["kind"] == "human"}


def kind_of(root, ident) -> str | None:
    decl = root["identities"].get(ident) if isinstance(ident, str) else None
    return decl["kind"] if decl else None


def signers(root, envelope: dict, message: bytes) -> set:
    """The identities whose every signature verifies against the root; None if any signature does not."""
    keys = {k["keyid"]: (ident, k) for ident, d in root["identities"].items() for k in d["keys"]}
    out = set()
    for sig in envelope["signatures"]:
        found = keys.get(sig["keyid"])
        if found is None or not verify(found[1], message, sig):
            return None
        out.add(found[0])
    return out
