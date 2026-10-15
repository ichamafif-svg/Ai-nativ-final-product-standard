"""Checkpoints any transparency witness can cosign (L-04): the journal as an RFC 6962 Merkle tree, its head as a
C2SP `tlog-checkpoint` in a C2SP `signed-note`.

The pin store keeps the journal from rolling back on this host; it cannot keep the whole host from rolling back.
A checkpoint published to independent witnesses does: a witness cosigns a checkpoint only if it extends every
checkpoint it has seen for that origin (a consistency proof), so a restored or forked journal is refused by people
outside the restoration domain. The formats are the ones the public witness network speaks (omniwitness, Sigsum,
litewitness); nothing here is Standard-specific except the origin line.

    note = checkpoint(origin, entries_raw, signer)          # the signed note, text
    size, root = verify(note, origin, {name: public_raw})   # refuses unless every listed key signed it
    inclusion(entries_raw, i) / consistency(entries_raw, m) # proofs (RFC 9162 §2.1.3, §2.1.4)

Leaves are the exact canonical bytes the journal stores (`canon(entry)`); the tree adds no authority, it is a
second, standard view of the same prefix. The kernel never reads it.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ED25519 = b"\x01"                     # C2SP signed-note signature type for Ed25519


class TransparencyError(ValueError):
    pass


# ---- RFC 6962 / RFC 9162 Merkle tree --------------------------------------------------------------------------------
def _leaf(raw: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + raw).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """The largest power of two smaller than n."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def root(leaves) -> bytes:
    leaves = list(leaves)
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return _leaf(leaves[0])
    k = _split(len(leaves))
    return _node(root(leaves[:k]), root(leaves[k:]))


def inclusion(leaves, index: int) -> list:
    leaves = list(leaves)
    if not 0 <= index < len(leaves):
        raise TransparencyError("no such leaf")
    if len(leaves) == 1:
        return []
    k = _split(len(leaves))
    if index < k:
        return inclusion(leaves[:k], index) + [root(leaves[k:])]
    return inclusion(leaves[k:], index - k) + [root(leaves[:k])]


def verify_inclusion(raw: bytes, index: int, size: int, proof: list, expected: bytes) -> bool:
    """RFC 9162 §2.1.3.2."""
    if not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, _leaf(raw)
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = _node(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn, sn = fn >> 1, sn >> 1
        else:
            r = _node(r, p)
        fn, sn = fn >> 1, sn >> 1
    return sn == 0 and r == expected


def consistency(leaves, old: int) -> list:
    """RFC 9162 §2.1.4.1: proof that the first `old` leaves are a prefix of `leaves`."""
    leaves = list(leaves)
    if not 0 < old <= len(leaves):
        raise TransparencyError("no such prefix")

    def sub(m, d, complete):
        n = len(d)
        if m == n:
            return [] if complete else [root(d)]
        k = _split(n)
        if m <= k:
            return sub(m, d[:k], complete) + [root(d[k:])]
        return sub(m - k, d[k:], False) + [root(d[:k])]
    return sub(old, leaves, True)


def verify_consistency(old: int, new: int, proof: list, old_root: bytes, new_root: bytes) -> bool:
    """RFC 9162 §2.1.4.2."""
    if old == new:
        return not proof and old_root == new_root
    if not 0 < old < new or not proof:
        return False
    if old & (old - 1) == 0:                        # a power of two: the old root is the first node
        proof = [old_root, *proof]
    fn, sn = old - 1, new - 1
    while fn & 1:
        fn, sn = fn >> 1, sn >> 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = _node(c, fr), _node(c, sr)
            if not fn & 1:
                while fn and not fn & 1:
                    fn, sn = fn >> 1, sn >> 1
        else:
            sr = _node(sr, c)
        fn, sn = fn >> 1, sn >> 1
    return fr == old_root and sr == new_root and sn == 0


# ---- C2SP signed note -----------------------------------------------------------------------------------------------
def key_hash(name: str, public_raw: bytes) -> bytes:
    return hashlib.sha256(name.encode() + b"\n" + ED25519 + public_raw).digest()[:4]


def verifier_key(name: str, public_raw: bytes) -> str:
    """The `vkey` string witnesses and monitors are configured with."""
    return f"{name}+{key_hash(name, public_raw).hex()}+{base64.b64encode(ED25519 + public_raw).decode()}"


def _name(name: str) -> str:
    if not name or any(c.isspace() or c == "+" for c in name):
        raise TransparencyError("a key name has no space and no '+'")
    return name


def checkpoint(origin: str, leaves, signer, name: str) -> str:
    """The signed note for the tree over `leaves`. `signer` is a bt.signing signer (local key or key service)."""
    leaves = list(leaves)
    if "\n" in origin or not origin:
        raise TransparencyError("an origin is one non-empty line")
    body = f"{origin}\n{len(leaves)}\n{base64.b64encode(root(leaves)).decode()}\n"
    return f"{body}\n{_line(body, signer, name)}"


def cosign(note: str, signer, name: str) -> str:
    """Add one more Ed25519 signature line to a note (another signer of Standard's own, e.g. a second host)."""
    body, _ = _parts(note)
    return note + _line(body, signer, name)


def _line(body: str, signer, name: str) -> str:
    public = base64.b64decode(signer.root_key()["public"])
    sig = key_hash(_name(name), public) + base64.b64decode(signer.sign(body.encode())["sig"])
    return f"— {name} {base64.b64encode(sig).decode()}\n"


def _parts(note: str):
    if "\n\n" not in note or not note.endswith("\n"):
        raise TransparencyError("not a signed note")
    body, sigs = note.split("\n\n", 1)
    body += "\n"
    lines = []
    for line in sigs[:-1].split("\n"):
        if not line.startswith("— ") or line.count(" ") != 2:
            raise TransparencyError("malformed signature line")
        _, name, sig = line.split(" ")
        lines.append((name, base64.b64decode(sig, validate=True)))
    return body, lines


def verify(note: str, origin: str, keys: dict) -> tuple[int, bytes]:
    """(size, root) if every key in `keys` ({name: raw Ed25519 public}) signed this checkpoint for `origin`."""
    body, lines = _parts(note)
    head = body.split("\n")
    if len(head) < 4 or head[0] != origin or not head[1].isdigit() or str(int(head[1])) != head[1]:
        raise TransparencyError("not a checkpoint for this origin")
    for name, public in keys.items():
        expected = key_hash(name, public)
        sigs = [s[4:] for n, s in lines if n == name and s[:4] == expected and len(s) == 68]
        try:
            if not sigs:
                raise InvalidSignature
            Ed25519PublicKey.from_public_bytes(public).verify(sigs[0], body.encode())
        except InvalidSignature:
            raise TransparencyError(f"{name} did not sign this checkpoint") from None
    return int(head[1]), base64.b64decode(head[2], validate=True)
