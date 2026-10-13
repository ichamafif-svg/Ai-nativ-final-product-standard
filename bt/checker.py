"""T05 — the independent second judge (ARCHITECTURE.md §6.4). Budget: restrictive only.

It runs after the kernel admitted an entry and before the journal commits it. It reads the signed entry itself, the
pinned declarations of the law (never the kernel's compiled law), and the state before; it re-derives what the entry
must change and compares it with the kernel's delta. A disagreement raises Disagreement, which the journal turns into
a persistent halt (F0-2). It can only block what the kernel admitted: a checker that accepts everything admits
nothing the kernel refuses.

Independence: this module imports no kernel module except `canon` (canonical bytes) and `floor0` (the pinned
specification). Signature verification, capability chains, conditions, obligations and the effect line are restated
here. Shared dependencies — the specification, canonical parsing, the cryptography library, the runtime and the OS —
are declared, not hidden: F0-2 is promised only for what this module recomputes.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from fractions import Fraction

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from kernel.canon import canon, digest, parse
from kernel.floor0 import DISPATCH_MS, LINE

PREFIX = "urn:standard:kernel:1:"
RESTRICT = {"veto": ("human",), "revoke": None, "freeze": ("human", "sentinel"), "flag": ("human", "sentinel"),
            "heartbeat": ("sentinel",), "invalidate": ("human", "oracle")}
BOOK = {("put", "statements"), ("set", "size"), ("set", "head"), ("set", "last_at")}
TOUCH = {
    "genesis": {("set", "domain"), ("set", "root"), ("set", "root_digest"), ("set", "anchor_at"), ("set", "code"),
                ("set", "law")},
    "rotate": {("put", "proposals")}, "grant": {("put", "proposals")}, "unfreeze": {("put", "proposals")},
    "law": {("put", "proposals")},
    "activate": {("set", "root"), ("set", "root_digest"), ("set", "law"), ("put", "grants"), ("drop", "frozen"),
                 ("drop", "proposals")},
    "delegate": {("put", "grants")}, "veto": {("drop", "proposals")}, "revoke": {("put", "revoked")},
    "freeze": {("put", "frozen")}, "flag": {("put", "flags")}, "heartbeat": {("put", "heartbeats")},
    "invalidate": {("put", "invalidated")}, "checkpoint": {("set", "anchor_at"), ("set", "witnessed")},
    "intent": {("put", "intents"), ("put", "obligations"), ("put", "line")},
    "token": {("drop", "obligations"), ("put", "tokens"), ("put", "token_of"), ("push", "uses"),
              ("put", "obligations"), ("put", "line")},
    "reservation": {("drop", "obligations"), ("put", "reserved"), ("put", "obligations"), ("put", "line")},
    "execution": {("put", "executed"), ("drop", "obligations"), ("put", "obligations"), ("put", "line")},
    "reconciliation": {("drop", "obligations"), ("put", "obligations"), ("put", "line")},
    "observation": {("put", "observations")}, "measurement": {("put", "observations")},
    "resource": {("put", "entities"), ("push", "uses")}, "transition": {("put", "entities"), ("push", "uses")},
}
EVIDENCE_TOUCH = {("drop", "obligations")}
LAPSING = ("pending", "unredeemed")


class Disagreement(Exception):
    pass


def _no(why: str):
    raise Disagreement(why)


def _humans(root) -> set:
    return {i for i, d in root["identities"].items() if d["kind"] == "human"}


def _kind(root, ident):
    return root["identities"].get(ident, {}).get("kind")


def _inside(child: str, parent: str) -> bool:
    """Pattern inclusion, restated: '*' only ends a pattern."""
    if parent == child:
        return True
    return parent.endswith("*") and (child[:-1] if child.endswith("*") else child).startswith(parent[:-1])


def _field(body, path):
    value = body
    for part in path.split("."):
        value = value.get(part) if isinstance(value, dict) else None
    return value if isinstance(value, (str, int)) and type(value) is not bool else None


def _number(value):
    if type(value) is int:
        return Fraction(value)
    if isinstance(value, str) and re.fullmatch(r"-?[0-9]{1,12}(\.[0-9]{1,6})?", value):
        return Fraction(value)
    return None


def _live(ob, at) -> bool:
    return not ((ob["stage"] in LAPSING or ob.get("on_due") == "lapse") and at > ob["due"])


class Checker:
    """One instance per journal. The law snapshot is rebuilt from pinned declarations when the law changes."""

    def __init__(self):
        self._law_digest = None

    # ---- law snapshot -------------------------------------------------------------------------------------------
    def use(self, effective: dict, law_digest: str) -> None:
        if self._law_digest == law_digest:
            return
        raw = copy.deepcopy(effective)
        if digest(raw) != law_digest:
            _no("the law snapshot differs from its pin")
        self.raw, self._law_digest = raw, law_digest
        self.levels = raw["levels"]
        self.evidence = set(raw.get("evidence", {}))
        self.contracts = {d["id"]: digest(d) for d in raw.get("obligations", [])}
        self.refuse = [{**d, **{k: [{"where": {}, "op": None, **r} for r in d.get(k, [])] for k in ("gate", "open", "close")}}
                       for d in raw.get("obligations", []) if d["level"] == "refuse"]

    def _condition_digests(self, names) -> list:
        return sorted(digest({"name": n, "policy": self.raw.get("conditions", {}).get(n)}) for n in names)

    def _op(self, name) -> dict:
        """The op as the kernel stores it: declared fields, trusted contracts with T07/T08 always."""
        op = self.raw["ops"][name]
        return {"args": dict(op["args"]), "resource": op["resource"], "profile": op["profile"],
                "trusted": sorted(set(op.get("trusted", [])) | {"T07", "T08"})}

    def _resource_of(self, op: str, args: dict) -> str:
        out, template = "", self.raw["ops"][op]["resource"]
        i = 0
        while i < len(template):
            if template[i] == "{":
                j = template.index("}", i)
                out += str(args[template[i + 1:j]])
                i = j + 1
            else:
                out += template[i]
                i += 1
        return out

    # ---- the entry --------------------------------------------------------------------------------------------------
    def check(self, pre: dict, record: dict, delta: list, entry: dict, effective: dict, law_digest: str) -> None:
        try:
            self._check(pre, record, delta, entry, effective, law_digest)
        except Disagreement:
            raise
        except Exception as exc:                       # a checker that cannot decide blocks
            _no(f"cannot independently check the entry: {type(exc).__name__}")

    def _check(self, pre, record, delta, entry, effective, law_digest):
        if record["law"] != law_digest or (pre["size"] and pre["law"]["digest"] != law_digest):
            _no("an entry is judged under the law in force at its position")
        self.use(effective, law_digest)
        kind, body, at = record["kind"], record["body"], record["at"]
        root = body["root"] if kind == "genesis" else pre["root"]
        signers = self._signed(pre, record, entry, root)
        allowed = EVIDENCE_TOUCH if kind in self.evidence else TOUCH.get(kind)
        if allowed is None:
            _no(f"unknown kind {kind}")
        law_ops = [op for op in delta if self._is_law(op)]
        delta = [op for op in delta if not self._is_law(op)]
        for op in delta:
            if (op[0], op[1]) not in allowed | BOOK:
                _no(f"{kind} may not {op[0]} {op[1]}")
        book = {(op[0], op[1]): op for op in delta if (op[0], op[1]) in BOOK}
        if len(book) != len(BOOK) or len([op for op in delta if (op[0], op[1]) in BOOK]) != len(BOOK):
            _no("every entry records itself exactly once")
        if book[("set", "size")][2] != pre["size"] + 1 or book[("set", "head")][2] != digest(entry):
            _no("an entry extends the head by one")
        if book[("put", "statements")][2:] != (body["id"], record) or body["id"] in pre["statements"]:
            _no("the signed statement is recorded once, unchanged")
        restricting = kind in RESTRICT
        if book[("set", "last_at")][2] != at or (pre["size"] and (at < pre["last_at"] or (at == pre["last_at"] and not restricting))):
            _no("time runs forward; only a restriction shares the last instant")
        if (kind == "genesis") != (pre["size"] == 0):
            _no("the genesis is first, and only first")
        if restricting:
            self._restriction(pre, record, root)
        handler = getattr(self, "_" + kind, None) if kind not in self.evidence else self._evidence
        if handler is None:
            _no(f"no independent check for {kind}")
        handler(pre, record, delta, root, signers)
        self._protocol_obligations(pre, record, delta)
        self._line(pre, record, delta)
        self._law_obligations(pre, record, law_ops)

    def _is_law(self, op) -> bool:
        return (op[1] in ("obligations", "closed") and op[0] in ("put", "drop")
                and op[2].split(":", 1)[0] in {d["id"] for d in self.refuse})

    # ---- signatures, restated -------------------------------------------------------------------------------------
    def _signed(self, pre, record, entry, root) -> set:
        if set(entry) != {"seq", "prev", "envelope"} or entry["seq"] != pre["size"] or entry["prev"] != pre["head"]:
            _no("the signed entry does not extend the head")
        env = entry["envelope"]
        if set(env) != {"payloadType", "payload", "signatures"} or env["payloadType"] != "application/vnd.in-toto+json":
            _no("the envelope carries exactly a payload type, a payload and signatures")
        ids = [s["keyid"] for s in env["signatures"]]
        if ids != sorted(set(ids)) or any(set(s) - {"keyid", "sig", "webauthn"} for s in env["signatures"]):
            _no("one signature per key, in key order, nothing unsigned")
        payload = base64.b64decode(env["payload"], validate=True)
        st = parse(payload)
        body = st["predicate"]
        kind = st["predicateType"].removeprefix(PREFIX)
        domain = "genesis" if pre["size"] == 0 else pre["domain"]
        expected = {"_type": "https://in-toto.io/Statement/v1", "predicateType": PREFIX + kind, "predicate": body,
                    "subject": [{"name": f"{domain}/{kind}:{body['id']}",
                                 "digest": {"sha256": hashlib.sha256(canon(body)).hexdigest()}}]}
        if (st != expected or record["kind"] != kind or record["body"] != body or record["at"] != body["at"]
                or record["author"] != body["author"]):
            _no("the kernel record differs from the signed statement")
        ptype = env["payloadType"].encode()
        message = b"DSSEv1 %d %s %d %s" % (len(ptype), ptype, len(payload), payload)
        keys = {k["keyid"]: (name, k) for name, ident in root["identities"].items() for k in ident["keys"]}
        signers = set()
        for sig in env["signatures"]:
            name, key = keys[sig["keyid"]]
            public = base64.b64decode(key["public"], validate=True)
            if "sha256:" + hashlib.sha256(public).hexdigest() != sig["keyid"]:
                _no("a signer key id is wrong")
            if key["alg"] == "ed25519":
                Ed25519PublicKey.from_public_bytes(public).verify(base64.b64decode(sig["sig"], validate=True), message)
            elif key["alg"] == "webauthn-es256":
                self._webauthn(key, public, message, sig)
            else:
                _no("unknown signature algorithm")
            signers.add(name)
        if body["author"] not in signers or sorted(signers) != record["signers"]:
            _no("the recorded signers differ from the verified signatures")
        return signers

    @staticmethod
    def _webauthn(key, public, message, sig):
        unb64 = lambda t: base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))
        w = sig["webauthn"]
        auth, client_raw = unb64(w["authenticatorData"]), unb64(w["clientDataJSON"])
        client = json.loads(client_raw)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(message).digest()).rstrip(b"=").decode()
        if (client.get("type") != "webauthn.get" or client.get("origin") not in key["origins"]
                or client.get("challenge") != challenge or len(auth) < 37
                or auth[:32] != hashlib.sha256(key["rp_id"].encode()).digest() or auth[32] & 0x05 != 0x05):
            _no("a WebAuthn assertion is invalid")
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public).verify(
            unb64(sig["sig"]), auth + hashlib.sha256(client_raw).digest(), ec.ECDSA(hashes.SHA256()))

    # ---- widening ---------------------------------------------------------------------------------------------------
    def _root_ok(self, root) -> None:
        k = root.get("threshold")
        if type(k) is not int or k < 2 or len(_humans(root)) < k + 2:
            _no("a root has a quorum of at least two and two more humans")
        if sum(d["kind"] == "witness" for d in root["identities"].values()) < self.raw["witnesses"]["quorum"]:
            _no("a root keeps enough witnesses for the time quorum")

    @staticmethod
    def _quorum(record, root, signers, extra=0) -> None:
        if _kind(root, record["author"]) != "human" or len(signers & _humans(root)) < root["threshold"] + extra:
            _no("a widening is stated by a human and signed by the quorum of the root in force")

    def _genesis(self, pre, record, delta, root, signers):
        self._root_ok(root)
        self._quorum(record, root, signers)
        b = record["body"]
        expected = {("set", "domain", digest(b)), ("set", "root_digest", digest(root)), ("set", "anchor_at", b["at"]),
                    ("set", "code", b["code"])}
        sets = {tuple(op) for op in delta if op[0] == "set" and op[1] in ("domain", "root_digest", "anchor_at", "code")}
        if sets != expected or [op[2] for op in delta if op[:2] == ("set", "root")] != [root]:
            _no("the genesis state equals its signed body")
        if [op[2] for op in delta if op[:2] == ("set", "law")] != [{"digest": record["law"], "client": b["law"]}]:
            _no("the genesis puts exactly its own client law in force")

    def _proposal(self, pre, record, delta, root, signers):
        b, kind = record["body"], record["kind"]
        self._quorum(record, root, signers, 1 if b.get("override") else 0)
        expected = {"id": b["id"], "kind": kind, "body": b, "signers": sorted(signers & _humans(pre["root"])),
                    "not_before": b["at"] + (2 if b.get("override") else 1) * self.raw["delays"][kind],
                    "override": bool(b.get("override")), "root_digest": pre["root_digest"],
                    "law_digest": pre["law"]["digest"]}
        if kind == "unfreeze":
            if b["scope"] not in pre["frozen"]:
                _no("only a frozen scope can be unfrozen")
            expected["freeze"] = pre["frozen"][b["scope"]]
        if delta.count(("put", "proposals", b["id"], expected)) != 1 or len([o for o in delta if o[1] == "proposals"]) != 1:
            _no("the proposal equals the signed request with its delay")

    def _rotate(self, pre, record, delta, root, signers):
        self._root_ok(record["body"]["root"])
        self._proposal(pre, record, delta, root, signers)

    _grant = _unfreeze = _law = _proposal

    def _activate(self, pre, record, delta, root, signers):
        self._quorum(record, root, signers)
        p = pre["proposals"].get(record["body"]["proposal"])
        if (p is None or p["root_digest"] != pre["root_digest"] or p["law_digest"] != pre["law"]["digest"]
                or pre["anchor_at"] < p["not_before"]):
            _no("an activation needs a live proposal of this root and law whose witnessed delay has passed")
        pb = p["body"]
        if p["kind"] == "rotate":
            self._root_ok(pb["root"])
            expected = [("set", "root", pb["root"]), ("set", "root_digest", digest(pb["root"]))]
        elif p["kind"] == "grant":
            expected = [("put", "grants", pb["id"], self._grant_record(pb, "root", record["at"]))]
        elif p["kind"] == "unfreeze":
            if pre["frozen"].get(pb["scope"]) != p["freeze"]:
                _no("the scope was frozen again since the proposal")
            expected = [("drop", "frozen", pb["scope"])]
        else:
            if pb["client"].get("floors") is None:
                _no("a client law names the floors of its release")
            changed = [op for op in delta if op[:2] == ("set", "law")]
            if len(changed) != 1 or changed[0][2].get("client") != pb["client"]:
                _no("an activated law puts exactly the proposed client law in force")
            expected = changed
        expected = expected + [("drop", "proposals", p["id"])]
        if [op for op in delta if (op[0], op[1]) not in BOOK] != expected:
            _no("the activation applies exactly its proposal")

    def _grant_record(self, b, parent, at) -> dict:
        return {"id": b["id"], "parent": parent, "holder": b["holder"], "actions": list(b["actions"]),
                "resources": list(b["resources"]), "conditions": list(b["conditions"]), "budget": b.get("budget"),
                "not_after": b["not_after"], "effective_at": at,
                "condition_digests": self._condition_digests(b["conditions"])}

    # ---- attenuation and restriction --------------------------------------------------------------------------------
    def _delegate(self, pre, record, delta, root, signers):
        b = record["body"]
        child, parent = self._grant_record(b, b["parent"], record["at"]), pre["grants"].get(b["parent"])
        if [op for op in delta if (op[0], op[1]) not in BOOK] != [("put", "grants", b["id"], child)]:
            _no("delegated rights equal the signed scope")
        if parent is None or b["parent"] == "root" or record["author"] != parent["holder"] or b["id"] in pre["grants"]:
            _no("a delegation derives a new grant from one its author holds")
        if (not set(child["actions"]) <= set(parent["actions"])
                or not all(any(_inside(c, p) for p in parent["resources"]) for c in child["resources"])
                or child["not_after"] > parent["not_after"]
                or not set(parent["condition_digests"]) <= set(child["condition_digests"])):
            _no("a delegation never widens its parent")
        pb, cb = parent.get("budget"), child.get("budget")
        if pb and not (cb and cb["count"] <= pb["count"] and cb["window"] >= pb["window"]):
            _no("a delegation keeps its parent's budget")
        self._chain(pre, b["parent"], record["at"])

    def _restriction(self, pre, record, root):
        kind, author = record["kind"], record["author"]
        allowed = RESTRICT[kind]
        if allowed is not None and _kind(root, author) not in allowed:
            _no(f"{kind} comes from a {' or '.join(allowed)} of the root")

    def _veto(self, pre, record, delta, root, signers):
        p = pre["proposals"].get(record["body"]["proposal"])
        if p is None or p["override"] or record["author"] in p["signers"] or _kind(root, record["author"]) != "human":
            _no("only a non-signing human vetoes a pending ordinary proposal")
        self._exactly(delta, [("drop", "proposals", p["id"])])

    def _revoke(self, pre, record, delta, root, signers):
        gid = record["body"]["grant"]
        if gid not in pre["grants"]:
            _no("a revocation names a grant")
        if _kind(root, record["author"]) != "human":
            holders, cur = set(), gid
            while cur != "root" and cur in pre["grants"]:
                holders.add(pre["grants"][cur]["holder"])
                cur = pre["grants"][cur]["parent"]
            if record["author"] not in holders:
                _no("a non-human revokes only along its own chain")
        self._exactly(delta, [("put", "revoked", gid, record["at"])])

    def _freeze(self, pre, record, delta, root, signers):
        self._exactly(delta, [("put", "frozen", record["body"]["scope"], record["body"]["id"])])

    def _flag(self, pre, record, delta, root, signers):
        if record["body"]["intent"] not in pre["intents"]:
            _no("a flag names an intent")
        self._exactly(delta, [("put", "flags", record["body"]["intent"], record["body"]["id"])])

    def _heartbeat(self, pre, record, delta, root, signers):
        if record["body"]["seen"] > pre["size"]:
            _no("a heartbeat is about what exists")
        self._exactly(delta, [("put", "heartbeats", record["author"], record["at"])])

    def _invalidate(self, pre, record, delta, root, signers):
        found = [o for o in pre["observations"].values() if o["id"] == record["body"]["evidence"]]
        if not found or (_kind(root, record["author"]) == "oracle" and any(o["author"] != record["author"] for o in found)):
            _no("an invalidation names admitted evidence its author may withdraw")
        self._exactly(delta, [("put", "invalidated", record["body"]["evidence"], record["body"]["id"])])

    def _checkpoint(self, pre, record, delta, root, signers):
        if _kind(root, record["author"]) != "witness" or \
                sum(_kind(root, s) == "witness" for s in signers) < self.raw["witnesses"]["quorum"]:
            _no("time moves only with the witness quorum")
        b = record["body"]
        if b["size"] != pre["size"] or b["head"] != pre["head"]:
            _no("a checkpoint names the current head")
        self._exactly(delta, [("set", "anchor_at", record["at"]), ("set", "witnessed", True)])

    @staticmethod
    def _exactly(delta, expected):
        if sorted(map(repr, (op for op in delta if (op[0], op[1]) not in BOOK))) != sorted(map(repr, expected)):
            _no("the delta differs from the exact signed consequence")

    # ---- authority, restated ----------------------------------------------------------------------------------------
    def _chain(self, pre, gid, at) -> list:
        chain, seen = [], set()
        while gid != "root":
            g = pre["grants"].get(gid)
            if g is None or gid in seen or len(seen) >= 16:
                _no("invalid capability chain")
            if gid in pre["revoked"] or g["not_after"] < at or g["holder"] not in pre["root"]["identities"]:
                _no("capability withdrawn")
            if list(g["condition_digests"]) != self._condition_digests(g["conditions"]):
                _no("capability conditions changed")
            seen.add(gid)
            chain.append(g)
            gid = g["parent"]
        if not chain:
            _no("the root is not a capability")
        return chain

    def _authority(self, pre, author, under, action, resource, stmt, at) -> tuple[list, set]:
        chain = self._chain(pre, under, at)
        if chain[0]["holder"] != author or action not in chain[0]["actions"] \
                or not any(_inside(resource, r) for r in chain[0]["resources"]):
            _no("outside the actor's capability")
        label = {author, *(g["holder"] for g in chain)}
        for g in chain:
            for name in g["conditions"]:
                if not self._holds(pre, self.raw["conditions"][name], {**stmt, "resource": resource}, label, at):
                    _no("a capability condition does not hold")
        return chain, label

    def _eligible(self, pre, o, at) -> bool:
        if o["id"] in pre["invalidated"]:
            return False
        spec = self.raw.get("instruments", {}).get(o["property"])
        if spec is None:
            return o["at"] <= at <= o["at"] + self.raw["ttl"]["observation"]
        return (o.get("instrument") == digest(spec) and o.get("method") == spec["method"]
                and o.get("coverage") == spec["coverage"] and o["author"] in spec["sources"]
                and o["at"] <= at <= o["at"] + spec["fresh_ms"])

    def _holds(self, pre, program, request, label, at) -> bool:
        """The positive language, restated, with facts read straight from the state."""
        for atom in program["all"]:
            op, args = next(iter(atom.items()))
            if op == "eq":
                value = _field(request, args[0])
                ok = value is not None and type(value) is type(args[1]) and value == args[1]
            elif op == "prefix":
                value = _field(request, args[0])
                ok = isinstance(value, str) and value.startswith(args[1])
            elif op == "observed":                      # D46: an optional fourth argument names the author's kind
                ok = any((o["resource"], o["property"], o["status"], o["level"]) == (request["resource"], *args[:3])
                         and (len(args) == 3 or _kind(pre["root"], o["author"]) == args[3])
                         and self._eligible(pre, o, at) and not label & set(o["label"])
                         for o in pre["observations"].values())
            elif op == "compare":                       # D35: decimal bounds, restated with exact arithmetic
                bound = _number(args[2])
                ok = bound is not None and any(
                    (o["resource"], o["property"], o["level"]) == (request["resource"], args[0], args[3])
                    and (v := _number(o["status"])) is not None and (v <= bound if args[1] == "le" else v >= bound)
                    and self._eligible(pre, o, at) and not label & set(o["label"])
                    for o in pre["observations"].values())
            elif op == "open":
                value = _field(request, args[1])
                ok = value is not None and any(
                    ob.get("type") == "law" and (ob["stage"], ob["key"]) == (args[0], value) and _live(ob, at)
                    and "label" in ob and not label & set(ob["label"]) for ob in pre["obligations"].values())
            elif op == "closed_at_least":
                ok = len({x["key"] for x in pre["closed"].values()
                          if x["type"] == args[0] and x["at"] + self.raw["ttl"]["observation"] >= at
                          and x["contract"] == self.contracts.get(x["type"]) and not label & set(x["label"])}) >= args[1]
            elif op == "related":
                bind = lambda v: request.get(v[1:]) if v.startswith("$") else v
                ok = self._related(pre, args[0], bind(args[1]), bind(args[2]))
            else:
                ok = False
            if not ok:
                return False
        return True

    @staticmethod
    def _related(pre, name, left, right) -> bool:
        if not isinstance(left, str) or not isinstance(right, str):
            return False
        if name == "role":
            return _kind(pre["root"], left) == right
        if name == "holds":
            return right not in pre["revoked"] and pre["grants"].get(right, {}).get("holder") == left
        if name == "parent":
            return left not in pre["revoked"] and pre["grants"].get(left, {}).get("parent") == right
        entity = pre["entities"].get(right if name == "owns" else left)
        return entity is not None and {"owns": entity["owner"] == left, "type": entity["type"] == right,
                                       "state": entity["state"] == right}.get(name, False)

    def _frozen(self, pre, resource) -> None:
        if any(_inside(resource, scope) for scope in pre["frozen"]):
            _no("the resource is frozen")

    def _spent(self, pre, delta, chain, at) -> None:
        if [op for op in delta if op[:2] == ("push", "uses")] != [("push", "uses", g["id"], at) for g in chain]:
            _no("an act charges every capability of its chain")
        for g in chain:
            b = g["budget"]
            if b and sum(1 for t in pre["uses"].get(g["id"], ()) if t > at - b["window"]) >= b["count"]:
                _no("a capability budget is exceeded")

    # ---- the effect line --------------------------------------------------------------------------------------------
    def _intent(self, pre, record, delta, root, signers):
        b = record["body"]
        resource = self._resource_of(b["op"], b["args"])
        expected = {"id": b["id"], "op": b["op"], "resource": resource, "args": b["args"], "author": b["author"],
                    "under": b["under"], "stmt": {**b, "resource": resource}, "contract": digest(self._op(b["op"]))}
        stored = [op for op in delta if op[:2] == ("put", "intents")]
        if len(stored) != 1 or stored[0][2] != b["id"] or {k: v for k, v in stored[0][3].items() if k != "label"} != expected:
            _no("the stored intent differs from the signed request")
        _, label = self._authority(pre, b["author"], b["under"], "effect:" + b["op"], resource, b, record["at"])
        if stored[0][3]["label"] != sorted(label):
            _no("the intent's provenance label is wrong")
        self._frozen(pre, resource)

    def _profile(self, pre, it, approvers, root_digest, at) -> None:
        approved = set(approvers) & _humans(pre["root"]) if root_digest == pre["root_digest"] else set()
        if self._op(it["op"])["profile"] == "human_quorum" and len(approved) < pre["root"]["threshold"]:
            _no("a sensitive effect lacks the current human quorum")
        heartbeat = self.raw["controls"]["heartbeat_ms"]
        prudent = heartbeat and any(at - pre["heartbeats"].get(i, -10 ** 15) > heartbeat
                                    for i, d in pre["root"]["identities"].items() if d["kind"] == "sentinel")
        if (prudent or it["id"] in pre["flags"]) and not approved:
            _no("a flagged or prudent effect lacks a human co-signature")

    def _effect_authority(self, pre, it, at) -> list:
        if it["contract"] != digest(self._op(it["op"])):
            _no("the operation contract changed")
        chain, _ = self._authority(pre, it["author"], it["under"], "effect:" + it["op"], it["resource"], it["stmt"], at)
        self._frozen(pre, it["resource"])
        return chain

    def _token(self, pre, record, delta, root, signers):
        b = record["body"]
        if _kind(root, record["author"]) != "guard" or b["intent"] in pre["token_of"]:
            _no("a guard issues at most one token per intent")
        it = pre["intents"][b["intent"]]
        if b["args_digest"] != digest(it["args"]):
            _no("a token binds the intent's arguments")
        chain = self._effect_authority(pre, it, record["at"])
        tok = {"intent": b["intent"], "guard": record["author"], "humans": sorted(signers & _humans(root)),
               "root_digest": pre["root_digest"]}
        if [op for op in delta if op[:2] == ("put", "tokens")] != [("put", "tokens", b["id"], tok)] or \
                [op for op in delta if op[:2] == ("put", "token_of")] != [("put", "token_of", b["intent"], b["id"])]:
            _no("the token equals its signed request and verified approvals")
        self._profile(pre, it, tok["humans"], tok["root_digest"], record["at"])
        self._spent(pre, delta, chain, record["at"])

    def _reservation(self, pre, record, delta, root, signers):
        token = record["body"]["token"]
        tok = pre["tokens"].get(token)
        if tok is None or tok["guard"] != record["author"] or token in pre["reserved"]:
            _no("a token is reserved once, by the guard that issued it")
        it = pre["intents"][tok["intent"]]
        self._effect_authority(pre, it, record["at"])
        self._profile(pre, it, tok["humans"], tok["root_digest"], record["at"])
        if [op for op in delta if op[:2] == ("put", "reserved")] != [("put", "reserved", token, record["body"]["id"])]:
            _no("the reservation records exactly its token")

    def _execution(self, pre, record, delta, root, signers):
        b = record["body"]
        tok = pre["tokens"].get(b["token"])
        if (tok is None or tok["guard"] != record["author"] or b["token"] not in pre["reserved"]
                or b["token"] in pre["executed"] or b["result"] not in ("ok", "failed", "unknown")):
            _no("an execution reports one reserved token, once, by its guard")
        if [op for op in delta if op[:2] == ("put", "executed")] != [("put", "executed", b["token"], b["result"])]:
            _no("the execution records exactly its result")

    def _attestation(self, pre, record, action, resource):
        b = record["body"]
        return self._authority(pre, b["author"], b["under"], action, resource, b, record["at"])

    def _reconciliation(self, pre, record, delta, root, signers):
        b = record["body"]
        it = pre["intents"].get(b["intent"])
        if it is None or b["result"] not in ("applied", "not_applied"):
            _no("a reconciliation names an intent and a definitive result")
        _, label = self._attestation(pre, record, "reconcile", it["resource"])
        if label & set(it["label"]):
            _no("a reconciliation is independent of the actor")

    def _certifies(self, chain, level) -> None:
        if level not in self.levels or "certify:" + level not in chain[0]["actions"]:
            _no("the chain cannot certify this level")

    def _observation(self, pre, record, delta, root, signers):
        b = record["body"]
        if b["property"] in self.raw.get("instruments", {}):
            _no("an instrumented property needs a measurement")
        chain, label = self._attestation(pre, record, "observe", b["resource"])
        self._certifies(chain, b["level"])
        value = {"id": b["id"], "resource": b["resource"], "property": b["property"], "status": b["status"],
                 "level": b["level"], "at": record["at"], "author": b["author"], "label": sorted(label)}
        self._exactly(delta, [("put", "observations", f"{b['resource']}|{b['property']}|{b['author']}", value)])

    def _measurement(self, pre, record, delta, root, signers):
        b = record["body"]
        spec = self.raw.get("instruments", {}).get(b["property"])
        if (spec is None or b["author"] not in spec["sources"] or b["method"] != spec["method"]
                or b["coverage"] != spec["coverage"] or not b["measured_at"] <= record["at"] <= b["measured_at"] + spec["fresh_ms"]):
            _no("an unqualified measurement")
        chain, label = self._attestation(pre, record, "observe", b["resource"])
        self._certifies(chain, b["level"])
        if self.levels.index(b["level"]) < self.levels.index(spec["min_level"]):
            _no("the measurement is below its instrument's level")
        value = {"id": b["id"], "resource": b["resource"], "property": b["property"], "status": b["status"],
                 "level": b["level"], "at": b["measured_at"], "author": b["author"], "label": sorted(label),
                 "method": b["method"], "coverage": b["coverage"], "instrument": digest(spec), "artifact": b["artifact"]}
        self._exactly(delta, [("put", "observations", f"{b['resource']}|{b['property']}|{b['author']}", value)])

    def _evidence(self, pre, record, delta, root, signers):
        b = record["body"]
        chain, label = self._attestation(pre, record, record["kind"], b["resource"])
        if "level" in b:
            self._certifies(chain, b["level"])
        for rule in self.raw.get("discharges", {}).get(record["kind"], []):
            it = pre["intents"].get(b[rule["key"]])
            if (it is None or it["resource"] != b["resource"] or label & set(it["label"])
                    or self.levels.index(b["level"]) < self.levels.index(rule["min_level"])):
                _no("a proof is independent, on the exact resource, at the required level")

    # ---- typed resources --------------------------------------------------------------------------------------------
    @staticmethod
    def _scalars(spec, values) -> None:
        if set(values) - set(spec):
            _no("an undeclared resource field")
        for name, kind in spec.items():
            if name not in values:
                if kind.endswith("?"):
                    continue
                _no("a missing resource field")
            kind, v = kind.rstrip("?"), values[name]
            ok = {"str": lambda: isinstance(v, str) and len(v) <= 4096, "int": lambda: type(v) is int,
                  "bool": lambda: type(v) is bool}.get(kind, lambda: isinstance(v, str))()
            if not ok:
                _no("a resource field has the wrong type")

    def _resource(self, pre, record, delta, root, signers):
        b = record["body"]
        spec = self.raw.get("resources", {}).get(b["type"])
        if spec is None or b["resource"] in pre["entities"] or len(pre["entities"]) >= 4096:
            _no("an invalid resource registration")
        chain, _ = self._attestation(pre, record, "register:" + b["type"], b["resource"])
        self._frozen(pre, b["resource"])
        self._scalars(spec["fields"], b["fields"])
        self._spent(pre, delta, chain, record["at"])
        value = {"type": b["type"], "owner": b["author"], "state": spec["initial"], "fields": b["fields"],
                 "contract": digest(spec), "version": 1, "created": record["at"]}
        if [op for op in delta if op[:2] == ("put", "entities")] != [("put", "entities", b["resource"], value)]:
            _no("the registered resource equals its signed request")

    def _transition(self, pre, record, delta, root, signers):
        b = record["body"]
        entity = pre["entities"].get(b["resource"])
        if entity is None or digest(entity) != b["expected"]:
            _no("a transition binds the exact existing resource")
        spec = self.raw.get("resources", {}).get(entity["type"])
        if spec is None or digest(spec) != entity["contract"]:
            _no("the resource contract changed")
        rule = spec["transitions"].get(b["operation"])
        if rule is None or entity["state"] not in rule["from"] or set(b["changes"]) != set(rule["writes"]):
            _no("the transition is not declared or not exhaustive")
        chain, label = self._attestation(pre, record, f"transition:{entity['type']}:{b['operation']}", b["resource"])
        self._frozen(pre, b["resource"])
        fields = {**entity["fields"], **b["changes"]}
        self._scalars(spec["fields"], fields)
        if not self._holds(pre, rule["requires"], b, label, record["at"]):
            _no("the transition's constraints do not hold")
        self._spent(pre, delta, chain, record["at"])
        value = {**entity, "fields": fields, "state": rule["to"], "version": entity["version"] + 1}
        if [op for op in delta if op[:2] == ("put", "entities")] != [("put", "entities", b["resource"], value)]:
            _no("the transition writes exactly its declared consequence")

    # ---- protocol obligations and the line --------------------------------------------------------------------------
    def _protocol_obligations(self, pre, record, delta):
        kind, b, at = record["kind"], record["body"], record["at"]
        intent_of = lambda t: pre["tokens"].get(t, {}).get("intent")
        consume = {"token": {f"pending:{b.get('intent')}"}, "reservation": {f"unredeemed:{b.get('token')}"},
                   "execution": {f"reconcile:{intent_of(b.get('token'))}"} if b.get("result") in ("ok", "failed") else set(),
                   "reconciliation": {f"reconcile:{b.get('intent')}"}}.get(kind, set())
        opens = {"intent": {f"pending:{b['id']}"}, "token": {f"unredeemed:{b['id']}"},
                 "reservation": {f"reconcile:{intent_of(b.get('token'))}"},
                 "execution": {f"proof:{intent_of(b.get('token'))}"} if b.get("result") == "ok" else set(),
                 "reconciliation": {f"proof:{b.get('intent')}"} if b.get("result") == "applied" else set()}.get(kind, set())
        if kind in self.evidence:
            consume = {f"proof:{b[r['key']]}" for r in self.raw.get("discharges", {}).get(kind, [])}
        dropped = {op[2] for op in delta if op[:2] == ("drop", "obligations")}
        if dropped != consume:
            _no(f"{kind} consumes exactly {sorted(consume)}")
        for name in dropped:
            ob = pre["obligations"].get(name)
            if ob is None or not _live(ob, at):
                _no(f"{kind} consumes a live {name}")
        put = {op[2]: op[3] for op in delta if op[:2] == ("put", "obligations")}
        if set(put) != opens:
            _no(f"{kind} opens exactly {sorted(opens)}")
        ttl = self.raw["ttl"]
        for name, ob in put.items():
            stage = name.split(":", 1)[0]
            if name in pre["obligations"] or ob["stage"] != stage or ob["opened"] != at or ob["due"] != at + ttl[stage]:
                _no(f"{name} opens fresh with its law deadline")

    def _line(self, pre, record, delta):
        """The effect line moves exactly along the FLOOR-0 table, once per effect entry, and nowhere else."""
        kind, b, at = record["kind"], record["body"], record["at"]
        moves = [op for op in delta if op[:2] == ("put", "line")]
        if kind not in ("intent", "token", "reservation", "execution", "reconciliation"):
            if moves:
                _no(f"{kind} may not move an effect line")
            return
        intent = {"intent": b["id"], "token": b.get("intent"), "reconciliation": b.get("intent")}.get(kind) \
            or pre["tokens"].get(b.get("token"), {}).get("intent")
        leave, enter = LINE.get((kind, b.get("result") if kind in ("execution", "reconciliation") else None), ((), None))
        cur = pre["line"].get(intent)
        state = None if cur is None else ("expired" if cur["state"] == "reserved" and at > cur["at"] + DISPATCH_MS
                                          else cur["state"])
        if state not in leave or moves != [("put", "line", intent, {"state": enter, "at": at})]:
            _no(f"{kind} moves the effect line outside its table")

    def _law_obligations(self, pre, record, ops):
        """Refuse-level law obligations: which instances this entry may open, close or needs open."""
        label = self._label(pre, record)
        may_open, may_close, may_satisfy = set(), set(), set()
        for d in self.refuse:
            for rule in d["gate"]:
                k = self._key(rule, record)
                inst = pre["obligations"].get(f"{d['id']}:{k}")
                if k is not None and not (inst and _live(inst, record["at"]) and "label" in inst
                                          and inst["contract"] == self.contracts[d["id"]]
                                          and not set(inst["label"]) & set(label)):
                    _no(f"{record['kind']} passed a closed gate {d['id']}:{k}")
            for rule in d["open"]:
                k = self._key(rule, record)
                if k is not None:
                    may_open.add(f"{d['id']}:{k}")
                    may_close.add(f"{d['id']}:{k}")
            for rule in d["close"]:
                k = self._key(rule, record)
                if k is not None:
                    may_close.add(f"{d['id']}:{k}")
                    may_satisfy.add(f"{d['id']}:{k}")
        dropped = {op[2] for op in ops if op[:2] == ("drop", "obligations")}
        for op in ops:
            name, stage = op[2], op[2].split(":", 1)[0]
            if op[:2] == ("put", "obligations") and (
                    name not in may_open or op[3]["due"] <= op[3]["opened"] or op[3].get("label") != label
                    or op[3]["stage"] != stage or op[3]["contract"] != self.contracts.get(stage)):
                _no(f"{record['kind']} may not open {name}")
            if op[:2] == ("drop", "obligations") and (name not in may_close or name not in pre["obligations"]):
                _no(f"{record['kind']} may not close {name}")
            if op[:2] == ("put", "closed"):
                prev = pre["obligations"].get(name)
                if (name not in may_satisfy or name not in dropped or prev is None or not _live(prev, record["at"])
                        or op[3] != {"type": prev["stage"], "key": prev["key"], "at": record["at"], "label": label,
                                     "contract": prev["contract"]}):
                    _no(f"{record['kind']} may not record {name} as closed")

    @staticmethod
    def _key(rule, record):
        b = record["body"]
        if record["kind"] != rule["kind"] or (rule["op"] is not None and b.get("op") != rule["op"]):
            return None
        if any(_field(b, p) != v for p, v in rule["where"].items()):
            return None
        return _field(b, rule["key"])

    @staticmethod
    def _label(pre, record) -> list:
        holders, seen, gid = {record["author"]}, set(), record["body"].get("under", "root")
        while gid != "root" and gid in pre["grants"] and gid not in seen and len(seen) < 16:
            seen.add(gid)
            holders.add(pre["grants"][gid]["holder"])
            gid = pre["grants"][gid]["parent"]
        return sorted(holders)

    # ---- the physical gate ------------------------------------------------------------------------------------------
    def dispatch(self, pre: dict, token: str, now: int, effective: dict, law_digest: str) -> dict:
        """Recompute, apart from the kernel, the exact effect allowed to leave now. Raises Disagreement otherwise."""
        try:
            if pre["law"]["digest"] != law_digest:
                _no("dispatch is judged under the law in force")
            self.use(effective, law_digest)
            tok = pre["tokens"][token]
            cur = pre["line"].get(tok["intent"])
            if cur is None or cur["state"] != "reserved" or now > cur["at"] + DISPATCH_MS:
                _no("only a reservation inside its dispatch window may leave")
            it = pre["intents"][tok["intent"]]
            self._effect_authority(pre, it, now)
            self._profile(pre, it, tok["humans"], tok["root_digest"], now)
            return {"op": it["op"], "resource": it["resource"], "args": copy.deepcopy(it["args"])}
        except Disagreement:
            raise
        except Exception as exc:
            _no(f"cannot independently check the departure: {type(exc).__name__}")
