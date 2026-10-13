"""The one constitutional judgment (K10, §6).

`decide(state, entry)` reads the state, never mutates it, and returns (record, delta) or raises Refused.
`apply(state, delta)` is the only mutation; a delta is data: put / drop / set / push. Every transition is therefore
caused by exactly one signed entry (F0-4) and nothing changes because time passed.

Admission of an entry, in this order:
    HIST   it extends the head; its time runs forward and stays within reach of the last witnessed time
    PROV   every signature verifies against the root in force; the subject names this ledger; the author signed
    TYPE   the body is exactly of its declared shape
    CAP    one gate per polarity (F0-5), then the capability chain for what acts, attests or attenuates
    OBL    the effect line and the law's refuse-level obligations
    NIV    a level is claimed only by a chain allowed to certify it
Every refusal is MECHANISM.REASON with one of the six mechanisms. Nothing is admitted by default.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass

from . import language, obligations as obl
from .canon import CanonError, canon, detach, digest, parse
from .floor0 import LAPSE, LINE, MAX_AHEAD_MS, POLARITY, RESTRICT_BY, line_state
from .identity import IdentityError, check_root, humans, kind_of, open_envelope, signers as verify_signers, subject_name
from .law import MAX_ENTITIES, Law, LawError, Release, compose
from .types import PATTERN, RESOURCE, ShapeError, build, covers, within

MECHANISMS = ("CAP", "OBL", "NIV", "PROV", "TYPE", "HIST")
MAX_CHAIN = 16
MAX_ENTRY_BYTES = 1 << 20

_PROPOSAL = {"override": "bool?"}
_SCOPE = {"holder": "id", "actions": "list", "resources": "list", "conditions": "list", "budget": "map?",
          "not_after": "int"}
SHAPES = {
    "genesis": {"root": "map", "law": "map", "code": "digest"},
    "law": {"client": "map", **_PROPOSAL},
    "rotate": {"root": "map", **_PROPOSAL},
    "grant": {**_SCOPE, **_PROPOSAL},
    "unfreeze": {"scope": "pattern", **_PROPOSAL},
    "activate": {"proposal": "id"},
    "veto": {"proposal": "id"},
    "delegate": {"parent": "id", **_SCOPE},
    "revoke": {"grant": "id"},
    "freeze": {"scope": "pattern"},
    "flag": {"intent": "id"},
    "heartbeat": {"seen": "int"},
    "invalidate": {"evidence": "id"},
    "checkpoint": {"size": "int", "head": "digest"},
    "intent": {"under": "id", "op": "id", "args": "map", "retry_of": "id?"},
    "token": {"intent": "id", "args_digest": "digest"},
    "reservation": {"token": "id"},
    "execution": {"token": "id", "result": "str"},
    "resource": {"under": "id", "resource": "resource", "type": "id", "fields": "map"},
    "transition": {"under": "id", "resource": "resource", "operation": "id", "expected": "digest", "changes": "map"},
    "reconciliation": {"under": "id", "intent": "id", "result": "str"},
    "observation": {"under": "id", "resource": "resource", "property": "str", "status": "str", "level": "str"},
    "measurement": {"under": "id", "resource": "resource", "property": "str", "status": "str", "level": "str",
                    "method": "id", "coverage": "resource", "measured_at": "int", "artifact": "digest"},
}
assert set(SHAPES) == set(POLARITY), "every kernel kind has exactly one polarity"


class Refused(Exception):
    def __init__(self, code: str, detail: str = ""):
        assert code.split(".", 1)[0] in MECHANISMS, code
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


def no(code: str, detail: str = ""):
    raise Refused(code, detail)


def empty() -> dict:
    return {"size": 0, "head": None, "domain": None, "last_at": 0, "anchor_at": 0, "witnessed": False,
            "root": None, "root_digest": None, "code": None, "law": None,
            "statements": {}, "proposals": {}, "grants": {}, "revoked": {}, "frozen": {}, "flags": {},
            "heartbeats": {}, "obligations": {}, "closed": {}, "intents": {}, "tokens": {}, "token_of": {},
            "reserved": {}, "executed": {}, "uses": {}, "line": {}, "observations": {}, "entities": {},
            "invalidated": {}}


def apply(state: dict, delta) -> dict:
    """The only mutation of kernel state. Values put here are never mutated afterwards."""
    for op in delta:
        if op[0] == "put":
            state[op[1]][op[2]] = op[3]
        elif op[0] == "drop":
            del state[op[1]][op[2]]
        elif op[0] == "set":
            state[op[1]] = op[2]
        elif op[0] == "push":
            state[op[1]][op[2]] = [*state[op[1]].get(op[2], ()), op[3]]
        else:
            raise ValueError(f"unknown delta {op[0]}")
    return state


def lapsed(ob: dict, at: int) -> bool:
    """Before any effect, time lapses an obligation; after a reservation nothing lapses (F0-6)."""
    return (ob["stage"] in LAPSE or ob.get("on_due") == "lapse") and at > ob["due"]


@dataclass(frozen=True)
class Decision:
    """An immutable judgment: bytes, never live objects. It is not a token, a reservation or a permission to send."""
    verdict: str                 # ACCEPT | REJECT
    code: str
    before: str
    after: str | None
    entry: bytes
    record: bytes | None
    delta: bytes
    detail: str = ""


@dataclass
class _Ctx:
    """Everything one judgment reads. Built once per entry; never shared between entries."""
    s: dict
    law: Law
    kind: str
    body: dict
    signers: set
    root: dict

    @property
    def at(self) -> int:
        return self.body["at"]


class Kernel:
    """The kernel carries no client law of its own: the genesis brings the first one, `law` entries replace it by
    widening, and every entry is judged under the release floors composed with the client law in force at its
    position. `code` is the digest of the code release, supplied by T01; the kernel never computes it."""

    def __init__(self, release: Release, code: str):
        self.release, self.code = release, code
        self._laws: dict[str, Law] = {}

    # ---- laws -----------------------------------------------------------------------------------------------------
    def load(self, client) -> Law:
        """The floors composed with this client law, validated, cached by effective digest."""
        try:
            effective = compose(self.release, copy.deepcopy(client))
            law = Law(effective)
        except (LawError, ValueError, TypeError, KeyError) as exc:
            raise LawError(str(exc)) from None
        return self._laws.setdefault(law.digest, law)

    def law_of(self, s: dict) -> Law:
        law = self._laws.get(s["law"]["digest"]) or self.load(s["law"]["client"])
        if law.digest != s["law"]["digest"]:
            no("HIST.LAW_PIN", "the client law does not match its effective pin")
        return law

    def law_by_digest(self, ident: str) -> Law:
        return self._laws[ident]

    # ---- the ledger -----------------------------------------------------------------------------------------------
    def replay(self, entries) -> dict:
        state = empty()
        for entry in entries:
            apply(state, self.decide(state, entry)[1])
        return state

    def decide(self, state: dict, entry) -> tuple[dict, list]:
        """Total: any input yields a verdict; an unexpected input error is a refusal, never an admission."""
        try:
            entry = parse(canon(entry), max_bytes=MAX_ENTRY_BYTES)       # bounded, detached, canonical
            return self._decide(state, entry)
        except Refused:
            raise
        except (KeyError, TypeError, ValueError, AttributeError, IndexError, RecursionError, CanonError) as exc:
            raise Refused("TYPE.MALFORMED", type(exc).__name__) from None

    def judge(self, state: dict, entry) -> Decision:
        """The same judgment as `decide`, as immutable bytes with the state digests before and after."""
        before = digest(detach(state))
        try:
            encoded = canon(entry)
        except CanonError as exc:
            return Decision("REJECT", "TYPE.MALFORMED", before, None, b"", None, b"[]", str(exc))
        try:
            record, delta = self.decide(state, entry)
        except Refused as r:
            return Decision("REJECT", r.code, before, None, encoded, None, b"[]", r.detail)
        after = apply(copy.deepcopy(state), copy.deepcopy(delta))
        return Decision("ACCEPT", "OK", before, digest(detach(after)), encoded, canon(record), canon(detach(delta)))

    def commit(self, state: dict, decision: Decision) -> dict:
        """Rejudge the exact signed input; never trust a supplied verdict or delta. In-memory only: durable authority
        exists only once the journal (T04) has pinned and committed it after the independent check (T05)."""
        if not isinstance(decision, Decision) or decision.verdict != "ACCEPT":
            no("HIST.COMMIT", "an accepted judgment is required")
        if digest(detach(state)) != decision.before:
            no("HIST.STALE", "the judgment is bound to another prefix")
        actual = self.judge(state, parse(decision.entry, max_bytes=MAX_ENTRY_BYTES))
        if actual != decision:
            no("HIST.COMMIT", "the judgment must equal the exhaustive rederived consequence")
        return apply(copy.deepcopy(state), parse(actual.delta, max_bytes=64 << 20))

    # ---- one entry --------------------------------------------------------------------------------------------------
    def _decide(self, s: dict, entry: dict) -> tuple[dict, list]:
        if not isinstance(entry, dict) or set(entry) != {"seq", "prev", "envelope"}:
            no("HIST.SHAPE", "an entry is {seq, prev, envelope}")
        if type(entry["seq"]) is not int or entry["seq"] != s["size"] or entry["prev"] != s["head"]:
            no("HIST.CHAIN", "the entry does not extend the head")
        try:
            kind, body, message, name = open_envelope(entry["envelope"])
        except IdentityError as exc:
            no("PROV.ENVELOPE", str(exc))
        genesis = kind == "genesis"
        if genesis != (s["size"] == 0):
            no("HIST.GENESIS", "the genesis is the first entry, and only the first")
        law = None if genesis else self.law_of(s)
        shape = SHAPES.get(kind) or (law.evidence.get(kind) if law else None)
        if shape is None:
            no("TYPE.KIND", f"{kind} is not a kind of this law")
        try:
            build(shape, body)
        except ShapeError as exc:
            no("TYPE.SHAPE", str(exc))
        if genesis:
            try:
                check_root(body["root"])
            except IdentityError as exc:
                no("TYPE.ROOT", str(exc))
            try:
                law = self.load(body["law"])
            except LawError as exc:
                no("TYPE.LAW", str(exc))
        elif s["code"] != self.code:
            no("HIST.CODE", "this state belongs to another code release")
        root = body["root"] if genesis else s["root"]
        if name != subject_name("genesis" if genesis else s["domain"], kind, body["id"]):
            no("PROV.DOMAIN", "the statement names another ledger")
        signed = verify_signers(root, entry["envelope"], message)
        if signed is None:
            no("PROV.SIGNATURE", "every signature must verify against the root in force")
        if body["author"] not in signed:
            no("PROV.AUTHOR", "the author did not sign")
        polarity = POLARITY.get(kind, "attest")
        at = body["at"]
        if at < 0:
            no("HIST.TIME", "ledger time is nonnegative")
        if not genesis:
            if at < s["last_at"] or (at == s["last_at"] and polarity != "restrict"):
                no("HIST.TIME", "time runs forward (a restriction may share the last instant)")
            if kind != "checkpoint" and at > s["anchor_at"] + MAX_AHEAD_MS:
                no("HIST.AHEAD", "too far ahead of the last witnessed time")
        if body["id"] in s["statements"]:
            no("TYPE.DUPLICATE", body["id"])
        c = _Ctx(s, law, kind, body, signed, root)
        self._gate(c, polarity)
        delta: list = []
        handler = getattr(self, "_" + kind, None) if kind in SHAPES else None
        (handler or self._evidence)(c, delta)
        if law.obligations:
            self._law_obligations(c, delta)
        record = {"kind": kind, "polarity": polarity, "author": body["author"], "at": at, "body": body,
                  "signers": sorted(signed), "law": law.digest}
        delta += [("put", "statements", body["id"], record), ("set", "size", s["size"] + 1),
                  ("set", "head", digest(entry)), ("set", "last_at", at)]
        return record, delta

    # ---- CAP: one gate per polarity -------------------------------------------------------------------------------
    def _gate(self, c: _Ctx, polarity: str) -> None:
        author_kind = kind_of(c.root, c.body["author"])
        if polarity == "widen":
            if author_kind != "human":
                no("CAP.HUMAN", "a widening is stated by a human of the root")
            need = c.root["threshold"] + (1 if c.body.get("override") else 0)
            got = c.signers & humans(c.root)
            if len(got) < need:
                no("CAP.QUORUM", f"{need} distinct humans of the root must sign, {len(got)} did")
        elif polarity == "restrict":
            if author_kind not in RESTRICT_BY[c.kind] and c.kind != "revoke":
                no("CAP.RESTRICT", f"{c.kind} comes from a {' or '.join(RESTRICT_BY[c.kind])} of the root")
        elif polarity == "witness":
            if author_kind != "witness":
                no("CAP.WITNESS", "time is stated by witnesses")
            got = {i for i in c.signers if kind_of(c.root, i) == "witness"}
            if len(got) < c.law.witness_quorum:
                no("CAP.WITNESS", f"{c.law.witness_quorum} witnesses must sign, {len(got)} did")
        # attenuate, act, attest: the capability chain is checked by the handler

    # ---- widen ------------------------------------------------------------------------------------------------------
    def _genesis(self, c: _Ctx, d: list) -> None:
        if c.body["code"] != self.code:
            no("HIST.CODE", "the genesis binds another code release")
        self._enough_witnesses(c.body["root"], c.law)
        d += [("set", "domain", digest(c.body)), ("set", "root", c.body["root"]),
              ("set", "root_digest", digest(c.body["root"])), ("set", "anchor_at", c.at),
              ("set", "code", c.body["code"]), ("set", "law", {"digest": c.law.digest, "client": c.body["law"]})]

    @staticmethod
    def _enough_witnesses(root, law: Law) -> None:
        if sum(d["kind"] == "witness" for d in root["identities"].values()) < law.witness_quorum:
            no("CAP.WITNESS", "the root lacks enough witnesses for the law's time quorum")

    def _propose(self, c: _Ctx, d: list, kind: str, extra=None) -> None:
        factor = 2 if c.body.get("override") else 1
        d.append(("put", "proposals", c.body["id"], {
            "id": c.body["id"], "kind": kind, "body": c.body, "signers": sorted(c.signers & humans(c.s["root"])),
            "not_before": c.at + factor * c.law.delay[kind], "override": bool(c.body.get("override")),
            "root_digest": c.s["root_digest"], "law_digest": c.s["law"]["digest"], **(extra or {})}))

    def _rotate(self, c: _Ctx, d: list) -> None:
        try:
            check_root(c.body["root"])
        except IdentityError as exc:
            no("TYPE.ROOT", str(exc))
        self._enough_witnesses(c.body["root"], c.law)
        self._propose(c, d, "rotate")

    def _grant(self, c: _Ctx, d: list) -> None:
        self._scope(c)
        if c.body["not_after"] <= c.at:
            no("TYPE.SHAPE", "a grant ends after it is proposed")
        self._propose(c, d, "grant")

    def _law(self, c: _Ctx, d: list) -> None:
        """A new client law: composed and validated now, in force on activation."""
        try:
            new = self.load(c.body["client"])
        except LawError as exc:
            no("TYPE.LAW", str(exc))
        self._enough_witnesses(c.s["root"], new)
        self._propose(c, d, "law")

    def _unfreeze(self, c: _Ctx, d: list) -> None:
        freeze = c.s["frozen"].get(c.body["scope"])
        if freeze is None:
            no("CAP.NOT_FROZEN", "that scope is not frozen")
        self._propose(c, d, "unfreeze", {"freeze": freeze})

    def _activate(self, c: _Ctx, d: list) -> None:
        p = c.s["proposals"].get(c.body["proposal"])
        if p is None:
            no("CAP.PROPOSAL", "no such pending proposal")
        if p["root_digest"] != c.s["root_digest"] or p["law_digest"] != c.s["law"]["digest"]:
            no("CAP.STALE", "the proposal was approved under another root or law: propose again")
        if c.s["anchor_at"] < p["not_before"]:
            no("CAP.DELAY", f"the proposal activates at {p['not_before']} of witnessed time")
        pb = p["body"]
        if p["kind"] == "law":
            d.append(("set", "law", {"digest": self.load(pb["client"]).digest, "client": pb["client"]}))
        elif p["kind"] == "rotate":
            d += [("set", "root", pb["root"]), ("set", "root_digest", digest(pb["root"]))]
        elif p["kind"] == "grant":
            if pb["not_after"] < c.at:
                no("CAP.EXPIRED", "the proposed grant has already ended")
            d.append(("put", "grants", pb["id"], self._grant_record(c.law, pb, "root", c.at)))
        else:
            if c.s["frozen"].get(pb["scope"]) != p["freeze"]:
                no("CAP.STALE", "the scope was frozen again since: propose again")
            d.append(("drop", "frozen", pb["scope"]))
        d.append(("drop", "proposals", p["id"]))

    # ---- attenuate --------------------------------------------------------------------------------------------------
    def _scope(self, c: _Ctx) -> None:
        b = c.body
        acts, res = b["actions"], b["resources"]
        if not acts or len(acts) > 64 or not all(isinstance(a, str) and 0 < len(a) <= 128 and "*" not in a for a in acts):
            no("TYPE.SHAPE", "actions are explicit names")
        if not res or len(res) > 64 or not all(isinstance(r, str) and PATTERN.fullmatch(r) for r in res):
            no("TYPE.SHAPE", "resources are patterns ('*' only after a separator)")
        if kind_of(c.s["root"], b["holder"]) is None:
            no("CAP.HOLDER", "the holder is not an identity of the root")
        if len(b["conditions"]) > 16 or any(not isinstance(x, str) or x not in c.law.conditions for x in b["conditions"]):
            no("CAP.CONDITION", "conditions name policies of the sealed law (at most 16)")
        budget = b.get("budget")
        if budget is not None and (set(budget) != {"count", "window"}
                                   or not all(type(v) is int and v > 0 for v in budget.values())):
            no("TYPE.SHAPE", "a budget is {count, window}, both positive")

    @staticmethod
    def _grant_record(law: Law, b: dict, parent: str, effective_at: int) -> dict:
        return {"id": b["id"], "parent": parent, "holder": b["holder"], "actions": list(b["actions"]),
                "resources": list(b["resources"]), "conditions": list(b["conditions"]), "budget": b.get("budget"),
                "not_after": b["not_after"], "effective_at": effective_at,
                "condition_digests": sorted(law.condition_digest(x) for x in b["conditions"])}

    def _delegate(self, c: _Ctx, d: list) -> None:
        self._scope(c)
        b = c.body
        parent = self._chain(c, b["parent"])[0]
        if b["author"] != parent["holder"]:
            no("CAP.ATTENUATE", "only the holder of a capability derives from it")
        if not set(b["actions"]) <= set(parent["actions"]) or not within(b["resources"], parent["resources"]):
            no("CAP.WIDENS", "a derived capability is included in its parent")
        record = self._grant_record(c.law, b, b["parent"], c.at)
        if not set(parent["condition_digests"]) <= set(record["condition_digests"]) or b["not_after"] > parent["not_after"]:
            no("CAP.WIDENS", "a derived capability keeps every condition and ends no later")
        pb, cb = parent["budget"], b.get("budget")
        if pb and not (cb and cb["count"] <= pb["count"] and cb["window"] >= pb["window"]):
            no("CAP.WIDENS", "a derived capability keeps its parent's budget")
        d.append(("put", "grants", b["id"], record))

    # ---- restrict ---------------------------------------------------------------------------------------------------
    def _veto(self, c: _Ctx, d: list) -> None:
        p = c.s["proposals"].get(c.body["proposal"])
        if p is None:
            no("CAP.VETO", "nothing pending to veto")
        if p["override"]:
            no("CAP.VETO", "an override by a higher quorum cannot be vetoed")
        if c.body["author"] in p["signers"]:
            no("CAP.VETO", "a signer of the proposal cannot veto it")
        d.append(("drop", "proposals", p["id"]))

    def _revoke(self, c: _Ctx, d: list) -> None:
        gid = c.body["grant"]
        if gid not in c.s["grants"]:
            no("CAP.CHAIN", "nothing to revoke")
        if kind_of(c.s["root"], c.body["author"]) != "human":
            holders, cur = set(), gid
            while cur != "root" and cur in c.s["grants"]:
                holders.add(c.s["grants"][cur]["holder"])
                cur = c.s["grants"][cur]["parent"]
            if c.body["author"] not in holders:
                no("CAP.RESTRICT", "a revocation comes from a human of the root or a holder along the chain")
        d.append(("put", "revoked", gid, c.at))

    def _freeze(self, c: _Ctx, d: list) -> None:
        d.append(("put", "frozen", c.body["scope"], c.body["id"]))

    def _flag(self, c: _Ctx, d: list) -> None:
        if c.body["intent"] not in c.s["intents"]:
            no("CAP.FLAG", "a flag names an intent")
        d.append(("put", "flags", c.body["intent"], c.body["id"]))

    def _heartbeat(self, c: _Ctx, d: list) -> None:
        """A sentinel's signal only restores the law's default; its silence tightens."""
        if c.body["seen"] > c.s["size"]:
            no("CAP.HEARTBEAT", "a heartbeat is about what exists")
        d.append(("put", "heartbeats", c.body["author"], c.at))

    def _invalidate(self, c: _Ctx, d: list) -> None:
        found = [o for o in c.s["observations"].values() if o["id"] == c.body["evidence"]]
        if not found:
            no("PROV.UNKNOWN", "an invalidation names admitted evidence")
        if kind_of(c.s["root"], c.body["author"]) != "human" and any(o["author"] != c.body["author"] for o in found):
            no("CAP.RESTRICT", "an oracle invalidates only its own evidence")
        d.append(("put", "invalidated", c.body["evidence"], c.body["id"]))

    # ---- witness ----------------------------------------------------------------------------------------------------
    def _checkpoint(self, c: _Ctx, d: list) -> None:
        if c.body["size"] != c.s["size"] or c.body["head"] != c.s["head"]:
            no("HIST.CHECKPOINT", "a checkpoint names the current head")
        d += [("set", "anchor_at", c.at), ("set", "witnessed", True)]

    # ---- capability chains and facts (F0-8) -----------------------------------------------------------------------
    def _chain(self, c: _Ctx, gid: str) -> list:
        if gid == "root":
            no("CAP.CHAIN", "the root is not a capability: act under a grant")
        chain, seen = [], set()
        while gid != "root":
            g = c.s["grants"].get(gid)
            if g is None or gid in seen or len(chain) >= MAX_CHAIN:
                no("CAP.CHAIN", f"{gid} is not a capability")
            if gid in c.s["revoked"] or g["not_after"] < c.at or kind_of(c.s["root"], g["holder"]) is None:
                no("CAP.WITHDRAWN", f"{gid} is revoked, expired, or its holder left the root")
            if list(g["condition_digests"]) != sorted(c.law.condition_digest(x) for x in g["conditions"]):
                no("CAP.STALE", "a condition of the capability changed: a new grant is required")
            chain.append(g)
            seen.add(gid)
            gid = g["parent"]
        return chain

    def _authorize(self, c: _Ctx, author: str, under: str, action: str, resource: str, stmt: dict):
        chain = self._chain(c, under)
        if chain[0]["holder"] != author:
            no("CAP.HOLDER", "the author does not hold this capability")
        if action not in chain[0]["actions"] or not covers(chain[0]["resources"], resource):
            no("CAP.SCOPE", f"{action} on {resource} is outside the capability")
        label = {author} | {g["holder"] for g in chain}
        if any(g["conditions"] for g in chain):
            atoms = tuple(a for g in chain for x in g["conditions"] for a in c.law.conditions[x])
            facts = self._facts(c, resource, stmt, label, atoms)
            for g in chain:
                for x in g["conditions"]:
                    if not self._evaluate(c.law.conditions[x], facts):
                        no("CAP.CONDITION", f"a condition of {g['id']} does not hold")
        return chain, sorted(label)

    @staticmethod
    def _evaluate(atoms, facts) -> bool:
        try:
            return language.evaluate(atoms, **facts)
        except language.LanguageError as exc:
            no("TYPE.BOUND", str(exc))

    def _facts(self, c: _Ctx, resource: str, stmt: dict, label: set, atoms) -> dict:
        """The facts a condition may read: the statement itself, and only the facts its atoms name, each fresh and
        attested by a chain sharing no holder with the actor's. A fact nobody names cannot crowd out those that matter."""
        s, at, law = c.s, c.at, c.law
        independent = lambda f: not set(f["label"]) & label
        observed_props = language.named(atoms, "observed") | language.named(atoms, "compare")
        open_kinds, closed_kinds = language.named(atoms, "open"), language.named(atoms, "closed_at_least")
        seen = [o for o in s["observations"].values() if o["resource"] == resource and o["property"] in observed_props
                and self.eligible(s, law, o, at) and independent(o)]
        return {
            "request": {**stmt, "author": stmt.get("author"), "resource": resource},
            "observations": {(o["resource"], o["property"], o["status"], o["level"]) for o in seen},
            "authored": {(o["resource"], o["property"], o["status"], o["level"], kind_of(s["root"], o["author"]))
                         for o in seen if kind_of(s["root"], o["author"]) is not None},
            "opened": {(ob["stage"], ob["key"]) for ob in s["obligations"].values()
                       if ob.get("type") == "law" and ob["stage"] in open_kinds and not lapsed(ob, at)
                       and "label" in ob and independent(ob)},
            "closed": {(x["type"], x["key"]) for x in s["closed"].values()
                       if x["type"] in closed_kinds and x["at"] + law.ttl["observation"] >= at and independent(x)
                       and x["contract"] == law.obligation_contract(x["type"])},
            "relations": relation_facts(s, stmt | {"resource": resource}, atoms),
        }

    @staticmethod
    def eligible(s: dict, law: Law, o: dict, at: int) -> bool:
        """An observation can serve now: not invalidated, fresh, and bound to its instrument's contract if any."""
        if o["id"] in s["invalidated"]:
            return False
        spec = law.instruments.get(o["property"])
        if spec is None:
            return o["at"] <= at <= o["at"] + law.ttl["observation"]
        return (o.get("instrument") == spec["contract"] and o.get("method") == spec["method"]
                and o.get("coverage") == spec["coverage"] and o["author"] in spec["sources"]
                and o["at"] <= at <= o["at"] + spec["fresh_ms"])

    @staticmethod
    def _certify(c: _Ctx, chain: list, level: str) -> None:
        if level not in c.law.rank:
            no("NIV.UNKNOWN", f"{level} is not a level of this law")
        if "certify:" + level not in chain[0]["actions"]:
            no("NIV.CERTIFY", f"this capability cannot certify {level}")

    @staticmethod
    def _unfrozen(c: _Ctx, resource: str) -> None:
        if covers(list(c.s["frozen"]), resource):
            no("CAP.FROZEN", f"{resource} is frozen")

    @staticmethod
    def _independent(label, it: dict) -> None:
        if set(label) & set(it["label"]):
            no("PROV.NOT_INDEPENDENT", "the attestation shares a holder with the actor's chain")

    @staticmethod
    def _spend(c: _Ctx, chain: list, d: list) -> None:
        for g in chain:
            budget = g["budget"]
            if budget and sum(1 for t in c.s["uses"].get(g["id"], ()) if t > c.at - budget["window"]) >= budget["count"]:
                no("OBL.BUDGET", f"the budget of {g['id']} is spent")
        d.extend(("push", "uses", g["id"], c.at) for g in chain)

    # ---- OBL: the effect line (§8) --------------------------------------------------------------------------------
    @staticmethod
    def _open(c: _Ctx, d: list, name: str, stage: str, intent: str, owner: str) -> None:
        d.append(("put", "obligations", name, {"stage": stage, "intent": intent, "opened": c.at,
                                                "due": c.at + c.law.ttl[stage], "owner": owner}))

    @staticmethod
    def _line(c: _Ctx, d: list, kind: str, result, intent: str) -> None:
        leave, enter = LINE[(kind, result)]
        current = line_state(c.s["line"], intent, c.at)
        if current not in leave:
            no("OBL.LINE", f"{kind} ({result}) cannot follow {current}")
        d.append(("put", "line", intent, {"state": enter, "at": c.at}))

    @staticmethod
    def _consume(c: _Ctx, d: list, name: str) -> None:
        ob = c.s["obligations"].get(name)
        if ob is None:
            no("OBL.NOT_OPEN", f"{name} is not open")
        if lapsed(ob, c.at):
            no("OBL.LAPSED", f"{name} lapsed at {ob['due']}")
        d.append(("drop", "obligations", name))

    def _intent(self, c: _Ctx, d: list) -> None:
        b = c.body
        op = c.law.ops.get(b["op"])
        if op is None:
            no("TYPE.OP", f"{b['op']} is not an op of this law")
        try:
            build(op["args"], b["args"], common=False)
        except ShapeError as exc:
            no("TYPE.ARGS", str(exc))
        resource = c.law.resource_of(b["op"], b["args"])
        if not RESOURCE.fullmatch(resource):
            no("TYPE.ARGS", "the arguments do not yield an exact resource")
        stmt = {**b, "resource": resource}
        _, label = self._authorize(c, b["author"], b["under"], "effect:" + b["op"], resource, stmt)
        self._unfrozen(c, resource)
        prior = b.get("retry_of")
        if prior is not None:
            p = c.s["intents"].get(prior)
            if not p or (p["op"], p["resource"]) != (b["op"], resource):
                no("OBL.RETRY", "a retry names an earlier intent of the same effect")
            if self._unresolved(c.s, prior, c.at):
                no("OBL.BLOCKED", "the earlier intent is unresolved: reconcile it first")
        d.append(("put", "intents", b["id"], {
            "id": b["id"], "op": b["op"], "resource": resource, "args": b["args"], "author": b["author"],
            "under": b["under"], "label": label, "stmt": stmt, "contract": digest(op)}))
        self._line(c, d, "intent", None, b["id"])
        self._open(c, d, f"pending:{b['id']}", "pending", b["id"], b["author"])

    @staticmethod
    def _unresolved(s: dict, intent_id: str, at: int) -> bool:
        names = [f"pending:{intent_id}", f"reconcile:{intent_id}"]
        if intent_id in s["token_of"]:
            names.append(f"unredeemed:{s['token_of'][intent_id]}")
        return any(n in s["obligations"] and not lapsed(s["obligations"][n], at) for n in names)

    def _reauthorize(self, c: _Ctx, it: dict) -> list:
        if it["contract"] != digest(c.law.ops.get(it["op"])):
            no("CAP.STALE", "the operation contract changed: a new intent is required")
        chain, _ = self._authorize(c, it["author"], it["under"], "effect:" + it["op"], it["resource"], it["stmt"])
        self._unfrozen(c, it["resource"])
        return chain

    def _profile(self, c: _Ctx, it: dict, approvers, root_digest: str) -> None:
        approved = set(approvers) & humans(c.s["root"]) if root_digest == c.s["root_digest"] else set()
        if c.law.ops[it["op"]]["profile"] == "human_quorum" and len(approved) < c.s["root"]["threshold"]:
            no("CAP.PROFILE", "this operation needs a human quorum of the current root")
        if (self._prudent(c) or it["id"] in c.s["flags"]) and not approved:
            no("CAP.PRUDENT", "a human of the current root must co-sign this effect")

    @staticmethod
    def _prudent(c: _Ctx) -> bool:
        if not c.law.heartbeat_ms:
            return False
        sentinels = [i for i, x in c.s["root"]["identities"].items() if x["kind"] == "sentinel"]
        return any(c.at - c.s["heartbeats"].get(i, -10 ** 15) > c.law.heartbeat_ms for i in sentinels)

    def _token(self, c: _Ctx, d: list) -> None:
        b = c.body
        if kind_of(c.s["root"], b["author"]) != "guard":
            no("CAP.GUARD", "only a guard issues a token")
        it = c.s["intents"].get(b["intent"])
        if it is None:
            no("OBL.NOT_OPEN", "no such intent")
        self._consume(c, d, f"pending:{b['intent']}")
        self._line(c, d, "token", None, b["intent"])
        chain = self._reauthorize(c, it)
        if b["args_digest"] != digest(it["args"]):
            no("OBL.MISMATCH", "the token binds other arguments than the intent")
        self._profile(c, it, c.signers, c.s["root_digest"])
        self._spend(c, chain, d)
        d += [("put", "tokens", b["id"], {"intent": b["intent"], "guard": b["author"],
                                         "humans": sorted(c.signers & humans(c.s["root"])),
                                         "root_digest": c.s["root_digest"]}),
              ("put", "token_of", b["intent"], b["id"])]
        self._open(c, d, f"unredeemed:{b['id']}", "unredeemed", b["intent"], b["author"])

    def _reservation(self, c: _Ctx, d: list) -> None:
        b = c.body
        tok = c.s["tokens"].get(b["token"])
        if tok is None or tok["guard"] != b["author"] or kind_of(c.s["root"], b["author"]) != "guard":
            no("CAP.GUARD", "only the issuing guard reserves its token")
        it = c.s["intents"][tok["intent"]]
        self._consume(c, d, f"unredeemed:{b['token']}")
        self._line(c, d, "reservation", None, tok["intent"])
        self._reauthorize(c, it)
        self._profile(c, it, tok["humans"], tok["root_digest"])
        d.append(("put", "reserved", b["token"], b["id"]))
        self._open(c, d, f"reconcile:{tok['intent']}", "reconcile", tok["intent"], b["author"])

    def judge_dispatch(self, s: dict, token_id: str, guard: str, now: int) -> dict:
        """The pure check at the physical gate, under the journal lock, just before the first byte leaves (§8.2).
        `now` is the executor's trusted time (T03); no ledger transition happens here."""
        law = self.law_of(s)
        tok = s["tokens"].get(token_id)
        if (tok is None or tok["guard"] != guard or kind_of(s["root"], guard) != "guard"
                or token_id not in s["reserved"] or token_id in s["executed"]):
            no("OBL.RESERVATION", "the issuing guard needs one unreported reservation")
        if now < s["last_at"] or now > s["anchor_at"] + MAX_AHEAD_MS:
            no("HIST.AHEAD", "a departure needs current witnessed time")
        if line_state(s["line"], tok["intent"], now) != "reserved":
            no("OBL.LINE", "only a reservation inside its dispatch window may leave")
        it = s["intents"][tok["intent"]]
        c = _Ctx(s, law, "dispatch", {"at": now, "author": guard, "id": token_id}, set(), s["root"])
        self._reauthorize(c, it)
        self._profile(c, it, tok["humans"], tok["root_digest"])
        return copy.deepcopy(it)

    def _execution(self, c: _Ctx, d: list) -> None:
        b = c.body
        tok = c.s["tokens"].get(b["token"])
        if tok is None or tok["guard"] != b["author"]:
            no("CAP.GUARD", "the guard that issued the token reports its execution")
        if b["token"] not in c.s["reserved"] or b["token"] in c.s["executed"]:
            no("OBL.RESERVATION", "exactly one unreported reservation precedes the result")
        if b["result"] not in ("ok", "failed", "unknown"):
            no("TYPE.SHAPE", "result is ok, failed or unknown")
        intent = tok["intent"]
        d.append(("put", "executed", b["token"], b["result"]))
        self._line(c, d, "execution", b["result"], intent)
        if b["result"] in ("ok", "failed"):
            self._consume(c, d, f"reconcile:{intent}")
        if b["result"] == "ok":
            self._open(c, d, f"proof:{intent}", "proof", intent, b["author"])

    # ---- attest -----------------------------------------------------------------------------------------------------
    def _reconciliation(self, c: _Ctx, d: list) -> None:
        b = c.body
        it = c.s["intents"].get(b["intent"])
        if it is None:
            no("OBL.NOT_OPEN", "no such intent")
        _, label = self._authorize(c, b["author"], b["under"], "reconcile", it["resource"], b)
        self._independent(label, it)
        if b["result"] not in ("applied", "not_applied"):
            no("TYPE.SHAPE", "result is applied or not_applied")
        self._line(c, d, "reconciliation", b["result"], b["intent"])
        self._consume(c, d, f"reconcile:{b['intent']}")
        if b["result"] == "applied":
            self._open(c, d, f"proof:{b['intent']}", "proof", b["intent"], b["author"])

    def _observation(self, c: _Ctx, d: list) -> None:
        b = c.body
        if b["property"] in c.law.instruments:
            no("PROV.INSTRUMENT", "this property requires a qualified measurement")
        chain, label = self._authorize(c, b["author"], b["under"], "observe", b["resource"], b)
        self._certify(c, chain, b["level"])
        d.append(("put", "observations", f"{b['resource']}|{b['property']}|{b['author']}", {
            "id": b["id"], "resource": b["resource"], "property": b["property"], "status": b["status"],
            "level": b["level"], "at": c.at, "author": b["author"], "label": label}))

    def _measurement(self, c: _Ctx, d: list) -> None:
        b = c.body
        spec = c.law.instruments.get(b["property"])
        if spec is None:
            no("PROV.INSTRUMENT", "a measurement needs a pinned instrument contract")
        if b["author"] not in spec["sources"] or b["method"] != spec["method"] or b["coverage"] != spec["coverage"]:
            no("PROV.COVERAGE", "source, method and coverage must match the instrument contract")
        if b["measured_at"] > c.at or b["measured_at"] + spec["fresh_ms"] < c.at:
            no("PROV.STALE", "a measurement is fresh and not from the future")
        chain, label = self._authorize(c, b["author"], b["under"], "observe", b["resource"], b)
        self._certify(c, chain, b["level"])
        if c.law.rank[b["level"]] < c.law.rank[spec["min_level"]]:
            no("NIV.TOO_LOW", "the instrument's minimum level is not met")
        d.append(("put", "observations", f"{b['resource']}|{b['property']}|{b['author']}", {
            "id": b["id"], "resource": b["resource"], "property": b["property"], "status": b["status"],
            "level": b["level"], "at": b["measured_at"], "author": b["author"], "label": label,
            "method": b["method"], "coverage": b["coverage"], "instrument": spec["contract"], "artifact": b["artifact"]}))

    def _evidence(self, c: _Ctx, d: list) -> None:
        """A law-declared evidence kind; it may discharge the proof obligation of an effect on the same resource."""
        b = c.body
        chain, label = self._authorize(c, b["author"], b["under"], c.kind, b["resource"], b)
        if "level" in b:
            self._certify(c, chain, b["level"])
        for rule in c.law.discharges.get(c.kind, []):
            target = b[rule["key"]]
            it = c.s["intents"].get(target)
            if it is None or it["resource"] != b["resource"]:
                no("PROV.SUBJECT", "the proof names an intent on this exact resource")
            if c.law.rank[b["level"]] < c.law.rank[rule["min_level"]]:
                no("NIV.TOO_LOW", f"proof:{target} needs {rule['min_level']}")
            self._independent(label, it)
            self._consume(c, d, f"proof:{target}")

    # ---- typed resources --------------------------------------------------------------------------------------------
    def _resource(self, c: _Ctx, d: list) -> None:
        b = c.body
        spec = c.law.resources.get(b["type"])
        if spec is None:
            no("TYPE.RESOURCE", "the resource type is not declared by the pinned law")
        if b["resource"] in c.s["entities"]:
            no("TYPE.EXISTS", "a stable resource identity is registered once")
        if len(c.s["entities"]) >= MAX_ENTITIES:
            no("TYPE.BOUND", "resource count limit")
        chain, _ = self._authorize(c, b["author"], b["under"], "register:" + b["type"], b["resource"], b)
        self._unfrozen(c, b["resource"])
        try:
            build(spec["fields"], b["fields"], common=False)
        except ShapeError as exc:
            no("TYPE.FIELDS", str(exc))
        self._spend(c, chain, d)
        d.append(("put", "entities", b["resource"], {
            "type": b["type"], "owner": b["author"], "state": spec["initial"], "fields": copy.deepcopy(b["fields"]),
            "contract": spec["contract"], "version": 1, "created": c.at}))

    def _transition(self, c: _Ctx, d: list) -> None:
        b = c.body
        entity = c.s["entities"].get(b["resource"])
        if entity is None or digest(detach(entity)) != b["expected"]:
            no("TYPE.CONFLICT", "a transition binds the exact existing resource")
        spec = c.law.resources.get(entity["type"])
        if spec is None or spec["contract"] != entity["contract"]:
            no("CAP.STALE", "the resource belongs to another type contract")
        rule = spec["transitions"].get(b["operation"])
        if rule is None or entity["state"] not in rule["from"]:
            no("TYPE.TRANSITION", "no declared transition from this state")
        chain, label = self._authorize(c, b["author"], b["under"], f"transition:{entity['type']}:{b['operation']}",
                                       b["resource"], b)
        self._unfrozen(c, b["resource"])
        if set(b["changes"]) != set(rule["writes"]):
            no("TYPE.WRITES", "changes are exactly the declared writes")
        fields = {**entity["fields"], **b["changes"]}
        try:
            build(spec["fields"], fields, common=False)
        except ShapeError as exc:
            no("TYPE.FIELDS", str(exc))
        if not self._evaluate(rule["requires"], self._facts(c, b["resource"], b, set(label), rule["requires"])):
            no("CAP.CONDITION", "the transition's constraints do not hold")
        self._spend(c, chain, d)
        d.append(("put", "entities", b["resource"], {**entity, "fields": fields, "state": rule["to"],
                                                     "version": entity["version"] + 1}))

    # ---- law-declared obligations at the refuse level ---------------------------------------------------------------
    def _law_obligations(self, c: _Ctx, d: list) -> None:
        record = {"kind": c.kind, "author": c.body["author"], "at": c.at, "body": c.body}
        label = set(self._label(c))
        opens, closes, failures = obl.step(
            c.law.obligations, ("refuse",), c.s["obligations"], record,
            lambda decl: self._holds(c, decl, label),
            lambda inst: "label" in inst and not set(inst["label"]) & label)
        if failures:
            no(failures[0][1], failures[0][2])
        for name, how in closes:
            d.append(("drop", "obligations", name))
            if how == "closed":
                ob = c.s["obligations"][name]
                d.append(("put", "closed", name, {"type": ob["stage"], "key": ob["key"], "at": c.at,
                                                 "label": sorted(label), "contract": ob["contract"]}))
        d.extend(("put", "obligations", name, {**inst, "label": sorted(label)}) for name, inst in opens)

    def _label(self, c: _Ctx) -> list:
        under = c.body.get("under")
        holders = set()
        if under and under != "root":
            cur, seen = under, set()
            while cur != "root" and cur in c.s["grants"] and cur not in seen and len(seen) < MAX_CHAIN:
                seen.add(cur)
                holders.add(c.s["grants"][cur]["holder"])
                cur = c.s["grants"][cur]["parent"]
        return sorted({c.body["author"]} | holders)

    def _holds(self, c: _Ctx, decl: dict, label: set) -> bool:
        if decl["when"] is None:
            return True
        b = c.body
        resource = c.law.resource_of(b["op"], b["args"]) if c.kind == "intent" else b.get("resource")
        return self._evaluate(decl["when"], self._facts(c, resource, b, label, decl["when"]))


def relation_facts(s: dict, request: dict, atoms) -> set:
    """Exact bound queries on the closed relations; a relation nobody names is never computed."""
    rows = set()
    for op, args in atoms:
        if op != "related":
            continue
        name, left, right = args
        bind = lambda x: request.get(x[1:]) if x.startswith("$") else x
        left, right = bind(left), bind(right)
        if not isinstance(left, str) or not isinstance(right, str):
            continue
        if relation_holds(s, name, left, right):
            rows.add((name, left, right))
    return rows


def relation_holds(s: dict, name: str, left: str, right: str) -> bool:
    if name == "role":
        return s["root"]["identities"].get(left, {}).get("kind") == right
    if name == "holds":
        return right not in s["revoked"] and s["grants"].get(right, {}).get("holder") == left
    if name == "parent":
        return left not in s["revoked"] and s["grants"].get(left, {}).get("parent") == right
    entity = s["entities"].get(right if name == "owns" else left)
    if entity is None:
        return False
    return {"owns": entity["owner"] == left, "type": entity["type"] == right,
            "state": entity["state"] == right}.get(name, False)
