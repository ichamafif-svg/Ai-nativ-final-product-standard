"""Accountability (F0-11, §9): the debt projection. Deterministic, outside admission, visibility budget.

It folds over the admitted journal after the kernel and never feeds back into it: a fault here can hide or invent a
gap, it can never authorize an effect. Anyone holding the journal recomputes the same verdict.

Guarantee: after genesis, each declared target has exactly one of a qualifying proof or one open obligation whose
`opened` and `due` never move while the gap continues — across retries, renames and law changes, because a debt
belongs to the (resource, property) it measures, not to the name of its target (§9.2). Retiring a target is never a
repair. An obligation past `due` escalates to the root humans. This is visibility, not convergence.
"""
from __future__ import annotations

import copy

from . import language, obligations as obl
from .canon import digest
from .floor0 import LAPSE
from .judge import Kernel, relation_facts

SOURCE_KINDS = ("oracle", "human", "service")
RETIRED = "REQUIREMENT_RETIRED_WITHOUT_REPAIR_PROOF"


def needs(target: dict, observation, rank: dict, at: int, covered: bool) -> list:
    """What a target lacks now: cover, observe, repair, prove. Empty means proven."""
    out = [] if covered else ["cover"]
    if observation is None:
        return out + ["observe"]
    stale = observation["at"] + target["fresh_ms"] < at
    if observation["status"].startswith("uncovered"):
        return out + ["observe"]                       # the instrument could not see everything: restore coverage
    if observation["status"] != target["expect"]:
        return out + (["observe"] if stale else []) + ["repair"]
    low = rank[observation["level"]] < rank[target["min_level"]]
    return out + (["observe"] if stale else []) + (["prove"] if low else [])


def empty() -> dict:
    return {"evidence": {}, "proofs": {}, "obligations": {}, "escalated": {}, "law": {}, "closed": {}, "measured": {},
            "carried": {}, "retired": {}}


class Accountability:
    def __init__(self, kernel: Kernel):
        self.kernel = kernel

    # ---- fold -------------------------------------------------------------------------------------------------------
    def feed(self, a: dict, ks: dict, record: dict) -> None:
        """Called once per admitted entry, with the kernel state after that entry."""
        law = self.kernel.law_by_digest(record["law"])
        at, kind = record["at"], record["kind"]
        if kind == "genesis":
            a["obligations"]["clock:witness"] = {"type": "clock", "opened": at, "due": at + law.ttl["proof"],
                                                 "owner": None}
        elif kind == "checkpoint":
            a["obligations"].pop("clock:witness", None)
        elif kind in ("observation", "measurement"):
            self._qualify(a, ks, law, record)
            self._resolve_violation(a, ks, record)
        if law.obligations:
            self._law_step(a, ks, law, record)
        law = self.kernel.law_of(ks)                   # an activation applies its new targets after its own entry
        self._discard_invalid(a, ks, law, at)
        self._sync(a, law, at)
        for name, ob in self._open(a, ks).items():
            if ob.get("escalates", True) and at >= ob["due"]:
                a["escalated"].setdefault(name, at)
        live = self._open(a, ks)
        for name in [n for n in a["escalated"] if n not in live]:
            del a["escalated"][name]                   # closed: the journal still shows the gap

    def _law_step(self, a, ks, law, record) -> None:
        """Obligations below the refuse level: the same engine and declarations as the kernel."""
        opens, closes, failures = obl.step(law.obligations, ("escalate", "measure"), a["law"], record,
                                           lambda decl: self._holds(a, ks, law, decl, record))
        at, ident = record["at"], record["body"]["id"]
        for name, how in closes:
            ob = a["law"].pop(name)
            if how == "closed":
                a["closed"][name] = {"type": ob["stage"], "key": ob["key"], "at": at, "contract": ob["contract"]}
                self._count(a, ob["stage"], "closed")
        for name, inst in opens:
            a["law"][name] = inst
            self._count(a, inst["stage"], "opened")
        for decl, code, detail in failures:
            if decl["level"] == "escalate":            # a violation is an obligation already due
                a["obligations"][f"violation:{decl['id']}:{ident}"] = {
                    "type": "violation", "declaration": decl["id"], "code": code, "detail": detail,
                    "owner": record["author"], "opened": at, "due": at}
            self._count(a, decl["id"], "violations")

    @staticmethod
    def _resolve_violation(a, ks, record) -> None:
        """A violation is an obligation already due; a human of the root closes it by deciding it was handled
        (`decision = approve` on law:violation/<declaration>/<entry>). The count of violations stays: closing is not
        forgetting, and no machine identity can close one."""
        b = record["body"]
        if (record["kind"] != "observation" or b["property"] != "decision" or b["status"] != "approve"
                or not b["resource"].startswith("law:violation/")
                or ks["root"]["identities"].get(b["author"], {}).get("kind") != "human"):
            return
        parts = b["resource"][len("law:violation/"):].split("/", 1)
        if len(parts) == 2:
            a["obligations"].pop(f"violation:{parts[0]}:{parts[1]}", None)

    @staticmethod
    def _count(a, decl_id, what) -> None:
        a["measured"].setdefault(decl_id, {"opened": 0, "closed": 0, "violations": 0})[what] += 1

    def _holds(self, a, ks, law, decl, record) -> bool:
        if decl["when"] is None:
            return True
        body, at = record["body"], record["at"]
        law_open = [*a["law"].values(), *(ob for ob in ks["obligations"].values() if ob.get("type") == "law")]
        eligible = [o for o in ks["observations"].values() if Kernel.eligible(ks, law, o, at)]
        kind = lambda ident: ks["root"]["identities"].get(ident, {}).get("kind")
        facts = {"request": body,
                 "observations": {(o["resource"], o["property"], o["status"], o["level"]) for o in eligible},
                 "authored": {(o["resource"], o["property"], o["status"], o["level"], kind(o["author"]))
                              for o in eligible if kind(o["author"])},
                 "opened": {(ob["stage"], ob["key"]) for ob in law_open if obl.live(ob, at)},
                 "closed": {(x["type"], x["key"]) for x in [*a["closed"].values(), *ks["closed"].values()]
                            if x["contract"] == law.obligation_contract(x["type"])},
                 "relations": relation_facts(ks, body, decl["when"])}
        try:
            return language.evaluate(decl["when"], **facts)
        except language.LanguageError as exc:
            raise ValueError("accountability exceeded its work bound") from exc

    @staticmethod
    def _owner_label(ks, owner) -> set:
        label = {owner}
        for gid, g in ks["grants"].items():
            if g["holder"] == owner:
                cur = gid
                while cur != "root" and cur in ks["grants"]:
                    label.add(ks["grants"][cur]["holder"])
                    cur = ks["grants"][cur]["parent"]
        return label

    def _qualify(self, a, ks, law, record) -> None:
        """An observation is evidence for a target only from a named source, independent of the target's owner."""
        b = record["body"]
        tid = law.by_key.get((b["resource"], b["property"]))
        if tid is None:
            return
        target = law.targets[tid]
        decl = ks["root"]["identities"].get(b["author"])
        o = ks["observations"][f"{b['resource']}|{b['property']}|{b['author']}"]
        if (b["author"] in target["sources"] and decl and decl["kind"] in SOURCE_KINDS
                and not set(o["label"]) & self._owner_label(ks, target["owner"])):
            a["evidence"][tid] = {**o, "target_contract": digest(target)}

    @staticmethod
    def _discard_invalid(a, ks, law, at) -> None:
        """Drop invalidated or contract-incompatible evidence; stale evidence stays, to date its expiry exactly."""
        for tid, o in list(a["evidence"].items()):
            spec = law.instruments.get(o["property"])
            if o["id"] in ks["invalidated"] or (spec and o.get("instrument") != spec["contract"]):
                a["evidence"].pop(tid)

    def _sync(self, a, law, at) -> None:
        """Open, keep or discharge exactly one obligation per target. Repetition never moves `opened` or `due`."""
        for tid in [t for t in a["evidence"] if t not in law.targets]:
            a["evidence"].pop(tid)
        for tid in [t for t in a["proofs"] if t not in law.targets]:
            a["proofs"].pop(tid)
        for name in [n for n in a["obligations"] if n.startswith("target:") and n[7:] not in law.targets]:
            self._carry(a, a["obligations"].pop(name), at)
        for tid, target in law.targets.items():
            name, subject = "target:" + tid, f"{target['resource']}|{target['property']}"
            prior = a["obligations"].get(name)
            if prior is not None and prior["subject"] != subject:
                self._carry(a, a["obligations"].pop(name), at)
            o = a["evidence"].get(tid)
            if o is not None and o["target_contract"] != digest(target):
                a["evidence"].pop(tid)                 # a redefined target needs a new observation (§4.6)
                o = None
            covered = target["kind"] == "coverage" or target["coverage"] in a["proofs"]
            spec = law.instruments.get(target["property"])
            assessed = {**target, "fresh_ms": min(target["fresh_ms"], spec["fresh_ms"])} if spec else target
            missing = needs(assessed, o, law.rank, at, covered)
            if not missing:
                a["obligations"].pop(name, None)
                a["carried"].pop(subject, None)
                a["retired"].pop(subject, None)
                a["proofs"][tid] = o["id"]
                continue
            a["proofs"].pop(tid, None)
            ob = a["obligations"].get(name)
            if ob is None:
                # A gap that began when a good proof expired opens at the expiry, not at its late detection.
                expired = o is not None and o["status"] == target["expect"] and o["at"] + assessed["fresh_ms"] < at
                opened = o["at"] + assessed["fresh_ms"] + 1 if expired else at
                parent = a["obligations"].get("target:" + target.get("coverage", ""))
                if "cover" in missing and parent:
                    opened = min(opened, parent["opened"])
                due = opened + target["due_ms"]
                carried = a["carried"].pop(subject, None)
                if carried:
                    opened, due = min(opened, carried["opened"]), min(due, carried["due"])
                a["retired"].pop(subject, None)
                ob = a["obligations"][name] = {"type": "target", "target": tid, "subject": subject,
                                               "owner": target["owner"], "opened": opened, "due": due}
            ob.update(owner=target["owner"], due=min(ob["due"], ob["opened"] + target["due_ms"]), needs=missing)

    @staticmethod
    def _carry(a, ob, at) -> None:
        """A retired or renamed target keeps its debt by subject; retirement is not a repair."""
        subject, prior = ob["subject"], a["carried"].get(ob["subject"])
        kept = {"opened": min(ob["opened"], prior["opened"]) if prior else ob["opened"],
                "due": min(ob["due"], prior["due"]) if prior else ob["due"]}
        a["carried"][subject] = kept
        a["retired"][subject] = {"subject": subject, **kept, "retired_at": at, "status": RETIRED}

    @staticmethod
    def _open(a, ks) -> dict:
        out = {name: dict(ob) for name, ob in a["obligations"].items()}
        for name, ob in [*ks["obligations"].items(), *((n, o) for n, o in a["law"].items() if o["level"] == "escalate")]:
            if ob.get("type") == "law":
                out[name] = dict(ob) if ob["on_due"] == "escalate" else {**ob, "escalates": False}
            elif ob["stage"] in LAPSE:
                out[name] = {"type": "protocol", **ob, "escalates": False}     # it lapses instead of escalating
            else:
                out[name] = {"type": "protocol", **ob}
        return out

    # ---- verdict ----------------------------------------------------------------------------------------------------
    def health(self, a: dict, ks: dict, *, required_at: int | None = None) -> dict:
        """PROVEN, IN_PROGRESS or ESCALATED as of signed ledger time. A trusted `required_at` beyond it is a visible
        clock gap, and every obligation already due by then escalates: a silent witness cannot hold the verdict."""
        if not ks["size"]:
            raise ValueError("an initialized ledger is required")
        if required_at is not None and (type(required_at) is not int or required_at < 0):
            raise ValueError("required_at is a nonnegative trusted millisecond timestamp")
        law = self.kernel.law_of(ks)
        at = ks["last_at"]
        horizon = max(at, required_at or 0)
        a = copy.deepcopy(a)
        self._discard_invalid(a, ks, law, horizon)
        self._sync(a, law, horizon)
        humans = sorted(i for i, d in ks["root"]["identities"].items() if d["kind"] == "human")
        open_, escalated = [], []
        for name, ob in sorted(self._open(a, ks).items()):
            if ob.get("type") == "law" and ob.get("on_due") == "lapse" and horizon > ob["due"]:
                continue
            if ob.get("type") == "protocol" and ob["stage"] in LAPSE and horizon > ob["due"]:
                continue
            item = {"obligation": name, **ob}
            if name in a["escalated"]:
                item["escalated_at"] = a["escalated"][name]
            if item.pop("escalates", True) and horizon >= ob["due"]:
                escalated.append({**item, "escalated_to": humans})
            else:
                open_.append(item)
        if required_at is not None and required_at > at:
            gap = {"obligation": "clock:after-ledger", "type": "clock_gap", "owner": humans[0], "opened": at + 1,
                   "due": at + law.ttl["proof"], "requested_at": required_at, "ledger_at": at}
            (escalated if horizon >= gap["due"] else open_).append(
                {**gap, "escalated_to": humans} if horizon >= gap["due"] else gap)
        proven = [{"target": t, "evidence": a["proofs"][t]} for t in law.targets if t in a["proofs"]]
        state = "ESCALATED" if escalated else ("PROVEN" if not open_ and len(proven) == len(law.targets) else "IN_PROGRESS")
        measured = {d: {**a["measured"].get(d, {"opened": 0, "closed": 0, "violations": 0}),
                        "open": sum(1 for ob in a["law"].values() if ob["stage"] == d and obl.live(ob, horizon))}
                    for d, decl in law.obligations.items() if decl["level"] == "measure"}
        return {"as_of": at, "evaluated_at": horizon, "witness_at": ks["anchor_at"] if ks["witnessed"] else None,
                "state": state, "proven": proven, "open": open_, "escalated": escalated, "measured": measured,
                "retired": [a["retired"][x] for x in sorted(a["retired"])]}
