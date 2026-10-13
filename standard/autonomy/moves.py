"""The moves of the game, as both players see them: one reading for the agent's loop and the human's queue.

A move is an op of the rules on one exact transition (base/head, from/to). It exists once the scanner has measured
something on that resource (a candidate commit, a contribution, a production switch). Its status says who plays next:

    ready      an autonomous route of the rules holds: the agent plays it
    decided    the human said yes and the human route holds: the agent plays it
    yours      only the human route can hold; everything it needs but the human's decision is there
    measuring  some fact a route needs is not measured yet (or no longer fresh)
    refuted    a measured fact rules every route out (red tests, a regression, a change outside its scope)
    frozen     the human said no: the resource is frozen
    playing    an intent is on its way; `done` once proven, `failed` if it did not apply

`wanted` says whether the move is worth playing now: a socle route would hold if the rules had not turned it off,
or the move has no autonomous route at all. The human's queue is the moves that are `yours` and `wanted`.

This is a reading, never a permission: freshness and independence are approximated from the view, and the kernel
judges again, with both judges, at every stage of the effect line.
"""
from __future__ import annotations

import re
from fractions import Fraction

DECISION = ["decision", "approve", "real", "human"]
SLOT = re.compile(r"\{([A-Za-z][A-Za-z0-9_]{0,63})\}")
NUMBER = re.compile(r"-?[0-9]{1,12}(\.[0-9]{1,6})?")
ORDER = {"rollback": 0, "abort": 1, "restart": 2, "deploy": 3, "canary": 4}   # stepping back first
# Moves worth playing as soon as they exist: a candidate or a contribution main could take, a release to ship. The
# others (rollback, restart, abort) are worth playing only when a route of the socle holds: a breach was measured.
WANTED = ("remediate", "implement", "integrate", "deploy", "canary", "inventory-refresh")


def _number(value):
    if type(value) is int:
        return Fraction(value)
    return Fraction(value) if isinstance(value, str) and NUMBER.fullmatch(value) else None


def op_of(ops: dict, resource: str):
    """(op, args) whose resource template yields exactly this resource, or None."""
    for name, op in sorted(ops.items()):
        template = op.get("resource", "")
        pattern = "".join(f"(?P<{m}>[A-Za-z0-9][A-Za-z0-9._@-]{{0,127}})" if m else re.escape(t)
                          for t, m in _parts(template))
        found = re.fullmatch(pattern, resource)
        if found:
            return name, dict(found.groupdict())
    return None


def _parts(template: str):
    at = 0
    for m in SLOT.finditer(template):
        yield template[at:m.start()], None
        yield "", m[1]
        at = m.end()
    yield template[at:], None


class Facts:
    """The view's facts on one resource, fresh and not stated by the actor."""

    def __init__(self, view: dict, now: int | None, actor: str = "agent"):
        law = view["law"]["effective"]
        self.kinds, self.settings, self.now = view.get("identities", {}), law.get("settings", {}), now
        self.fresh = {p: spec["fresh_ms"] for p, spec in law.get("instruments", {}).items()}
        self.ttl = law.get("ttl", {}).get("observation", 86_400_000)
        self.by = {}
        for f in view.get("facts", []):
            if f["author"] != actor:
                self.by.setdefault(f["resource"], []).append(f)

    def _live(self, f) -> bool:
        return self.now is None or f["at"] + self.fresh.get(f["property"], self.ttl) >= self.now

    def atom(self, resource: str, request: dict, op: str, args: list) -> str:
        """`holds`, `absent` (not measured, or no longer fresh) or `other` (measured otherwise)."""
        if op in ("eq", "prefix"):
            value = request.get(args[0]) if "." not in args[0] else None
            ok = value == args[1] if op == "eq" else isinstance(value, str) and value.startswith(args[1])
            return "holds" if ok else "other"
        if op not in ("observed", "compare"):
            return "absent"                                 # obligations and relations: only the kernel knows
        seen = [f for f in self.by.get(resource, []) if f["property"] == args[0] and self._live(f)]
        if op == "observed" and len(args) == 4:
            seen = [f for f in seen if self.kinds.get(f["author"]) == args[3]]
        if not seen:
            return "absent"
        if op == "observed":
            return "holds" if any(f["status"] == args[1] for f in seen) else "other"
        bound = args[2]
        bound = _number(self.settings.get(bound[1:]) if isinstance(bound, str) and bound[:1] == "@" else bound)
        values = [_number(f["status"]) for f in seen]
        ok = any(v is not None and bound is not None and (v <= bound if args[1] == "le" else v >= bound) for v in values)
        return "holds" if ok else "other"

    def route(self, resource: str, request: dict, program: dict) -> dict:
        atoms = [next(iter(a.items())) for a in program.get("all", [])]
        states = [(op, args, self.atom(resource, request, op, args)) for op, args in atoms]
        return {"holds": all(s == "holds" for _, _, s in states),
                "missing": [_say(op, args) for op, args, s in states if s == "absent"],
                "refuted": [_say(op, args) for op, args, s in states if s == "other"]}


def _say(op, args) -> str:
    if op == "observed":
        return ("a human's decision" if list(args) == DECISION else f"{args[0]} = {args[1]}")
    if op == "compare":
        return f"{args[0]} {'≤' if args[1] == 'le' else '≥'} {args[2]}"
    return f"{op} {' '.join(map(str, args))}"


def frozen(scopes, resource: str) -> bool:
    return any(s == resource or (s.endswith("*") and resource.startswith(s[:-1])) for s in scopes)


def _socle() -> dict:
    from standard.floors import FLOORS
    return FLOORS["ops"]


def judge(view: dict, op: str, resource: str, args: dict, *, now=None, socle=None) -> dict:
    """The status of one move. socle: the release's ops, to tell what the rules turned off from what never held."""
    law = view["law"]["effective"]
    socle = _socle() if socle is None else socle
    routes = law["ops"][op]["routes"]
    facts = Facts(view, now if now is not None else view.get("now"))
    request = {**args, "resource": resource, "op": op}
    seen = {name: facts.route(resource, request, program) for name, program in routes.items()}
    off = {name: facts.route(resource, request, program) for name, program in (socle or {}).get(op, {}).get(
        "routes", {}).items() if name not in routes}
    human = seen["human"]
    premises = {**human, "missing": [m for m in human["missing"] if m != "a human's decision"]}
    auto = sorted(name for name, r in seen.items() if name != "human" and r["holds"])
    played = [p for p in view.get("played", {}).values() if p["op"] == op and p["resource"] == resource]
    state = max(played, key=lambda p: p["at"] or 0)["state"] if played else None
    if state in ("intended", "tokened", "reserved", "uncertain", "proving"):
        status = "playing" if state != "proving" else "done"
    elif frozen(view.get("frozen", []), resource):
        status = "frozen"
    elif auto:
        status = "ready"
    elif human["holds"]:
        status = "decided"
    elif premises["refuted"] or all(r["refuted"] for r in seen.values()):
        status = "refuted"
    elif not premises["missing"]:
        status = "yours"
    else:
        status = "measuring"
    wanted = op in WANTED or bool(auto) or any(r["holds"] for r in off.values())
    return {"op": op, "resource": resource, "args": args, "status": status, "route": auto[0] if auto else
            ("human" if human["holds"] else None), "wanted": wanted, "last": state,
            "missing": sorted({m for r in seen.values() for m in r["missing"]}),
            "refuted": sorted({m for r in seen.values() for m in r["refuted"]}),
            "turned_off": sorted(name for name, r in off.items() if r["holds"])}


def moves(view: dict, *, main: str | None = None, now=None, socle=None) -> list:
    """Every move the facts make possible on the current main, with its status; production first."""
    law = view["law"]["effective"]
    resources = {f["resource"] for f in view.get("facts", [])} | set(view.get("transitions", {}))
    out = []
    for resource in sorted(r for r in resources if "/" in r):   # a move is an exact transition, never a target
        found = op_of(law["ops"], resource)
        if found is None:
            continue
        op, args = found
        if main and "base" in args and args["base"] != main:
            continue                                        # a transition from an older main can never land
        out.append(judge(view, op, resource, args, now=now, socle=socle))
    return sorted(out, key=lambda m: (ORDER.get(m["op"], 9), m["resource"]))


def queue(view: dict, **kw) -> list:
    """What waits for the human: moves only their decision can play, and worth playing."""
    return [m for m in moves(view, **kw) if m["status"] == "yours" and m["wanted"]]
