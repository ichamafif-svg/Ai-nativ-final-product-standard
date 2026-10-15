"""The feedback matrix (D70, ARCHITECTURE.md §4.12): one way back to the agent, keyed by catalog rule.

Every source (the bac's wall, tests, lint and typing, SAST, the block scanner, probes, later the gateway, the egress
proxy, RLS and the secret broker) speaks of the same 156 rules. `matrix` says, rule by rule, which sources cover it
at which moment and how strong its strongest active source is; `route` is the one filter every feedback item goes
through before anyone reads it. Nothing here is authority: a fact is still judged by the kernel.
"""
from __future__ import annotations

import json

from enclosure.refusals import WALLS

MOMENTS = ("before", "build", "admission", "run")
# Strength of a rule's strongest active source; a planned wall does not count.
STRENGTH = {"measured": 4, "wall": 3, "static": 2, "review": 1, "none": 0}
STATIC = ("blocks", "bandit", "semgrep", "mypy")
MEASURED = ("probe", "test", "fact")
# The parts of the platform whose walls already teach in the precheck's bac, read from the refusal reader itself.
# They teach; they do not yet hold the rule where the product runs (an empty network holds every egress rule
# vacuously in a test). Only a part enforced in production gives a rule the "wall" strength.
WALLED = frozenset(holder for holder, _, _ in WALLS.values())
RUNNING: frozenset = frozenset()      # parts of the platform enforced where the product runs (D68 step 2 onwards)

KINDS = {"lesson": "agent", "fact": "kernel", "alarm": "hidden control", "need": "human"}
TRUST = ("fact", "diagnostic")
FIELDS = ("kind", "source", "moment", "rules", "where", "attempt", "available", "instead", "ask", "trust", "new")


def _sources(rule: dict) -> dict:
    """{moment: [source, ...]} for one rule."""
    checks = [c.split(":")[0] for c in rule["check"]]
    out = {moment: [] for moment in MOMENTS}
    out["before"].append("contract")
    for kind in ("blocks", "bandit", "semgrep", "mypy"):
        if kind in checks:
            out["build"].append(kind)
            out["admission"].append(kind)
    for kind in MEASURED:
        if kind in checks:
            out["admission"].append(kind)
    holder = rule["held_by"]
    if holder.startswith("platform:"):
        if holder in WALLED:
            out["build"].append("wall")
        out["run"].append("wall" if holder in RUNNING else "wall (planned)")
    for kind in ("patrol", "human"):
        if kind in checks:
            out["admission" if kind == "human" else "build"].append(kind)
    return out


def strength(rule: dict) -> str:
    checks = {c.split(":")[0] for c in rule["check"]}
    if checks & set(MEASURED):
        return "measured"
    if rule["held_by"] in RUNNING:
        return "wall"
    if checks & set(STATIC):
        return "static"
    if checks & {"patrol", "human"}:
        return "review"
    return "none"


def matrix(cat: dict) -> dict:
    """Rule by rule: sources per moment and strongest active source; plus the totals and the gaps."""
    rules = {r["id"]: {"held_by": r["held_by"], "sources": _sources(r), "strength": strength(r)}
             for r in cat["rules"]}
    totals = {name: sum(1 for r in rules.values() if r["strength"] == name) for name in STRENGTH}
    return {"rules": rules, "totals": totals,
            "review_only": sorted(rid for rid, r in rules.items() if r["strength"] in ("review", "none")),
            "planned_walls": sorted(rid for rid, r in rules.items()
                                    if r["held_by"].startswith("platform:") and r["held_by"] not in RUNNING)}


def item(kind: str, source: str, moment: str, *, rules=(), where: str = "", attempt: str = "", trust="diagnostic",
         new: bool = True, **extra) -> dict:
    """The one format of a feedback item."""
    if kind not in KINDS or moment not in MOMENTS or trust not in TRUST:
        raise ValueError(f"feedback: kind {kind}, moment {moment}, trust {trust}")
    return {"kind": kind, "source": source, "moment": moment, "rules": sorted(rules), "where": where,
            "attempt": attempt[:240], "trust": trust, "new": new,
            **{k: v for k, v in extra.items() if k in FIELDS}}


def route(items: list, *, budget: int = 6000) -> dict:
    """The one filter: dedupe, order, bound what is said, route by kind, keep within the agent's budget."""
    seen, kept = set(), []
    for entry in items:
        key = (tuple(entry["rules"]) or (entry["source"],), entry["where"], entry["kind"])
        if key in seen:
            continue
        seen.add(key)
        kept.append({k: v for k, v in entry.items() if k in FIELDS})
    kept.sort(key=lambda e: (e["trust"] != "fact", not e["new"], e["source"], e["rules"], e["where"]))
    out = {audience: [] for audience in KINDS.values()}
    for entry in kept:
        out[KINDS[entry["kind"]]].append(entry)
    agent, size, deferred = [], 0, 0
    for entry in out["agent"]:
        cost = len(json.dumps(entry, ensure_ascii=False))
        if size + cost > budget:
            deferred += 1
            continue
        agent.append(entry)
        size += cost
    out["agent"] = agent
    out["deferred_for_agent"] = deferred
    return out


def render(dossier: dict) -> str:
    """The agent's reading of its dossier: one line per item, in the filter's order."""
    lines = []
    for e in dossier["agent"]:
        line = f"- [{e['source']}{'' if e['new'] else ', already on base'}]"
        if e["rules"]:
            line += f" rules {', '.join(e['rules'])}"
        if e["where"]:
            line += f" at {e['where']}"
        if e["attempt"]:
            line += f": {e['attempt']}"
        if e.get("instead"):
            line += f"\n  instead: {e['instead']}"
        lines.append(line)
    if dossier.get("deferred_for_agent"):
        lines.append(f"- {dossier['deferred_for_agent']} more items, lower in order, after these are addressed")
    return "\n".join(lines)
