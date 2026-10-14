"""Exploratory law patrol context, and the rotation over the rules only a reader can check.

Patrol is advisory. It starts before a deterministic gap exists and packages law, settings, findings, routes and weak
spots so a read-only model or a human can look for blind spots. Without a focus, each round takes the next category of
the rule catalog in a fixed order and carries the rules of that category the AI checks (alone, or for the part a
deterministic check cannot see), in the text the agent codes to: one category per round, never all of them. What it
finds is a proposal or a debt for people to weigh, never a fact and never a refusal of a move.
"""
from __future__ import annotations

import json
import os
import hashlib

from instruments.tree import Snapshot

from standard.catalog import categories, effective, load, render

from .concepts import AUTHORITY
from .drift_map import gap_dossiers
from .read_model import ReadModel

SUSPICION_KEYS = ("law_ref", "surface", "why", "evidence_seen", "determinism_gap", "needs",
                  "suggested_action", "confidence", "authority")
SIMPLICITY = ("Find needless layers, state, dependencies, dead code and duplicated mechanisms across the repository. "
              "Propose a smaller design for a current need, with concrete paths, the behaviour and guarantees to "
              "preserve, and verification needed. Do not optimise line counts, weaken checks or invent work. "
              "law_ref is design:simplicity; a design proposal is not a law violation or a safety debt.")


def rotation(state_path, cat=None) -> str:
    """The next category to patrol, in the catalog's fixed order; the position is kept in U's own file."""
    order = ["simplicity", *categories()]
    try:
        last = json.loads(state_path.read_text()).get("category")
    except (OSError, ValueError):
        last = None
    nxt = order[(order.index(last) + 1) % len(order)] if last in order else order[0]
    state_path.write_text(json.dumps({"category": nxt}))
    return nxt


def patrol_rules(category: str, values: dict, features=None) -> list:
    """The rules of a category an AI reads to check (`ai` in who), rendered as the agent codes to them."""
    import re as _re
    out = []
    for r in load()["rules"]:
        slug = _re.sub(r"[^a-z0-9]+", "-", r["category"].lower()).strip("-")
        if slug != category or "ai" not in r["who"]:
            continue
        if features is not None and not set(r["applies"]) <= set(features):
            continue
        out.append(render(r, values))
    return out


def patrol_context(view: dict, findings=None, routes=(), qualify=None, *, focus=None,
                   mode: str = "RUN", model: ReadModel | None = None, rules: list | None = None) -> dict:
    """Context for a repo-wide or targeted law patrol (`rules`: the catalog rules this round reads for)."""
    model = model or ReadModel(view, findings, routes, qualify)
    model.assert_view(view)
    law, findings, settings = model.law, model.findings, model.settings
    dossiers = gap_dossiers(view, model=model, mode=mode)
    selected = dossiers
    if focus:
        text = str(focus)
        selected = [d for d in dossiers if text in (d["id"], d["law"]["resource"]) or text in json.dumps(d["law"])]
    weak = [d for d in selected if d["state"] in ("unknown", "unmeasured", "open")
            or d["route"]["state"] in (None, "NO_ROUTE", "TRUST_BLOCKED")
            or d["action"]["method"] in ("missing_task", "llm_or_configured_scope")]
    simplicity = focus == "simplicity"
    return {"kind": "simplicity-patrol" if simplicity else "law-patrol",
            "mission": SIMPLICITY if simplicity else "Find possible law violations missed by instruments.",
            "mode": "targeted" if focus else "wide", "focus": focus,
            "basis": view["prefix"], "law_digest": view["law"].get("digest"),
            "read_model": {"basis": model.basis, "authority": model.graph()["authority"]},
            "effective_law": law, "settings": settings,
            "known_findings": findings,
            "known_gaps": [d for d in selected if d["state"] in ("gap", "open", "escalated", "unmeasured")],
            "weak_spots": weak,
            "instruments": law.get("instruments", {}),
            "operations": law.get("ops", {}),
            "routes": {op: spec.get("routes", {}) for op, spec in law.get("ops", {}).items()},
            "rules": rules or [],
            "authority": AUTHORITY["patrol"],
            "expected_output": {"suspicions": [{k: "..." for k in SUSPICION_KEYS}]}}


def run_patrol(cycle, *, main, focus=None) -> dict:
    """Run one advisory pass inside U, with read/search tools only; keep a private result history.
    cycle: the repair producer (its agent, findings and routes)."""
    from .advisory_llm import propose_patrol
    from .llm import redact

    if cycle.agent.llm is None:
        raise ValueError("law patrol needs a configured model in the agent process")
    if focus is not None and (not isinstance(focus, str) or len(focus) > 200):
        raise ValueError("patrol focus is at most 200 characters")
    view, base = cycle.service.view(), main()
    model = ReadModel(view, cycle._findings(), cycle.routes, cycle.service.qualify, main=base)
    tree = Snapshot(cycle.agent.store, base)
    rules = []
    if focus is None:                                  # a round of the rotation: one category of AI-read rules
        from instruments.surfaces import scan
        category = rotation(cycle.agent.store.parent / "patrol-rotation.json")
        values = effective(load(), view["law"]["effective"].get("settings", {}).get("values"))
        rules = patrol_rules(category, values, scan(tree)["features"] if hasattr(tree, "paths") else None)
        focus = "simplicity" if category == "simplicity" else f"rules:{category}"
    context = patrol_context(view, focus=focus, model=model, rules=rules)

    class ReadOnlyResearch:
        def dialogue(self, prompt, snapshot, *, key):
            return cycle.agent.research.dialogue(prompt, snapshot, key=key,
                                                 allowed_actions=("read", "search"))

    result = propose_patrol(context, tree, ReadOnlyResearch())
    record = {"basis": context["basis"], "law_digest": context["law_digest"], "main": base,
              "focus": focus, "mode": context["mode"],
              "next": "Serve an existing debt within its scope, or create a human-contracted build request for a refactor.",
              **result}
    current = cycle.service.view()
    record["state"] = ("proposed" if main() == base and current["law"].get("digest") == record["law_digest"] else "stale")
    record["id"] = "patrol:" + hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()[:24]
    clean, _ = redact(json.dumps(record, sort_keys=True))
    notes = cycle.agent.store.parent / "patrol-results.jsonl"
    fd = os.open(notes, os.O_APPEND | os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(clean + "\n")
    return json.loads(clean)


def patrol_results(cycle, *, main) -> list:
    """U's proposal history, labelled against the current main/law. It is never a queue of constitutional debts."""
    path = cycle.agent.store.parent / "patrol-results.jsonl"
    if not path.exists():
        return []
    view, base = cycle.service.view(), main()
    out = []
    with path.open() as source:
        for line in source:
            item = json.loads(line)
            item["state"] = ("proposed" if item["main"] == base and item["law_digest"] == view["law"].get("digest") else "stale")
            out.append(item)
    return out


class Patrol:
    """One bounded advisory round after normal moves, on a persisted cadence; failures do not block the loop."""
    name = "patrol"

    def __init__(self, cycle, main, *, clock, interval_ms=3_600_000):
        if type(interval_ms) is not int or not 60_000 <= interval_ms <= 86_400_000:
            raise ValueError("patrol interval_ms must be 60000..86400000")
        self.cycle, self.main, self.clock, self.interval_ms = cycle, main, clock, interval_ms
        self.notes = cycle.agent.store.parent / "patrol-schedule.json"

    def run(self, view, main):
        if self.cycle.agent.llm is None:
            return {"state": "unavailable", "reason": "no model configured"}
        now = self.clock()
        note = json.loads(self.notes.read_text()) if self.notes.exists() else {}
        if now < note.get("next_at", 0):
            return {**note, "state": "waiting"}
        # Reserve the next round before model calls; errors and process restarts cannot create a retry storm.
        self.notes.write_text(json.dumps({"next_at": now + self.interval_ms}))
        try:
            result = run_patrol(self.cycle, main=self.main)
            report = {"state": result["state"], "id": result["id"], "focus": result["focus"],
                      "suspicions": len(result["suspicions"])}
        except Exception as exc:
            report = {"state": "unavailable", "reason": f"{type(exc).__name__}: {str(exc)[:200]}"}
        self.notes.write_text(json.dumps({"next_at": now + self.interval_ms, **report}))
        return report
