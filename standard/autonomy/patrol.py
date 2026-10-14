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

from standard.catalog import applicable, categories, effective, load, render, slug
from .context import assemble
from .research import ReadScope

from .concepts import AUTHORITY
from .context import gap_dossiers
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
        note = json.loads(state_path.read_text())
        last = note.get("category")
    except (OSError, ValueError):
        note, last = {}, None
    nxt = order[(order.index(last) + 1) % len(order)] if last in order else order[0]
    state_path.write_text(json.dumps({**note, "category": nxt}))
    return nxt


def patrol_rules(category: str, values: dict, features=None) -> list:
    """The rules of a category an AI reads to check (`ai` in who), rendered as the agent codes to them."""
    return [render(r, values) for r in (applicable(load(), features) if features is not None else load()["rules"])
            if slug(r["category"]) == category and "ai" in r["who"]]


def patrol_context(view: dict, findings=None, routes=(), qualify=None, *, focus=None,
                   mode: str = "RUN", model: ReadModel | None = None, rules: list | None = None) -> dict:
    """Context for a repo-wide or targeted law patrol (`rules`: the catalog rules this round reads for)."""
    model = model or ReadModel(view, findings, routes, qualify)
    model.assert_view(view)
    law, findings, settings = model.law, model.findings, model.settings
    dossiers = gap_dossiers(view, model=model, mode=mode)
    selected = dossiers
    question = (focus or "").split(":")[0]
    if focus and question != "simplicity":
        text = ":".join(str(focus).split(":")[:2]) if str(focus).startswith("rules:") else str(focus)
        selected = [d for d in dossiers if text in (d["id"], d["law"]["resource"]) or text in json.dumps(d["law"])]
    weak = [d for d in selected if d["state"] in ("unknown", "unmeasured", "open")
            or d["route"]["state"] in (None, "NO_ROUTE", "TRUST_BLOCKED")
            or d["action"]["method"] in ("missing_task", "llm_or_configured_scope")]
    simplicity = question == "simplicity"
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
    from .llm import redact
    from instruments.surfaces import scan
    from instruments.scope import relative

    if cycle.agent.llm is None:
        raise ValueError("patrol needs a configured model in the agent process")
    if focus is not None and (not isinstance(focus, str) or len(focus) > 200):
        raise ValueError("patrol focus is at most 200 characters")
    view, base = cycle.service.view(), main()
    model = ReadModel(view, cycle._findings(), cycle.routes, cycle.service.qualify, main=base)
    if focus in categories():
        focus = f"rules:{focus}"
    snapshot = Snapshot(cycle.agent.store, base)
    product = scan(snapshot, declared=model.settings.get("features", ()))
    state_path = cycle.agent.store.parent / "patrol-rotation.json"
    if focus is None:
        category = rotation(state_path)
        focus = "simplicity" if category == "simplicity" else f"rules:{category}"
        roots = [".", *sorted({p.split("/", 1)[0] for p in snapshot.paths() if "/" in p})]
        note = json.loads(state_path.read_text())
        cursors = note.get("scopes", {})
        cursor = cursors.get(category, 0)
        root = roots[cursor % len(roots)]
        state_path.write_text(json.dumps({**note, "scopes": {**cursors, category: cursor + 1}}))
        if root != ".":
            focus += ":" + root
    parts = focus.split(":")
    category = parts[1] if parts[0] == "rules" and len(parts) >= 2 else None
    if category is not None and category not in categories():
        raise ValueError("unknown catalog category")
    if parts[0] not in ("simplicity", "rules") and model.target(focus) is None:
        raise ValueError("patrol focus must name simplicity, a catalog category or an effective target")
    root = ":".join(parts[2:]) if category else ":".join(parts[1:]) if parts[0] == "simplicity" else ""
    if root and (not relative(root) or not any(p == root or p.startswith(root + "/") for p in snapshot.paths())):
        raise ValueError("exploration scope must name an existing relative file or directory")
    paths = [p for p in snapshot.paths() if not root or p == root or p.startswith(root + "/")]
    tree = ReadScope(snapshot, paths)
    values = effective(load(), model.settings.get("values"))
    rules = patrol_rules(category, values, product["features"]) if category else []
    context = patrol_context(view, focus=focus, model=model, rules=rules)
    context["scope"] = {"question": "simplicity" if parts[0] == "simplicity" else "conformance",
                        "root": root or ".", "files": len(paths), "mode": "read_only"}
    context["rule_ids"] = [r.split()[0] for r in rules]
    # Applicability is observed on the whole product, even when this mission reads one subsystem.
    context["product"] = product
    result = (propose_patrol(context, tree, cycle.agent.research) if rules or category is None else
              {"suspicions": [], "authority": context["authority"], "outcome": "no applicable AI-readable requirements"})
    record = {"basis": context["basis"], "law_digest": context["law_digest"], "main": base,
              "focus": focus, "mode": context["mode"], "scope": context["scope"],
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


def propose_patrol(context: dict, tree, research, *, key=None) -> dict:
    """Ask a read-only research loop to patrol for possible law violations not yet deterministically born."""
    scope = context.get("scope", {"mode": "read_only"})
    category = (context.get("focus") or "").split(":")
    category = category[1] if category[0] == "rules" and len(category) > 1 else None
    packet, sources = assemble(context, tree, role="explore", scope=scope, touched=None, category=category,
                               rule_ids=context.get("rule_ids"), documents={"scope": sorted(tree.paths())})
    prompt = ("Explore this pinned repository scope. Mission: " + context.get("mission", "Find possible law violations.") +
              " Read the catalog requirements and block contracts; investigate only the named question and scope. "
              "Report concrete suspicions, behaviour/guarantees to preserve and verification needed. "
              "Do not claim facts, close gaps, authorize work or change law. Return JSON {\"suspicions\": "
              f"[objects with only these keys: {', '.join(SUSPICION_KEYS)}]}}.\n" + packet)
    reply = research.dialogue(prompt, tree, key=key or f"patrol:{context.get('focus') or 'wide'}",
                              allowed_actions=("read", "search"), context=sources)
    if not isinstance(reply, dict) or not isinstance(reply.get("suspicions"), list):
        raise ValueError("exploration unavailable: expected a suspicions list")
    suspicions = reply["suspicions"]
    out = []
    for item in (suspicions[:50] if isinstance(suspicions, list) else []):
        if not isinstance(item, dict) or not isinstance(item.get("law_ref"), str) or not item["law_ref"]:
            continue
        filtered = {k: item[k][:2000] for k in ("law_ref", "surface", "why", "determinism_gap",
                                                  "suggested_action", "confidence")
                    if isinstance(item.get(k), str)}
        for k in ("evidence_seen", "needs"):
            if isinstance(item.get(k), list):
                filtered[k] = [v[:500] for v in item[k][:20] if isinstance(v, str)]
        filtered["authority"] = "proposal_only"
        out.append(filtered)
    return {"suspicions": out, "authority": context["authority"]}
