"""Exploratory law patrol context.

Patrol is advisory. It starts before a deterministic gap exists and packages law, settings, findings, routes and weak
spots so a read-only model or a human can look for blind spots.
"""
from __future__ import annotations

import json
import os

from instruments.tree import Snapshot

from .concepts import AUTHORITY
from .drift_map import gap_dossiers
from .read_model import ReadModel

SUSPICION_KEYS = ("law_ref", "surface", "why", "evidence_seen", "determinism_gap", "needs",
                  "suggested_action", "confidence", "authority")


def patrol_context(view: dict, findings=None, routes=(), qualify=None, *, settings=None, rules=None, focus=None,
                   mode: str = "RUN", model: ReadModel | None = None) -> dict:
    """Context for a repo-wide or targeted law patrol."""
    model = model or ReadModel(view, findings, routes, qualify,
                               settings=settings if settings is not None else rules)
    model.assert_view(view)
    law, findings, settings = model.law, model.findings, model.settings
    dossiers = gap_dossiers(view, model=model, mode=mode)
    selected = dossiers
    if focus:
        text = str(focus)
        selected = [d for d in dossiers if text in (d["id"], d["law"]["resource"]) or text in json.dumps(d["law"])]
    weak = [d for d in selected if d["state"] in ("unknown", "unmeasured", "open", "attestation_due")
            or d["route"]["state"] in (None, "NO_ROUTE", "TRUST_BLOCKED")
            or d["action"]["method"] in ("missing_task", "llm_or_configured_scope")]
    return {"kind": "law-patrol", "mode": "targeted" if focus else "wide", "focus": focus,
            "basis": view["prefix"], "law_digest": view["law"].get("digest"),
            "read_model": {"basis": model.basis, "authority": model.graph()["authority"]},
            "effective_law": law, "system_settings": settings,
            "known_findings": findings,
            "known_gaps": [d for d in selected if d["state"] in ("gap", "open", "escalated", "unmeasured",
                                                           "attestation_due")],
            "weak_spots": weak,
            "instruments": law.get("instruments", {}),
            "operations": law.get("ops", {}),
            "conditions": law.get("conditions", {}),
            "authority": AUTHORITY["patrol"],
            "expected_output": {"suspicions": [{k: "..." for k in SUSPICION_KEYS}]}}


def run_patrol(cycle, *, focus=None) -> dict:
    """Run one advisory pass inside U, with read/search tools only; keep a private result history."""
    from .advisory_llm import propose_patrol
    from .llm import redact

    if cycle.agent.llm is None:
        raise ValueError("law patrol needs a configured model in the agent process")
    if focus is not None and (not isinstance(focus, str) or len(focus) > 200):
        raise ValueError("patrol focus is at most 200 characters")
    view, base = cycle.service.view(), cycle.main()
    model = ReadModel(view, cycle._findings(), cycle.routes, cycle.service.qualify,
                      settings=cycle.settings(), main=base)
    context = patrol_context(view, focus=focus, model=model)
    tree = Snapshot(cycle.agent.store, base)

    class ReadOnlyResearch:
        def dialogue(self, prompt, snapshot, *, key):
            return cycle.agent.research.dialogue(prompt, snapshot, key=key,
                                                 allowed_actions=("read", "search"))

    result = propose_patrol(context, tree, ReadOnlyResearch())
    record = {"basis": context["basis"], "law_digest": context["law_digest"], "main": base,
              "focus": focus, "mode": context["mode"], **result}
    clean, _ = redact(json.dumps(record, sort_keys=True))
    notes = cycle.agent.store.parent / "patrol-results.jsonl"
    fd = os.open(notes, os.O_APPEND | os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(clean + "\n")
    return json.loads(clean)
