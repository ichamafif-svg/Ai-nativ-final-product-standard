"""Deterministic gap/drift dossiers.

This module maps already-born obligations and published findings to the law target, route, proof plan and autonomy
scope. It does not create gaps, close them or ask a model to judge them.
"""
from __future__ import annotations

from typing import Optional


from .concepts import AUTHORITY
from .context import task_context
from .read_model import ReadModel


def _task_for(tasks: list, target_id: str) -> Optional[dict]:
    return next((t for t in tasks if t.get("target") == target_id and t.get("need") in ("repair", "human")),
                next((t for t in tasks if t.get("target") == target_id), None))


def _action(target: dict, task: Optional[dict], role: dict) -> dict:
    if role["level"] == "human":
        return {"owner": "human", "method": "human", "can_repair": False,
                "why": "no move of the rules repairs it: the human does (a provider's settings)"}
    if not target.get("repair"):
        return {"owner": "observer", "method": "observe", "can_repair": False,
                "why": "the law declares no repair operation"}
    if task is None:
        return {"owner": "unknown", "method": "missing_task", "can_repair": False,
                "why": "no projected task exists at this prefix"}
    if role["method"] == "recipe":
        return {"owner": "agent", "method": "recipe", "can_repair": task.get("state") == "AVAILABLE",
                "why": "a trusted recipe can be independently reproduced"}
    if task.get("state") == "HUMAN_REVIEW":
        return {"owner": "human", "method": "decision", "can_repair": False,
                "why": "the projected need waits for the human's decision"}
    if role["level"] == "decision":
        return {"owner": "agent", "method": "candidate + human decision", "can_repair": task.get("state") == "AVAILABLE",
                "why": "the rules keep this move for the human: the agent proposes, the human decides"}
    return {"owner": "agent", "method": "llm_or_configured_scope", "can_repair": task.get("state") == "AVAILABLE",
            "why": "the agent proposes code; the scanner's facts on the exact commit decide which route holds"}


def gap_dossiers(view: dict, findings=None, routes=(), qualify=None, *, mode: str = "RUN",
                 model: ReadModel | None = None) -> list:
    """Return one deterministic dossier per target of the effective law."""
    model = model or ReadModel(view, findings, routes, qualify)
    model.assert_view(view)
    tasks = model.plan(mode)["tasks"]
    out = []
    for row in model.targets():
        target, finding = row["target"], row["finding"]
        task = _task_for(tasks, target["id"])
        ctx_task = task or {"id": f"target:{target['id']}", "need": "repair" if target.get("repair") else "attest",
                            "op": target.get("repair"), "resource": target["resource"], "target": target["id"],
                            "opened": None, "due": None}
        context = task_context(view, ctx_task, model=model)
        status = row["state"]
        out.append({"id": target["id"], "state": status,
                    "law": {k: target.get(k) for k in ("id", "resource", "property", "expect", "repair", "human",
                                                       "fresh_ms", "due_ms", "sources")},
                    "drift": {"status": finding.get("status"), "where": list(finding.get("details", []))[:50],
                              "source": "instrument" if finding else "health"},
                    "obligations": row["debt"],
                    "route": {"task": task, "state": task and task.get("state"),
                              "choices": (task or {}).get("routes", [])},
                    "action": _action(target, task, row["role"]),
                    "proof_to_close": context["proof_plan"],
                    "decision": context["decision"],
                    "autonomy": context["autonomy"],
                    "methods": ["deterministic", "instrument"] + (["recipe"] if row["role"]["method"] == "recipe" else [])
                               + ["llm_reading"],
                    "authority": AUTHORITY["dossier"]})
    return out
