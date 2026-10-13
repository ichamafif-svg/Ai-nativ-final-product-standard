"""Deterministic gap/drift dossiers.

This module maps already-born obligations and published findings to the law target, route, proof plan and autonomy
scope. It does not create gaps, close them or ask a model to judge them.
"""
from __future__ import annotations

from typing import Optional

from instruments.data import EMPTY
from instruments.recipes import recipes_for

from .concepts import AUTHORITY
from .context import task_context
from .read_model import ReadModel, target_state


def _task_for(tasks: list, target_id: str) -> Optional[dict]:
    return next((t for t in tasks if t.get("target") == target_id and t.get("need") in ("repair", "review")),
                next((t for t in tasks if t.get("target") == target_id), None))


def _action(target: dict, task: Optional[dict], recipes: set) -> dict:
    if target.get("human") or target.get("resource", "").startswith("org:"):
        return {"owner": "human", "method": "attestation", "can_repair": False,
                "why": "the target is organisational or explicitly human"}
    if not target.get("repair"):
        return {"owner": "observer", "method": "observe", "can_repair": False,
                "why": "the law declares no repair operation"}
    if task is None:
        return {"owner": "unknown", "method": "missing_task", "can_repair": False,
                "why": "no projected task exists at this prefix"}
    if target["id"] in recipes:
        return {"owner": "agent", "method": "recipe", "can_repair": task.get("state") == "AVAILABLE",
                "why": "a trusted recipe can be independently reproduced"}
    if task.get("state") == "HUMAN_REVIEW":
        return {"owner": "human", "method": "review", "can_repair": False,
                "why": "the projected need requires human review"}
    return {"owner": "agent", "method": "llm_or_configured_scope", "can_repair": task.get("state") == "AVAILABLE",
            "why": "the agent may propose code, but independent facts and possibly review still decide"}


def gap_dossiers(view: dict, findings=None, routes=(), qualify=None, *, settings=None, mode: str = "RUN",
                 model: ReadModel | None = None) -> list:
    """Return one deterministic dossier per target of the effective law."""
    model = model or ReadModel(view, findings, routes, qualify, settings=settings)
    tasks = model.plan(mode)["tasks"]
    recipes = set(recipes_for(EMPTY))
    out = []
    for row in model.targets():
        target, finding = row["target"], row["finding"]
        task = _task_for(tasks, target["id"])
        ctx_task = task or {"id": f"target:{target['id']}", "need": "repair" if target.get("repair") else "attest",
                            "op": target.get("repair"), "resource": target["resource"], "target": target["id"],
                            "opened": None, "due": None}
        context = task_context(view, ctx_task, model.findings, settings=model.settings)
        status = row["state"]
        out.append({"id": target["id"], "state": status,
                    "law": {k: target.get(k) for k in ("id", "resource", "property", "expect", "repair", "human",
                                                       "fresh_ms", "due_ms", "sources")},
                    "drift": {"status": finding.get("status"), "where": list(finding.get("details", []))[:50],
                              "source": "instrument" if finding else "health"},
                    "obligations": row["debt"],
                    "route": {"task": task, "state": task and task.get("state"),
                              "choices": (task or {}).get("routes", [])},
                    "action": _action(target, task, recipes),
                    "proof_to_close": context["proof_plan"],
                    "decision": context["decision"],
                    "autonomy": context["autonomy"],
                    "methods": ["deterministic", "instrument"] + (["recipe"] if target["id"] in recipes else [])
                               + ["llm_reading"],
                    "authority": AUTHORITY["dossier"]})
    return out
