"""Human/agent context packets for the web and CLI surface.

The surface renders these packets; it does not decide. Keeping packet assembly here prevents the HTTP installation
object from becoming the owner of autonomy concepts.
"""
from __future__ import annotations

from instruments.suite import contract_path, load
from standard.autonomy.concepts import AUTHORITY
from standard.autonomy.context import task_context
from standard.autonomy.patrol import patrol_context
from standard.autonomy.read_model import ReadModel


def common_context(view: dict) -> dict:
    return {"basis": view["prefix"], "law_digest": view["law"]["digest"], "assessment": view.get("assessment"),
            "settings": view["law"]["effective"].get("settings", {}), "authority": AUTHORITY["surface"]}


def target_context(view: dict, findings: dict, routes, qualify, ident: str, model: ReadModel | None = None) -> dict:
    model = model or ReadModel(view, findings, routes, qualify)
    model.assert_view(view)
    row = model.target(ident)
    if row is None:
        raise ValueError("unknown target")
    target = row["target"]
    plan = model.plan()
    tasks = [t for t in plan["tasks"] if t.get("target") == ident]
    task = next((t for t in tasks if t["need"] in ("repair", "human")),
                (tasks or [{"id": f"target:{ident}", "need": "repair" if target.get("repair") else "human",
                           "op": target.get("repair"), "resource": target["resource"], "target": ident,
                           "opened": None, "due": None}])[0])
    ctx = task_context(view, task, findings, model=model)
    return {**common_context(view), **ctx, "kind": "target", "id": ident,
            "title": f"{target['property']} = {target['expect']}",
            "mission": {"need": ctx["decision"]["need"], "resource": target["resource"],
                        "why": ctx["findings"].get("status"), "decision": ctx["decision"]},
            "law": ctx["law_trace"],
            "proof": {**ctx["proof_plan"], "facts": ctx["facts"], "tasks": tasks},
            "agent": ctx["autonomy"],
            "admission": {"decision": ctx["decision"],
                          "requires": "fresh independent facts on the exact transition matching one route of the op",
                          "human": bool(target.get("human"))}}


def request_context(view: dict, findings: dict, requests, ident: str, main: str,
                    model: ReadModel | None = None) -> dict:
    model = model or ReadModel(view, findings, main=main)
    model.assert_view(view)
    resource = f"build:request/{ident}"
    entity = model.entity(resource)
    if not entity or entity.get("type") != "request":
        raise ValueError("unknown request")
    spec, contract = (load(requests, entity["fields"][k]) for k in ("spec", "contract"))
    features = [{"resource": r, "facts": facts} for r, facts in model.transitions(f"repo:feature:{ident}/")]
    ctx = task_context(view, {"id": f"request:{ident}", "need": "implement", "op": "implement",
                              "resource": resource, "target": None, "opened": entity.get("created"),
                              "due": None}, findings, model=model)
    return {**common_context(view), **ctx, "kind": "request", "id": ident, "title": entity["fields"]["title"],
            "mission": {"need": "implement", "resource": resource, "state": entity["state"],
                        "main": main, "contract_path": contract_path(ident), "decision": ctx["decision"]},
            "request": {"spec": spec.decode(errors="replace") if spec else None,
                        "contract": contract.decode(errors="replace") if contract else None,
                        "facts": model.transition(resource)},
            "law": ctx["law_trace"],
            "proof": {**ctx["proof_plan"], "features": features, "delivery": ["accepted = yes for delivery"]},
            "agent": {**ctx["autonomy"],
                      "can": ctx["autonomy"]["can"] + ["add the signed acceptance contract byte for byte"],
                      "cannot": ctx["autonomy"]["cannot"] + ["change tests", "change the signed contract"]},
            "admission": {"decision": ctx["decision"],
                          "implement": "acceptance, tests, no regression and scope measured on the exact transition; "
                                       "the human's decision if the rules keep the move",
                          "deliver": "only after main passes the unchanged contract"}}


def patrol_packet(view: dict, findings: dict, routes, qualify, ident: str, model: ReadModel | None = None) -> dict:
    focus = ident if ident and ident != "wide" else None
    ctx = patrol_context(view, findings, routes, qualify, focus=focus, model=model)
    return {**common_context(view), **ctx, "kind": "patrol", "id": ident or "wide",
            "title": "Patrouille loi" + (f" · {focus}" if focus else " · repo"),
            "mission": {"need": "explore", "focus": focus, "mode": ctx["mode"],
                        "decision": {"status": "proposal_only",
                                     "reason": "exploratory patrol may surface suspicions but cannot create facts"}},
            "agent": {"mode": "read_only_patrol",
                      "can": ["read and search the repository snapshot", "compare code against effective law",
                              "surface suspicions and blind spots", "suggest instruments, rules or fixes"],
                      "cannot": ["claim a fact", "open or close an official gap", "authorize work",
                                 "change the rules", "write main directly"]},
            "admission": {"suspicions": "must become scanner evidence, a change of the rules or a normal repair before they matter"}}


def agent_context(kind: str, ident: str, *, view: dict, findings: dict, routes, qualify, requests, main: str,
                  model: ReadModel | None = None) -> dict:
    if kind == "target":
        return target_context(view, findings, routes, qualify, ident, model)
    if kind == "request":
        return request_context(view, findings, requests, ident, main, model)
    if kind == "patrol":
        return patrol_packet(view, findings, routes, qualify, ident, model)
    raise ValueError("kind is target, request or patrol")
