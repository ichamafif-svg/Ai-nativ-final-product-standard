"""Human/agent context packets for the web and CLI surface.

The surface renders these packets; it does not decide. Keeping packet assembly here prevents the HTTP installation
object from becoming the owner of autonomy concepts.
"""
from __future__ import annotations

from instruments.suite import contract_path, load
from standard.autonomy.concepts import AUTHORITY
from standard.autonomy.context import task_context
from standard.autonomy.law_surface import law_surface_map
from standard.autonomy.patrol import patrol_context
from standard.autonomy.read_model import ReadModel


def common_context(view: dict, settings: dict) -> dict:
    return {"basis": view["prefix"], "law_digest": view["law"]["digest"], "assessment": view.get("assessment"),
            "system_settings": settings, "authority": AUTHORITY["surface"]}


def target_context(view: dict, findings: dict, settings: dict, routes, qualify, ident: str,
                   model: ReadModel | None = None) -> dict:
    law = view["law"]["effective"]
    target = next((t for t in law["targets"] if t["id"] == ident), None)
    if target is None:
        raise ValueError("unknown target")
    model = model or ReadModel(view, findings, routes, qualify, settings=settings)
    plan = model.plan()
    tasks = [t for t in plan["tasks"] if t.get("target") == ident]
    task = next((t for t in tasks if t["need"] in ("repair", "review")),
                (tasks or [{"id": f"target:{ident}", "need": "repair" if target.get("repair") else "attest",
                           "op": target.get("repair"), "resource": target["resource"], "target": ident,
                           "opened": None, "due": None}])[0])
    ctx = task_context(view, task, findings, settings=settings, model=model)
    return {**common_context(view, settings), **ctx, "kind": "target", "id": ident,
            "title": f"{target['property']} = {target['expect']}",
            "mission": {"need": ctx["decision"]["need"], "resource": target["resource"],
                        "why": ctx["findings"].get("status"), "decision": ctx["decision"]},
            "law": ctx["law_trace"],
            "proof": {**ctx["proof_plan"], "facts": ctx["facts"], "tasks": tasks},
            "agent": ctx["autonomy"],
            "admission": {"decision": ctx["decision"],
                          "requires": "fresh independent facts matching the target and operation conditions",
                          "review": bool(target.get("human")) or target.get("repair") != "remediate"}}


def request_context(view: dict, findings: dict, settings: dict, requests, ident: str, main: str,
                    model: ReadModel | None = None) -> dict:
    law = view["law"]["effective"]
    resource = f"build:request/{ident}"
    entity = view.get("entities", {}).get(resource)
    if not entity or entity.get("type") != "request":
        raise ValueError("unknown request")
    spec, contract = (load(requests, entity["fields"][k]) for k in ("spec", "contract"))
    features = [{"resource": r, "facts": facts} for r, facts in view.get("transitions", {}).items()
                if r.startswith(f"repo:feature:{ident}/")]
    ctx = task_context(view, {"id": f"request:{ident}", "need": "implement", "op": "implement",
                              "resource": resource, "target": None, "opened": entity.get("created"),
                              "due": None}, findings, settings=settings, model=model)
    return {**common_context(view, settings), **ctx, "kind": "request", "id": ident, "title": entity["fields"]["title"],
            "mission": {"need": "implement", "resource": resource, "state": entity["state"],
                        "main": main, "contract_path": contract_path(ident), "decision": ctx["decision"]},
            "request": {"spec": spec.decode(errors="replace") if spec else None,
                        "contract": contract.decode(errors="replace") if contract else None,
                        "facts": view["transitions"].get(resource, {})},
            "law": ctx["law_trace"],
            "proof": {**ctx["proof_plan"], "features": features, "delivery": ["accepted = yes for delivery"]},
            "agent": {**ctx["autonomy"],
                      "can": ctx["autonomy"]["can"] + ["add the signed acceptance contract byte for byte"],
                      "cannot": ctx["autonomy"]["cannot"] + ["change tests", "change the signed contract",
                                                             "land without review"]},
            "admission": {"decision": ctx["decision"],
                          "implement": "kernel requires scanner facts on the exact transition plus review",
                          "deliver": "only after main passes the unchanged contract"}}


def patrol_packet(view: dict, findings: dict, settings: dict, routes, qualify, ident: str,
                  model: ReadModel | None = None) -> dict:
    focus = ident if ident and ident != "wide" else None
    ctx = patrol_context(view, findings, routes, qualify, settings=settings, focus=focus, model=model)
    return {**common_context(view, settings), **ctx, "kind": "patrol", "id": ident or "wide",
            "title": "Patrouille loi" + (f" · {focus}" if focus else " · repo"),
            "mission": {"need": "explore", "focus": focus, "mode": ctx["mode"],
                        "decision": {"status": "proposal_only",
                                     "reason": "exploratory patrol may surface suspicions but cannot create facts"}},
            "agent": {"mode": "read_only_patrol",
                      "can": ["read and search the repository snapshot", "compare code against effective law",
                              "surface suspicions and blind spots", "suggest instruments, review or fixes"],
                      "cannot": ["claim a fact", "open or close an official gap", "authorize work",
                                 "change law or system settings", "write main directly"]},
            "admission": {"suspicions": "must become scanner evidence, human review, law proposal or normal repair before they matter"}}


def surface_packet(view: dict, findings: dict, settings: dict, routes, qualify, ident: str, inputs=None,
                   model: ReadModel | None = None) -> dict:
    focus = ident if ident and ident != "wide" else None
    packet = law_surface_map(view, findings, routes, qualify, settings=settings, focus=focus, inputs=inputs,
                             model=model)
    return {**common_context(view, settings), **packet, "kind": "surface", "id": ident or "wide",
            "title": "Carte loi / code" + (f" · {focus}" if focus else " · repo"),
            "mission": {"need": "validate-map", "focus": focus,
                        "decision": {"status": "review_only",
                                     "reason": "this map makes bindings and unknowns explicit for a human"}},
            "agent": {"mode": "read_only_map",
                      "can": ["read the map", "surface missing bindings", "suggest instruments or reviews"],
                      "cannot": ["certify compliance", "create facts", "close gaps", "change law or system settings"]},
            "admission": {"map_review": "a human can validate the map as review input; closure still requires admitted facts"}}


def agent_context(kind: str, ident: str, *, view: dict, findings: dict, settings: dict, routes, qualify, requests,
                  main: str, inputs=None, model: ReadModel | None = None) -> dict:
    if kind == "target":
        return target_context(view, findings, settings, routes, qualify, ident, model)
    if kind == "request":
        return request_context(view, findings, settings, requests, ident, main, model)
    if kind == "patrol":
        return patrol_packet(view, findings, settings, routes, qualify, ident, model)
    if kind == "surface":
        return surface_packet(view, findings, settings, routes, qualify, ident, inputs, model)
    raise ValueError("kind is target, request, patrol or surface")
