"""One contextual surface for humans and agents, derived from the checked view, never an authority."""
from __future__ import annotations

import json
from typing import Optional

from .concepts import AUTHORITY
from .read_model import ReadModel, human_target


def _matching_conditions(law: dict, op_name: Optional[str]) -> dict:
    conditions = law.get("conditions", {})
    names = {n for n in conditions if op_name and (n == op_name or n.startswith(f"{op_name}-"))}
    return {n: conditions[n] for n in sorted(names)}


def _observations(policy: Optional[dict]) -> list:
    out = []
    for atom in (policy or {}).get("all", []):
        if "observed" in atom:
            name, value, level = atom["observed"]
            out.append({"kind": "observed", "name": name, "expect": value, "level": level})
        elif "compare" in atom:
            name, op, value, level = atom["compare"]
            out.append({"kind": "compare", "name": name, "op": op, "expect": value, "level": level})
    return out


def _proof_plan(conditions: dict, target: Optional[dict], facts: list, finding: dict) -> dict:
    # The gateway exposes `status`, not `value`. It omits provenance and level, so this is a reading aid only.
    observed = {o["property"]: o["status"] for o in facts if isinstance(o, dict)
                and "property" in o and "status" in o}
    alternatives = []
    for name, policy in conditions.items():
        expected = _observations(policy)
        missing = [item for item in expected if item["name"] not in observed]
        mismatch = [item for item in expected if item["kind"] == "observed" and item["name"] in observed
                    and str(observed[item["name"]]) != str(item["expect"])]
        alternatives.append({"condition": name, "expected": expected, "missing": missing,
                             "mismatch": mismatch, "comparison_requires_kernel": any(
                                 item["kind"] == "compare" for item in expected)})
    return {"target": target and {"property": target.get("property"), "expect": target.get("expect"),
                                  "min_level": target.get("min_level"), "fresh_ms": target.get("fresh_ms"),
                                  "sources": target.get("sources", [])},
            "alternatives": alternatives, "observed": observed, "finding": finding,
            "comparison_scope": "candidate values only; source, level, freshness and capability chain are judged by the kernel",
            "limits": ["agent notes are not facts", "agent commits do not certify closure",
                       "the kernel admits only signed statements backed by independent evidence"]}


def _autonomy(task: dict, target: Optional[dict], operation: Optional[dict]) -> dict:
    op = task.get("op") or (target or {}).get("repair")
    human = human_target(target or {})
    if task.get("need") == "investigate":
        mode = "research_only"
        can = ["read and search a pinned snapshot", "propose a tool or an instrument for review"]
        requires = ["an independent qualified route before any repair or proof"]
    elif human:
        mode = "human_attestation"
        can = ["prepare a dossier", "explain missing evidence", "propose next operator action"]
        requires = ["a person signs the attestation or review"]
    elif op:
        mode = "bounded_agent"
        can = ["inspect the repository and known findings", "propose a commit in its own store",
               "run its own prechecks", "submit a signed intent when it has a grant"]
        requires = ["independent scanners measure the exact transition", "the kernel rechecks current rights"]
    else:
        mode = "explain_only"
        can = ["explain the obligation", "prepare evidence for a person"]
        requires = ["a lawful operation or human statement"]
    cannot = ["change the law", "weaken system settings", "write main directly",
              "certify its own proof", "close an obligation without kernel admission"]
    return {"mode": mode, "operation": op, "resource_template": operation and operation.get("resource"),
            "can": can, "cannot": cannot, "requires": requires}


def _decision(task: dict, target: Optional[dict], operation: Optional[dict], conditions: dict, proof: dict) -> dict:
    if not operation and not target:
        status, reason = "blocked", "no matching law target or operation"
    elif task.get("need") == "investigate":
        status, reason = "research_only", "this task explores a missing route and cannot submit a repair"
    elif human_target(target or {}):
        status, reason = "needs_human", "the target is marked as requiring a person"
    elif task.get("state") in ("NO_ROUTE", "TRUST_BLOCKED"):
        status, reason = "needs_route", "the projected work has no qualified route"
    elif task.get("state") == "HUMAN_REVIEW":
        status, reason = "needs_human", "the projected work requires human review"
    elif not operation:
        status, reason = "needs_operation", "the target has no repair operation"
    elif proof["alternatives"] and all(a["missing"] or a["mismatch"] for a in proof["alternatives"]):
        status, reason = "needs_evidence", "no named operation condition has matching visible values"
    else:
        status, reason = "candidate", "the operation may be investigated; this packet cannot establish admission"
    return {"status": status, "reason": reason, "need": task.get("need"), "resource": task.get("resource"),
            "operation": task.get("op") or (target or {}).get("repair"), "conditions": sorted(conditions)}


def task_context(view: dict, task: dict, findings=None, settings=None, *, model: ReadModel | None = None) -> dict:
    model = model or ReadModel(view, findings, settings=settings)
    model.assert_view(view)
    law = model.law
    target = next((t for t in law.get("targets", []) if t["id"] == task.get("target")), None)
    op_name = task.get("op") or (target or {}).get("repair")
    operation = law.get("ops", {}).get(op_name)
    grants = view.get("grants", {})
    conditions = _matching_conditions(law, op_name)
    resource = task["resource"]
    fact_resource = resource if not target else target["resource"]
    facts = model.facts_for(resource)
    if fact_resource != resource:
        facts += model.facts_for(fact_resource)
    finding = model.finding(fact_resource, target["property"]) if target else {}
    proof = _proof_plan(conditions, target, facts, finding)
    context = {"basis": view["prefix"], "law_digest": view["law"].get("digest"), "task": task,
            "requirement": target, "operation": operation, "effective_law": law,
            "assessment": view.get("assessment"), "entity": model.entity(task["resource"]),
            "grants": grants, "facts": facts, "findings": finding,
            "system_settings": model.settings,
            "law_trace": {"target": target, "operation_name": op_name, "operation": operation,
                          "conditions": conditions,
                          "grant_conditions": {gid: {name: law.get("conditions", {}).get(name)
                                                      for name in grant.get("conditions", [])}
                                               for gid, grant in grants.items() if grant.get("conditions")},
                          "resource_type": law.get("resources", {}).get((resource or "").split(":", 1)[0])},
            "proof_plan": proof, "autonomy": _autonomy(task, target, operation),
            "decision": _decision(task, target, operation, conditions, proof),
            "authority": AUTHORITY["context"]}
    refs = {f"law:targets/{target['id']}"} if target else set()
    if op_name:
        refs.add(f"law:ops/{op_name}")
    refs.update(f"law:conditions/{name}" for name in conditions)
    graph = model.graph()
    context["read_model"] = {"basis": model.basis,
                             "relations": [edge for edge in graph["relations"] if edge["from"] in refs],
                             "authority": graph["authority"]}
    context["human"] = {"summary": context["decision"]["reason"],
                        "why": ["this packet is compiled from the verified prefix, effective law, system settings and facts",
                                "the interface renders the same context the agent receives",
                                "nothing here grants authority without a signed statement admitted by the kernel"]}
    return context


def model_packet(context: dict) -> str:
    """Versioned structured input for a model; authority remains with the signed admission path."""
    return json.dumps({"schema": "standard-agent-context/v1", "packet": context}, sort_keys=True,
                      ensure_ascii=False)


def render_context(context: dict) -> str:
    task, target = context["task"], context["requirement"]
    prefix = context["basis"]
    lines = [f"prefix {prefix.get('size', '?')} · head {str(prefix.get('head', '?'))[:19]} · law {context['law_digest']}",
             f"task {task['id']}: {task['need']} {task['resource']}",
             f"opened {task.get('opened')}, due {task.get('due')}"]
    if target:
        lines.append(f"requirement: {target['property']} = {target['expect']} at level {target['min_level']}, "
                     f"fresh {target['fresh_ms']} ms, sources {', '.join(target['sources'])}")
    if context["operation"]:
        lines.append("repair op: " + json.dumps(context["operation"], sort_keys=True))
    lines.append("decision packet: " + json.dumps(context.get("decision", {}), sort_keys=True))
    lines.append("autonomy scope: " + json.dumps(context.get("autonomy", {}), sort_keys=True))
    lines.append("law trace: " + json.dumps(context.get("law_trace", {}), sort_keys=True))
    lines.append("read model: " + json.dumps(context.get("read_model", {}), sort_keys=True))
    lines.append("proof plan: " + json.dumps(context.get("proof_plan", {}), sort_keys=True))
    if context.get("system_settings"):
        lines.append("system settings: " + json.dumps(context["system_settings"], sort_keys=True))
    for route in task.get("routes", []):
        lines.append(f"route {route['route']}: {route['state']} (T {', '.join(route['required_t'])})")
    found = context["findings"]
    if found:
        lines.append(f"instrument reports {found.get('status')}; where (information, not a fact):")
        lines.extend(f"  {str(d).splitlines()[0][:200]}" for d in found.get("details", [])[:20])
    # Full effective declarations include client conditions whose names differ from Standard's conventions.
    lines.append("Effective law (floors and client, at this prefix):\n" + json.dumps(context["effective_law"], sort_keys=True))
    lines.append("Admitted grant declarations (the kernel rechecks current rights on submission):\n"
                 + json.dumps(context["grants"], sort_keys=True))
    lines.append(context["authority"])
    return "\n".join(lines)
