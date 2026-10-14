"""One contextual surface for humans and agents, derived from the checked view, never an authority."""
from __future__ import annotations

import json
import re
from typing import Optional

from .concepts import AUTHORITY
from .read_model import ReadModel, human_target


def _routes(law: dict, op_name: Optional[str]) -> dict:
    """The routes of the op in force: the ways the move may be played (F0-12)."""
    return dict(sorted(law.get("ops", {}).get(op_name or "", {}).get("routes", {}).items()))


def _observations(policy: Optional[dict]) -> list:
    out = []
    for atom in (policy or {}).get("all", []):
        if "observed" in atom:
            name, value, level, *by = atom["observed"]
            out.append({"kind": "observed", "name": name, "expect": value, "level": level,
                        **({"author_kind": by[0]} if by else {})})
        elif "compare" in atom:
            name, op, value, level = atom["compare"]
            out.append({"kind": "compare", "name": name, "op": op, "expect": value, "level": level})
    return out


def _proof_plan(routes: dict, target: Optional[dict], facts: list, finding: dict) -> dict:
    # The gateway exposes `status`, not `value`. It omits provenance and level, so this is a reading aid only.
    observed = {o["property"]: o["status"] for o in facts if isinstance(o, dict)
                and "property" in o and "status" in o}
    alternatives = []
    for name, policy in routes.items():
        expected = _observations(policy)
        missing = [item for item in expected if item["name"] not in observed]
        mismatch = [item for item in expected if item["kind"] == "observed" and item["name"] in observed
                    and str(observed[item["name"]]) != str(item["expect"])]
        alternatives.append({"route": name, "expected": expected, "missing": missing,
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
        mode = "human_repair"
        can = ["prepare a dossier", "explain missing evidence", "propose what the human could change"]
        requires = ["the human repairs it where no move of the rules reaches (a provider's settings)"]
    elif op:
        mode = "bounded_agent"
        can = ["inspect the repository and known findings", "propose a commit in its own store",
               "run its own prechecks", "play the move when a route of the rules holds"]
        requires = ["independent scanners measure the exact transition",
                    "an autonomous route of the rules, or the human's decision on the exact resource",
                    "the kernel rechecks current rights"]
    else:
        mode = "explain_only"
        can = ["explain the obligation", "prepare evidence for a person"]
        requires = ["a lawful operation or human statement"]
    cannot = ["change the rules", "decide in the human's place", "write main directly",
              "certify its own proof", "close an obligation without kernel admission"]
    return {"mode": mode, "operation": op, "resource_template": operation and operation.get("resource"),
            "can": can, "cannot": cannot, "requires": requires}


def _decision(task: dict, target: Optional[dict], operation: Optional[dict], routes: dict, proof: dict) -> dict:
    if not operation and not target:
        status, reason = "blocked", "no matching law target or operation"
    elif task.get("need") == "investigate":
        status, reason = "research_only", "this task explores a missing route and cannot submit a repair"
    elif human_target(target or {}):
        status, reason = "needs_human", "no move of the rules repairs this target: the human does"
    elif task.get("state") in ("NO_ROUTE", "TRUST_BLOCKED"):
        status, reason = "needs_route", "the projected work has no qualified route"
    elif task.get("state") == "HUMAN_REVIEW":
        status, reason = "needs_human", "the projected work needs the human's decision"
    elif not operation:
        status, reason = "needs_operation", "the target has no repair operation"
    elif proof["alternatives"] and all(a["missing"] or a["mismatch"] for a in proof["alternatives"]):
        status, reason = "needs_evidence", "no route of the operation has matching visible values"
    else:
        status, reason = "candidate", "the operation may be investigated; this packet cannot establish admission"
    return {"status": status, "reason": reason, "need": task.get("need"), "resource": task.get("resource"),
            "operation": task.get("op") or (target or {}).get("repair"), "routes": sorted(routes)}


def task_context(view: dict, task: dict, findings=None, *, model: ReadModel | None = None) -> dict:
    model = model or ReadModel(view, findings)
    model.assert_view(view)
    law = model.law
    target = next((t for t in law.get("targets", []) if t["id"] == task.get("target")), None)
    op_name = task.get("op") or (target or {}).get("repair")
    operation = law.get("ops", {}).get(op_name)
    grants = view.get("grants", {})
    routes = _routes(law, op_name)
    resource = task["resource"]
    fact_resource = resource if not target else target["resource"]
    facts = model.facts_for(resource)
    if fact_resource != resource:
        facts += model.facts_for(fact_resource)
    finding = model.finding(fact_resource, target["property"]) if target else {}
    proof = _proof_plan(routes, target, facts, finding)
    context = {"basis": view["prefix"], "law_digest": view["law"].get("digest"), "task": task,
            "requirement": target, "operation": operation, "effective_law": law,
            "assessment": view.get("assessment"), "entity": model.entity(task["resource"]),
            "grants": grants, "facts": facts, "findings": finding,
            "settings": model.settings,
            "law_trace": {"target": target, "operation_name": op_name, "operation": operation,
                          "routes": routes,
                          "grant_conditions": {gid: {name: law.get("conditions", {}).get(name)
                                                      for name in grant.get("conditions", [])}
                                               for gid, grant in grants.items() if grant.get("conditions")},
                          "resource_type": law.get("resources", {}).get((resource or "").split(":", 1)[0])},
            "proof_plan": proof, "autonomy": _autonomy(task, target, operation),
            "decision": _decision(task, target, operation, routes, proof),
            "authority": AUTHORITY["context"]}
    if target:
        context["definition"] = model.target(target["id"])["definition"]
        context["measurement"] = model.target(target["id"])["measurement"]
    refs = {f"law:targets/{target['id']}"} if target else set()
    if op_name:
        refs.add(f"law:ops/{op_name}")
    refs.update(f"law:ops/{op_name}#{name}" for name in routes)
    graph = model.graph()
    context["read_model"] = {"basis": model.basis,
                             "relations": [edge for edge in graph["relations"] if edge["from"] in refs],
                             "authority": graph["authority"]}
    context["human"] = {"summary": context["decision"]["reason"],
                        "why": ["this packet is compiled from the verified prefix, the rules in force and facts",
                                "the interface renders the same context the agent receives",
                                "nothing here grants authority without a signed statement admitted by the kernel"]}
    return context


def assemble(context: dict, tree, *, role: str, scope=None, touched=(), focus=(), values=None, documents=None,
             category=None, rule_ids=None, budget=28_000) -> tuple[str, dict]:
    """Common mission reading derived from the catalog and pinned inputs. Large entries are deferred whole.

    read(ref=...) retrieves exact declarations/documents; search(in=context, query=...) lists references. These use
    the existing research tools and budgets. Selection changes attention, never applicability or admission.
    """
    from instruments.surfaces import scan
    from standard.catalog import contracts, effective, load, render, render_contracts
    from .repomap import RepoMap

    cat = load()
    law = context.get("effective_law", {})
    settings = context.get("settings", law.get("settings", {}))
    values = effective(cat, settings.get("values")) if values is None else values
    sources = {}
    for section, entries in law.items():
        if isinstance(entries, dict):
            sources.update({f"law/{section}/{name}": value for name, value in entries.items()})
        elif isinstance(entries, list) and all(isinstance(v, dict) and "id" in v for v in entries):
            sources.update({f"law/{section}/{v['id']}": v for v in entries})
        else:
            sources[f"law/{section}"] = entries
    sources.update({f"rule/{r['id']}": render(r, values) for r in cat["rules"]})
    sources.update({f"block/{name}": block for name, block in cat["blocks"].items()})
    sources.update({f"parameter/{name}": {"definition": spec, "value": values.get(name), "set": name in values}
                    for name, spec in cat["values"].items()})
    sources.update({f"policy/{name}": {"definition": spec, "value": settings.get(name), "set": name in settings}
                    for name, spec in cat["policy"]["parameter"].items()})
    sources.update({f"document/{name}": text for name, text in (documents or {}).items()})
    product = context.get("product") or (scan(tree, declared=settings.get("features", ())) if hasattr(tree, "paths") else {"features": [], "stacks": []})
    technical = contracts(cat, product["features"], values, touched=touched, category=category,
                          ids=rule_ids, stacks=product["stacks"])
    packet = {"role": role, "basis": {"journal": context.get("basis"), "law": context.get("law_digest"),
                                      "code": getattr(tree, "commit", None), "catalog": cat["digest"]},
              "scope": scope or {"mode": "read_only"}, "authority": AUTHORITY["context"],
              "selection": "Omitted requirements still apply. Read complete deferred entries before deciding; "
                           "use read(ref, offset) or search(in=context, query) for pinned declarations/documents.",
              "rule_ids": [r["id"] for r in technical["rules"]],
              "documents": sorted(f"document/{name}" for name in (documents or {}))}
    deferred = []

    def add(name, value):
        sources[f"mission/{name}"] = value
        if len(json.dumps({**packet, name: value}, ensure_ascii=False)) < budget - 2000:
            packet[name] = value
        else:
            deferred.append(f"mission/{name}")

    for name in ("task", "requirement", "definition", "measurement", "operation", "autonomy", "decision", "proof_plan", "law_trace"):
        if context.get(name):
            add(name, context[name])
    names = set(re.findall(r"@([a-z_]+)", json.dumps(context.get("law_trace", context.get("operation", {})))))
    for name in sorted(names & cat["policy"]["parameter"].keys()):
        add(f"policy/{name}", sources[f"policy/{name}"])
    add("technical", render_contracts(technical))
    for name in ("mission", "findings", "facts", "known_gaps", "weak_spots"):
        if context.get(name):
            add(name, context[name])
    if hasattr(tree, "paths"):
        paths = sorted(tree.paths())
        focus = sorted(set(focus) & set(paths))
        add("repository", {"files": len(paths), "focus": focus, "map": RepoMap(tree).render(limit=4000, focus=focus)})
        for path in focus[:4]:
            if getattr(tree, "entries", {}).get(path, ("",))[0] == "120000":
                continue
            raw = tree.read(path)
            if b"\x00" not in raw:
                add(f"code/{path}", raw.decode(errors="replace"))
    packet["deferred"] = deferred
    # Strings are immutable and each role receives its own inventory, even during parallel review.
    sources = {ref: value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)
               for ref, value in sources.items()}
    return json.dumps({"schema": "standard-agent-context/v2", "packet": packet}, ensure_ascii=False, sort_keys=True), sources


def write_scope(kind: str, ident: str, scopes=None) -> dict:
    """A description of the instrument's exact definitions; the scanner remains the enforcer."""
    from instruments.scope import FEATURE, REPAIR, RESERVED, WORKFLOWS
    from instruments.suite import contract_path
    pattern = FEATURE if kind == "build" or ident.startswith("rules-") else WORKFLOWS if ident == "actions" else REPAIR.get(ident)
    return {"kind": kind, "id": ident, "path_regex": pattern,
            "custom_globs": [] if pattern else (scopes or {}).get(ident, []), "reserved_regex": RESERVED.pattern,
            "reserved_exception": WORKFLOWS if kind == "repair" and ident == "actions" else None,
            "protected_contract": contract_path(ident) if kind == "build" else None,
            "new_paths": "same scope and relative-path checks as existing paths",
            "authority": "reading aid only; host and independent scanner enforce scope"}


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
    if context.get("settings"):
        lines.append("settings: " + json.dumps(context["settings"], sort_keys=True))
    for route in task.get("routes", []):
        lines.append(f"route {route['route']}: {route['state']} (T {', '.join(route['required_t'])})")
    found = context["findings"]
    if found:
        lines.append(f"instrument reports {found.get('status')}; where (information, not a fact):")
        lines.extend(f"  {str(d).splitlines()[0][:200]}" for d in found.get("details", [])[:20])
    # Full effective declarations include client conditions whose names differ from Standard's conventions.
    lines.append("The rules in force (socle and client, at this prefix):\n" + json.dumps(context["effective_law"], sort_keys=True))
    lines.append("Admitted grant declarations (the kernel rechecks current rights on submission):\n"
                 + json.dumps(context["grants"], sort_keys=True))
    lines.append(context["authority"])
    return "\n".join(lines)


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
