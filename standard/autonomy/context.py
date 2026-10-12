"""One contextual surface for humans and agents, derived from the checked view, never an authority."""
from __future__ import annotations

import json


def task_context(view: dict, task: dict, findings=None) -> dict:
    law = view["law"]["effective"]
    target = next((t for t in law.get("targets", []) if t["id"] == task.get("target")), None)
    operation = law.get("ops", {}).get(task.get("op") or (target or {}).get("repair"))
    return {"basis": view["prefix"], "law_digest": view["law"].get("digest"), "task": task,
            "requirement": target, "operation": operation, "effective_law": law,
            "assessment": view.get("assessment"), "entity": view.get("entities", {}).get(task["resource"]),
            "grants": view.get("grants", {}),
            "facts": [f for f in view.get("facts", []) if f.get("resource") == task["resource"]],
            "findings": (findings or {}).get(f"{task['resource']}|{(target or {}).get('property')}", {}),
            "authority": "Information only. Submit signed statements; the kernel decides. Agent work cannot certify a fact."}


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
