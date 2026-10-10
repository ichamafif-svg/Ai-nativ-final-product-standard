"""U08 — the entry point for agents and humans (ARCHITECTURE.md §11.5).

    python -m surface [--socket PATH] status            the verdict and what is known at the current prefix
    python -m surface [--socket PATH] tasks             the work the law asks for, most urgent first
    python -m surface [--socket PATH] context TASK_ID   one task: its debt, its law, the T its routes need
    python -m surface [--socket PATH] law SECTION/ID    one declaration of the effective law (floors or client)

Plain text bound to the prefix and the law digest. It reads through the admission gateway only: nothing printed
here is a permission, and a signed envelope is the only thing an agent can submit.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from autonomy.projection import Route, project
from trusted.gateway import GatewayClient

DEFAULT_SOCKET = os.environ.get("STANDARD_SOCKET", "/run/standard/admission.sock")
DEFAULT_ROUTES = [Route("agent-remediate", "RUN", "repo:*", frozenset({"repair"})),
                  Route("scanner", "RUN", "*", frozenset({"observe", "cover", "prove"}))]


def _header(view: dict) -> str:
    p = view["prefix"]
    return f"prefix {p['size']} · head {p['head'][:19]}… · law {view['law']['digest'][:19]}…"


def status(view: dict) -> str:
    h = view["health"]
    lines = [_header(view), f"state: {h['state']}  ·  proven {len(h['proven'])}  ·  open {len(h['open'])}  ·  "
             f"escalated {len(h['escalated'])}"]
    for item in h["escalated"]:
        lines.append(f"  ESCALATED {item['obligation']} (due {item['due']}) → {', '.join(item['escalated_to'])}")
    for item in h.get("retired", []):
        lines.append(f"  RETIRED   {item['subject']}: {item['status']}")
    return "\n".join(lines)


def tasks(view: dict, plan: dict) -> str:
    lines = [_header(view)]
    for t in plan["tasks"]:
        flag = "!" if t["escalated"] else " "
        lines.append(f"{flag} {t['state']:13} {t['id']:40} {t['need']:8} {t['resource']}  due {t['due']}")
    return "\n".join(lines) if plan["tasks"] else lines[0] + "\nno open work"


def context(view: dict, plan: dict, task_id: str) -> str:
    task = next((t for t in plan["tasks"] if t["id"] == task_id), None)
    if task is None:
        return f"no task {task_id} at this prefix"
    law = view["law"]["effective"]
    target = next((t for t in law["targets"] if t["id"] == task["target"]), None)
    lines = [_header(view), f"task {task['id']}: {task['need']} {task['resource']}",
             f"opened {task['opened']}, due {task['due']}{' (escalated)' if task['escalated'] else ''}"]
    if target:
        lines.append(f"requirement: {target['property']} = {target['expect']} at level {target['min_level']}, "
                     f"fresh {target['fresh_ms']} ms, sources {', '.join(target['sources'])}")
        if target.get("repair"):
            op = law["ops"][target["repair"]]
            lines.append(f"repair op: {target['repair']} on {op['resource']} ({op['profile']}), "
                         f"T: {', '.join(sorted(set(op.get('trusted', [])) | {'T07', 'T08'}))}")
            for name, cond in law["conditions"].items():
                if name.startswith(target["repair"]):
                    lines.append(f"  condition {name}: {json.dumps(cond['all'])}")
    for c in task["routes"]:
        lines.append(f"route {c['route']}: {c['state']} (T {', '.join(c['required_t'])})")
    lines.append("submit only a signed envelope; the kernel decides.")
    return "\n".join(lines)


def declaration(view: dict, ref: str) -> str:
    section, _, ident = ref.partition("/")
    law = view["law"]["effective"]
    value = law.get(section)
    if isinstance(value, list):
        value = next((x for x in value if x.get("id") == ident), None)
    elif isinstance(value, dict) and ident:
        value = value.get(ident)
    return _header(view) + "\n" + (json.dumps(value, indent=2, sort_keys=True) if value is not None else f"no {ref}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m surface")
    parser.add_argument("--socket", default=DEFAULT_SOCKET)
    parser.add_argument("command", choices=("status", "tasks", "context", "law"))
    parser.add_argument("ref", nargs="?")
    args = parser.parse_args(argv)
    client = GatewayClient(args.socket)
    try:
        view = client.view()
    except Exception as exc:
        print(f"Standard is not reachable or not qualified here ({exc}). Nothing is attested or authorized.")
        return 2
    plan = project(view, DEFAULT_ROUTES, client.qualify)
    if args.command == "status":
        print(status(view))
    elif args.command == "tasks":
        print(tasks(view, plan))
    elif args.command == "context":
        print(context(view, plan, args.ref or (plan["tasks"][0]["id"] if plan["tasks"] else "")))
    else:
        print(declaration(view, args.ref or ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
