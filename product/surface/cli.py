"""U08 — the entry point for agents and humans (ARCHITECTURE.md §11.5).

    python -m product.surface [--socket PATH] status            the verdict and what is known at the current prefix
    python -m product.surface [--socket PATH] tasks             the work the law asks for, most urgent first
    python -m product.surface [--socket PATH] context TASK_ID   one task: its debt, its law, the T its routes need
    python -m product.surface [--socket PATH] law SECTION/ID    one declaration of the effective law (floors or client)
    python -m product.surface review TARGET BASE HEAD --identity ID --key FILE --under GRANT [--changes-requested]
    python -m product.surface attest TARGET --identity ID --key FILE --under GRANT
    python -m product.surface set SCOPE/KEY VALUE --identity ID --key FILE --under GRANT    a production setting (D31), e.g.
                                                    set global/objective 99.95 ; set c-1a2b3c4d5e6f/p99_ms 250
    python -m product.surface decide RESOURCE PROPERTY --identity ID --key FILE --under GRANT    an engineer's decision, e.g.
                                                    decide run:release:all/FROM/TO approved
    python -m product.surface dossier HEAD --repo PATH          what a reviewer reads before signing: the agent's dossier

`--findings FILE` adds the instruments' findings (where the gap is) to `context`; `--memory FILE` adds to `tasks` the
obligations the agent gave up on. Both are information, never facts.

Plain text bound to the prefix and the law digest. It reads through the admission gateway only: nothing printed
here is a permission, and a signed envelope is the only thing an agent can submit.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from product.autonomy.projection import Route, project
from bt.gateway import GatewayClient

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


def context(view: dict, plan: dict, task_id: str, findings: dict | None = None) -> str:
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
    if target and findings is not None:
        found = findings.get(f"{target['resource']}|{target['property']}")
        if found:
            lines.append(f"instrument reports {found['status']}; where (information, not a fact):")
            lines += [f"  {d.splitlines()[0][:200]}" for d in found["details"][:20]]
    lines.append("submit only a signed envelope; the kernel decides.")
    return "\n".join(lines)


def dossier(repo, head: str) -> str:
    import subprocess
    git = lambda *a: subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, check=True).stdout
    return git("log", "-1", "--format=%H%n%an <%ae>%n%n%B", head) + git("show", "--stat", "--format=", head)


def abandoned(memory: dict) -> str:
    gone = {t: m["abandoned"] for t, m in memory.items() if m.get("abandoned")}
    if not gone:
        return ""
    return "\nthe agent gave up on (people must decide):\n" + "\n".join(
        f"  {t} on {a['base'][:12]}:\n    " + a["dossier"].replace("\n", "\n    ")[:1500] for t, a in sorted(gone.items()))


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
    parser = argparse.ArgumentParser(prog="python -m product.surface")
    parser.add_argument("--socket", default=DEFAULT_SOCKET)
    parser.add_argument("command", choices=("status", "tasks", "context", "law", "review", "attest", "dossier", "set",
                                                       "decide"))
    parser.add_argument("ref", nargs="?")
    parser.add_argument("base", nargs="?")
    parser.add_argument("head", nargs="?")
    parser.add_argument("--identity")
    parser.add_argument("--key")
    parser.add_argument("--under")
    parser.add_argument("--changes-requested", action="store_true")
    parser.add_argument("--findings")
    parser.add_argument("--memory")
    parser.add_argument("--repo")
    args = parser.parse_args(argv)
    if args.command == "dossier":
        print(dossier(args.repo or ".", args.ref or "HEAD"))
        return 0
    client = GatewayClient(args.socket)
    try:
        view = client.view()
    except Exception as exc:
        print(f"Standard is not reachable or not qualified here ({exc}). Nothing is attested or authorized.")
        return 2
    if args.command in ("set", "decide"):                 # the same signed statements the interface makes (D31)
        from .human import _observation, load_signer
        signer = load_signer(args.identity, args.key)
        resource, prop, status = ((f"run:policy/{args.ref}", "value", args.base) if args.command == "set"
                                  else (args.ref, args.base, "yes"))
        try:
            print(json.dumps(client.admit(_observation(view, signer, args.under, resource, prop, status, None))))
        except Exception as exc:
            print(f"refused: {exc}")
            return 1
        return 0
    if args.command in ("review", "attest"):
        from .human import attest, load_signer, review
        signer = load_signer(args.identity, args.key)
        statement = (review(view, signer, args.under, args.ref, args.base, args.head,
                            "changes_requested" if args.changes_requested else "approved")
                     if args.command == "review" else attest(view, signer, args.under, args.ref))
        try:
            print(json.dumps(client.admit(statement)))
        except Exception as exc:
            print(f"refused: {exc}")
            return 1
        return 0
    plan = project(view, DEFAULT_ROUTES, client.qualify)
    if args.command == "status":
        print(status(view))
    elif args.command == "tasks":
        print(tasks(view, plan) + (abandoned(json.loads(open(args.memory).read())) if args.memory else ""))
    elif args.command == "context":
        print(context(view, plan, args.ref or (plan["tasks"][0]["id"] if plan["tasks"] else ""),
                      json.loads(open(args.findings).read()) if args.findings else None))
    else:
        print(declaration(view, args.ref or ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
