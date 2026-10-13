"""U08 — the entry point for the agent and the human (ARCHITECTURE.md §11.5).

Reading (through the admission gateway, bound to the prefix and the rules' digest):

    python -m standard.surface [--socket PATH] status            the verdict and what is known at the current prefix
    python -m standard.surface [--socket PATH] moves             every move of the game and who plays next
    python -m standard.surface [--socket PATH] queue             what waits for the human's decision
    python -m standard.surface [--socket PATH] tasks             the work the debts ask for, most urgent first
    python -m standard.surface [--socket PATH] context TASK_ID   one task: its debt, its routes, the T they need
    python -m standard.surface [--socket PATH] drift [TARGET]    gap/drift dossiers: target, finding, route and proof
    python -m standard.surface [--socket PATH] patrol [FOCUS]    exploratory patrol context, wide or targeted
    python -m standard.surface [--socket PATH] read-model [--repo PATH] whole derived reading graph
    python -m standard.surface [--socket PATH] law SECTION/ID    one declaration of the rules in force
    python -m standard.surface dossier HEAD --repo PATH          what the human reads before saying yes

The human's three gestures (--identity ID --key FILE; yes also needs --under GRANT):

    python -m standard.surface yes RESOURCE                      yes to one move, on its exact resource
    python -m standard.surface no SCOPE                          freeze a move or a scope (run:release:* stops deploys)
    python -m standard.surface release SCOPE                     lift a no
    python -m standard.surface rules set KEY VALUE               change one setting of the rules
    python -m standard.surface rules route OP ROUTE on|off       give an autonomous route to the agent, or take it back

`--findings FILE` adds the instruments' findings (where the gap is); `--memory FILE` adds to `tasks` the obligations
the agent gave up on. Both are information, never facts. Nothing printed is a permission: the kernel decides.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

from standard.autonomy.projection import installed_routes
from standard.autonomy.context import render_context, task_context
from standard.autonomy.drift_map import gap_dossiers
from standard.autonomy.moves import moves
from standard.autonomy.patrol import patrol_context
from standard.autonomy.read_model import ReadModel
from bt.gateway import GatewayClient

DEFAULT_SOCKET = os.environ.get("STANDARD_SOCKET", "/run/standard/admission.sock")
DEFAULT_ROUTES = installed_routes()


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


def context(view: dict, plan: dict, task_id: str, findings: dict | None = None, model: ReadModel | None = None) -> str:
    task = next((t for t in plan["tasks"] if t["id"] == task_id), None)
    if task is None:
        return f"no task {task_id} at this prefix"
    return render_context(task_context(view, task, findings, model=model))


def board(view: dict, rows: list, empty: str) -> str:
    """Moves, one per line: status, op, resource, and what is missing or why it cannot be played."""
    lines = [_header(view)]
    for m in rows:
        why = "; ".join(m["refuted"] or m["missing"]) or (f"route {m['route']}" if m["route"] else "")
        lines.append(f"{m['status']:9} {m['op']:9} {m['resource']}  {why}")
    return "\n".join(lines) if rows else lines[0] + "\n" + empty


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


def drift(view: dict, routes, qualify, findings: dict, ref: Optional[str] = None,
          model: ReadModel | None = None) -> str:
    dossiers = gap_dossiers(view, findings, routes, qualify, model=model)
    if ref:
        dossiers = [d for d in dossiers if d["id"] == ref]
    return _header(view) + "\n" + json.dumps(dossiers, indent=2, sort_keys=True)


def patrol(view: dict, routes, qualify, findings: dict, ref: Optional[str] = None,
           model: ReadModel | None = None) -> str:
    context = patrol_context(view, findings, routes, qualify, focus=ref, model=model)
    return _header(view) + "\n" + json.dumps(context, indent=2, sort_keys=True)


def gesture(view: dict, args) -> dict:
    """The signed statement of one of the human's gestures."""
    from standard.autonomy.rules import change
    from .human import decide, load_signer, refuse, release, rules
    signer = load_signer(args.identity, args.key)
    what = args.args
    if args.command == "yes":
        return decide(view, signer, args.under, what[0])
    if args.command == "no":
        return refuse(view, signer, what[0])
    if args.command == "release":
        return release(view, signer, what[0])
    client = view["law"]["client"]
    if what[:1] == ["set"] and len(what) == 3:
        return rules(view, signer, change(client, settings={what[1]: what[2]}))
    if what[:1] == ["route"] and len(what) == 4 and what[3] in ("on", "off"):
        op, route = what[1], what[2]
        kept = set(client.get("routes", {}).get(op, [r for r in view["law"]["effective"]["ops"][op]["routes"]
                                                     if r != "human"]))
        kept = kept | {route} if what[3] == "on" else kept - {route}
        return rules(view, signer, change(client, routes={op: sorted(kept)}))
    raise ValueError("rules set KEY VALUE | rules route OP ROUTE on|off")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m standard.surface")
    parser.add_argument("--socket", default=DEFAULT_SOCKET)
    parser.add_argument("command", choices=("status", "moves", "queue", "tasks", "context", "drift", "patrol",
                                            "read-model", "law", "dossier", "yes", "no", "release", "rules"))
    parser.add_argument("args", nargs="*")
    parser.add_argument("--identity")
    parser.add_argument("--key")
    parser.add_argument("--under")
    parser.add_argument("--findings")
    parser.add_argument("--memory")
    parser.add_argument("--repo")
    args = parser.parse_args(argv)
    ref = args.args[0] if args.args else None
    if args.command == "dossier":
        print(dossier(args.repo or ".", ref or "HEAD"))
        return 0
    client = GatewayClient(args.socket)
    try:
        view = client.view()
    except Exception as exc:
        print(f"Standard is not reachable or not qualified here ({exc}). Nothing is attested or authorized.")
        return 2
    if args.command in ("yes", "no", "release", "rules"):
        try:
            print(json.dumps(client.admit(gesture(view, args))))
        except Exception as exc:
            print(f"refused: {exc}")
            return 1
        return 0
    findings = json.loads(open(args.findings).read()) if args.findings else {}
    code_index = None
    if args.command == "read-model" and args.repo:
        from instruments.tree import Snapshot
        from standard.autonomy.repomap import RepoMap
        import subprocess
        main = subprocess.run(["git", "-C", args.repo, "rev-parse", "main"], check=True,
                              capture_output=True, text=True).stdout.strip()
        code_index = RepoMap(Snapshot(args.repo, main))
    else:
        main = None
    model = ReadModel(view, findings, DEFAULT_ROUTES, client.qualify, main=main, code_index=code_index)
    plan = model.plan()
    if args.command == "status":
        print(status(view))
    elif args.command == "moves":
        print(board(view, moves(view), "no move"))
    elif args.command == "queue":
        print(board(view, [m for m in moves(view) if m["status"] == "yours" and m["wanted"]], "nothing waits for you"))
    elif args.command == "tasks":
        print(tasks(view, plan) + (abandoned(json.loads(open(args.memory).read())) if args.memory else ""))
    elif args.command == "context":
        print(context(view, plan, ref or (plan["tasks"][0]["id"] if plan["tasks"] else ""), findings, model))
    elif args.command == "drift":
        print(drift(view, DEFAULT_ROUTES, client.qualify, findings, ref, model))
    elif args.command == "patrol":
        print(patrol(view, DEFAULT_ROUTES, client.qualify, findings, ref, model))
    elif args.command == "read-model":
        print(json.dumps(model.graph(), indent=2, sort_keys=True))
    else:
        print(declaration(view, ref or ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
