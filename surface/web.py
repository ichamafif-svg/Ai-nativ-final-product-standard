"""U08 — the web interface (ARCHITECTURE.md §11.9): BUILD and RUN of one installation, reviews to sign, the law.

    python -m surface.web standard.toml [--bind 127.0.0.1] [--port 8080]

It binds to localhost by default: reach it through an SSH tunnel (`ssh -L 8080:localhost:8080 server`) or put a TLS
proxy in front. It holds no key and decides nothing. It reads the installation through the admission gateway (the view,
the facts on exact transitions), plus what is published for people (the instruments' findings, the agent's notes, the
repositories read-only), and forwards to the kernel the envelopes a person signed in their own browser. A person's
private key is imported into their browser and never sent here; the browser builds the bytes it signs from the body it
displays.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from autonomy.projection import Route, project
from trusted.data import EMPTY
from trusted.gateway import GatewayClient
from trusted.recipes import recipes_for

STATIC = Path(__file__).with_name("static")
SHA = re.compile(r"[0-9a-f]{40}")
BRANCH = re.compile(r"([0-9a-f]{40})\trefs/heads/([a-z0-9][a-z0-9_-]{0,63})/(\S+)")
ROUTES = {"RUN": [Route("agent-remediate", "RUN", "repo:*", frozenset({"repair"})),
                  Route("scanner", "RUN", "*", frozenset({"observe", "cover", "prove"}))]}
HOLDERS = {"reviewer": "h3", "officer": "h2"}           # the demo ceremony's grants to people (tools/ceremony.py)
MAX_BODY = 1 << 20


def git(repo, *args, check=True) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=60)
    if check and r.returncode != 0:
        raise RuntimeError(r.stderr.strip()[:300])
    return r.stdout


def _toml(path) -> dict:
    try:
        return tomllib.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}


def _json(path) -> dict:
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}


class Installation:
    """What the interface reads, from one standard.toml."""

    def __init__(self, config_path):
        path = Path(config_path).resolve()
        c, base = tomllib.loads(path.read_text()), path.parent
        resolve = lambda p: (base / p).resolve()
        self.client = GatewayClient(resolve(c["socket"]["path"]))
        repo = c["repository"]
        self.repo = resolve(repo.get("path") or repo.get("mirror"))
        self.inbox = resolve(repo["inbox"]) if repo.get("inbox") else None
        agent = resolve(c.get("agent", {}).get("store", "agent/store")).parent
        self.findings, self.memory, self.proposals = base / "findings.json", agent / "memory.json", agent / "proposals.json"
        self.grants = {name: {"id": gid, "holder": HOLDERS.get(name)} for name, gid in c["grants"].items()
                       if name in HOLDERS}
        self.product = self.repo.name.removesuffix(".git")
        hosted = c.get("hosting", {}).get("config")
        self.products = sorted(_toml(hosted).get("repositories", {})) if hosted else [self.product]

    # ---- the product, whatever it is: requirements by domain and their state ---------------------------------
    def requirements(self, view: dict, findings: dict) -> list:
        """One line per requirement of the effective law. held: proven or measured as expected; gap: measured off;
        unmeasured: no instrument could cover it here; attest: waits for a person's attestation; escalated: past due."""
        health = view["health"]
        proven = {p.get("target") for p in health["proven"]}
        escalated = {e.get("target") for e in health["escalated"]}
        opened = {o.get("target") for o in health["open"]}
        autonomous = set(recipes_for(EMPTY))
        out = []
        for t in view["law"]["effective"]["targets"]:
            f = findings.get(f"{t['resource']}|{t['property']}")
            status = f["status"] if f else None
            if t["id"] in escalated:
                state = "escalated"
            elif status == t["expect"] or (t["id"] in proven and t["id"] not in opened):
                state = "held"
            elif status and status.startswith("uncovered"):
                state = "unmeasured"
            elif status:
                state = "gap"
            elif t["resource"].startswith("org:") or t.get("human"):
                state = "attest"
            else:
                state = "pending"
            who = ("people" if t.get("human") or t["resource"].startswith("org:") else
                   "agent" if t["id"] in autonomous else "review" if t.get("repair") == "remediate" else "agent")
            out.append({"id": t["id"], "domain": t["resource"].split(":")[1], "resource": t["resource"],
                        "property": t["property"], "expect": t["expect"], "measured": status, "state": state,
                        "who": who, "where": [d.splitlines()[0][:200] for d in (f or {}).get("details", [])[:8]]})
        return out

    # ---- RUN: the product in production, maintained -----------------------------------------------------------
    def run(self, view: dict, findings: dict) -> dict:
        plan = project(view, ROUTES["RUN"], self.client.qualify, mode="RUN")
        targets = {t["id"]: t for t in view["law"]["effective"]["targets"]}
        repairs = []
        for p in _json(self.proposals).values():
            t = targets.get(p["target"], {})
            transition = f"repo:{p['area']}:{p['item']}/{p['base']}/{p['head']}"
            facts = view["transitions"].get(transition, {})
            repairs.append({**p, "requirement": f"{t.get('property')} = {t.get('expect')}", "facts": facts,
                            "resource": transition, "kind": "repair",
                            "awaiting_review": p["route"] == "review" and facts.get("tests") == "green"
                            and facts.get("review") != "approved"})
        gaps = []
        for t in targets.values():
            f = findings.get(f"{t['resource']}|{t['property']}")
            if f and f["status"] != t["expect"]:
                gaps.append({"target": t["id"], "resource": t["resource"], "expect": t["expect"],
                             "status": f["status"], "where": [d.splitlines()[0][:200] for d in f["details"][:8]],
                             "autonomous": t.get("repair") == "remediate" and t["id"] in ("sbom", "vulns", "actions"),
                             "human": bool(t.get("human"))})
        abandoned = [{"target": k, "dossier": v["abandoned"]["dossier"], "base": v["abandoned"]["base"]}
                     for k, v in _json(self.memory).items() if v.get("abandoned")]
        return {"tasks": plan["tasks"], "state": plan["state"], "gaps": sorted(gaps, key=lambda g: g["target"]),
                "repairs": repairs, "abandoned": abandoned}

    # ---- BUILD: the product being built ----------------------------------------------------------------------
    def build(self, view: dict, findings: dict, main: str) -> dict:
        contributions = []
        if self.inbox:
            for line in git(self.repo, "ls-remote", str(self.inbox), "refs/heads/*", check=False).splitlines():
                m = BRANCH.fullmatch(line)
                if not m:
                    continue
                head, author, branch = m.groups()
                facts = next((f for r, f in view["transitions"].items()
                              if r.startswith(f"repo:contrib:{author}/") and r.endswith(f"/{head}")), {})
                resource = next((r for r in view["transitions"] if r.startswith(f"repo:contrib:{author}/")
                                 and r.endswith(f"/{head}")), f"repo:contrib:{author}/{main}/{head}")
                base = resource.split("/")[1]
                landed = subprocess.run(["git", "-C", str(self.repo), "merge-base", "--is-ancestor", head, "main"],
                                        capture_output=True, timeout=60).returncode == 0
                blocked = [p for p, bad in (("tests", facts.get("tests") not in (None, "green")),
                                            ("regressions", facts.get("regressions") not in (None, "none"))) if bad]
                contributions.append({
                    "author": author, "branch": branch, "head": head, "base": base, "resource": resource,
                    "facts": facts, "kind": "contribution", "landed": landed, "stale": base != main and not landed,
                    "blocked": blocked,
                    "why": [d.splitlines()[0][:200] for p in blocked
                            for d in findings.get(f"{resource}|{p}", {}).get("details", [])[:5]],
                    "awaiting_review": not landed and not blocked and facts.get("tests") == "green"
                    and facts.get("regressions") == "none" and facts.get("review") != "approved"})
        return {"contributions": contributions, "requests": []}

    def history(self, limit: int = 20) -> list:
        out = git(self.repo, "log", f"-{limit}", "--format=%H%x09%an%x09%at%x09%s", "main", check=False)
        return [dict(zip(("sha", "author", "at", "subject"), line.split("\t", 3))) for line in out.splitlines()]

    def state(self) -> dict:
        view = self.client.view()
        findings = _json(self.findings)
        main = git(self.repo, "rev-parse", "main").strip()
        law = view["law"]["effective"]
        health = view["health"]
        return {
            "prefix": view["prefix"], "assessment": view["assessment"], "law_digest": view["law"]["digest"],
            "health": {"state": health["state"], "open": len(health["open"]), "escalated": health["escalated"],
                       "proven": len(health["proven"]), "as_of": health["as_of"]},
            "main": main, "history": self.history(),
            "product": self.product, "products": self.products,
            "requirements": self.requirements(view, findings),
            "run": self.run(view, findings), "build": self.build(view, findings, main),
            "law": {"targets": [{k: t.get(k) for k in ("id", "resource", "property", "expect", "coverage", "repair",
                                                        "human", "due_ms")} for t in law["targets"]],
                    "conditions": law["conditions"], "ops": sorted(law["ops"])},
            "signing": {"domain": view["prefix"]["genesis"], "as_of": health["as_of"], "grants": self.grants},
        }

    def dossier(self, head: str) -> dict:
        if not SHA.fullmatch(head):
            raise ValueError("a commit is 40 hex characters")
        return {"head": head, "message": git(self.repo, "log", "-1", "--format=%an <%ae>%n%n%B", head),
                "diff": git(self.repo, "show", "--stat", "--patch", "--format=", head)[:120_000]}


def handler(inst: Installation):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Standard"

        def log_message(self, fmt, *args):
            sys.stderr.write("web: " + fmt % args + "\n")

        def _send(self, status, body: bytes, kind: str):
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                                                        "img-src 'self' data:; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def _ok(self, value, status=HTTPStatus.OK):
            self._send(status, json.dumps(value).encode(), "application/json")

        def do_GET(self):
            route = self.path.split("?", 1)[0]
            try:
                if route in ("/", "/index.html"):
                    return self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
                if route in ("/sign.js", "/app.js"):
                    return self._send(200, (STATIC / route[1:]).read_bytes(), "text/javascript; charset=utf-8")
                if route == "/app.css":
                    return self._send(200, (STATIC / "app.css").read_bytes(), "text/css; charset=utf-8")
                if route == "/api/state":
                    return self._ok(inst.state())
                if route.startswith("/api/dossier/"):
                    return self._ok(inst.dossier(route.rsplit("/", 1)[1]))
                return self._ok({"error": "not found"}, HTTPStatus.NOT_FOUND)
            except ValueError as exc:
                return self._ok({"error": str(exc)[:200]}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:                       # unreachable or unqualified: say so, attest nothing
                return self._ok({"error": f"{type(exc).__name__}: {exc}"[:400]}, HTTPStatus.SERVICE_UNAVAILABLE)

        def do_POST(self):
            if self.path != "/api/admit":
                return self._ok({"error": "not found"}, HTTPStatus.NOT_FOUND)
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return self._ok({"error": "application/json only"}, HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
            size = int(self.headers.get("Content-Length") or 0)
            if not 0 < size <= MAX_BODY:
                return self._ok({"error": "bad length"}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            try:
                envelope = json.loads(self.rfile.read(size))
                return self._ok({"admitted": inst.client.admit(envelope)})
            except Exception as exc:
                return self._ok({"refused": getattr(exc, "code", None) or str(exc)[:300]}, HTTPStatus.CONFLICT)
    return Handler


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m surface.web")
    parser.add_argument("config")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)
    inst = Installation(args.config)
    server = ThreadingHTTPServer((args.bind, args.port), handler(inst))
    print(f"Standard interface on http://{args.bind}:{args.port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
