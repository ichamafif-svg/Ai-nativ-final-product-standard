"""U08 — the web console (ARCHITECTURE.md §11.9): the game as the human sees it, BUILD and RUN of one installation.

The human's queue (the moves only their decision can play), yes and no on each move, the rules of the game to edit and
sign, production and the product being built.

    python -m surface.web standard.toml [--bind 127.0.0.1] [--port 8080]

It binds to localhost by default: reach it through an SSH tunnel (`ssh -L 8080:localhost:8080 server`) or put a TLS
proxy in front. It holds no key and decides nothing. It reads the installation through the admission gateway (the view,
the facts on exact transitions), plus what is published for people (the instruments' findings, the agent's notes, the
repositories read-only), and forwards to the kernel the envelopes the human signed in their own browser. The
human's private key is imported into their browser and never sent here; the browser builds the bytes it signs from
the body it displays: a decision, a freeze, or the full new rules the console drafted for them.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import tomllib
from blocks.python.standard_blocks import log
from blocks.python.standard_blocks.parse import strict_json
from bt.gateway import GatewayClient
from context.missions import task_context
from context.missions import gap_dossiers
from context.moves import moves
from agent.work import installed_routes
from context.model import ReadModel
from agent.work import WorkEngine
from surface import views as read_views
from surface.views import agent_context as build_agent_context
from surface.views import git

STATIC = Path(__file__).with_name("static")
SHA = re.compile(r"[0-9a-f]{40}")
MAX_BODY = 1 << 20


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
        self.routes = installed_routes(c.get("agent", {}).get("scopes", ()),
                                       model=bool(c.get("llm") or c.get("agent", {}).get("api_key_file")))
        resolve = lambda p: (base / p).resolve()
        self.client = GatewayClient(resolve(c["socket"]["path"]))
        repo = c["repository"]
        self.repo = resolve(repo.get("path") or repo.get("mirror"))
        self.inbox = resolve(repo["inbox"]) if repo.get("inbox") else None
        agent = resolve(c.get("agent", {}).get("store", "agent/store")).parent
        self.findings, self.memory, self.proposals = base / "findings.json", agent / "memory.json", agent / "proposals.json"
        self.work_db = agent / "work.db"
        self.grant_ids = {name: gid for name, gid in c["grants"].items() if name == "human"}
        self.product = self.repo.name.removesuffix(".git")
        run = c.get("run", {})
        from surface.telemetry import Telemetry
        self.telemetry = Telemetry(Path(run.get("store", Path.home() / ".standard" / "telemetry.db")).expanduser(),
                                   base / "readings", slo=float(run.get("slo", 99.9)) / 100,
                                   interval=float(run.get("interval", 15)))
        self.rollback = bool(c.get("deploy")) and "agent" in c["grants"]     # D30: can act in production
        self.slo_db = base / "slo.db"
        self.requests = resolve(c.get("build", {}).get("store", "requests"))          # D34: specs and contracts
        self.request_notes, self.moves_notes = agent / "requests.json", agent / "moves.json"
        self.telemetry.extra = self.burning
        self.deploy_root = resolve(c["deploy"]["root"]) if c.get("deploy") else None
        hosted = c.get("hosting", {}).get("config")
        self.products = sorted(_toml(hosted).get("repositories", {})) if hosted else [self.product]

    def people(self, view: dict | None = None) -> dict:
        """The human's capability, with the holder the admitted journal names (never a hard-coded identity)."""
        grants = (view or self.client.view()).get("grants", {})
        return {name: {"id": gid, "holder": grants.get(gid, {}).get("holder")} for name, gid in self.grant_ids.items()}

    # ---- the product, whatever it is: requirements by domain and their state ---------------------------------
    def requirements(self, view: dict, findings: dict, model: ReadModel | None = None) -> list:
        model = model or ReadModel(view, findings)
        model.assert_view(view)
        return read_views.requirements(model)

    # ---- RUN: the product in production, maintained -----------------------------------------------------------
    def context(self, task_id: str) -> dict:
        view, findings = self.client.view(), _json(self.findings)
        main = git(self.repo, "rev-parse", "main").strip()
        model = self.read_model(view, findings, main)
        plan = model.plan()
        task = next((t for t in plan["tasks"] if t["id"] == task_id), None)
        if task is None:
            raise ValueError("no task at this prefix")
        return task_context(view, task, model=model)

    def agent_context(self, kind: str, ident: str) -> dict:
        """A human-readable dossier for the same context an agent works under. It is not authority."""
        from instruments.tree import GitTree
        view, findings = self.client.view(), _json(self.findings)
        main = git(self.repo, "rev-parse", "main").strip()
        model = self.read_model(view, findings, main)
        return build_agent_context(kind, ident, view=view, findings=findings, routes=self.routes,
                                   qualify=self.client.qualify, requests=self.requests, main=main, model=model,
                                   tree=GitTree(self.repo, main) if kind == "patrol" else None)

    def read_model(self, view: dict, findings: dict, main: str) -> ReadModel:
        return ReadModel(view, findings, self.routes, self.client.qualify, main=main,
                         inputs=self.surface_inputs(main, findings))

    def surface_inputs(self, main: str, findings: dict) -> dict:
        import hashlib
        content = json.dumps(findings, sort_keys=True, separators=(",", ":"), default=str).encode()
        return {"findings": {"kind": "diagnostic_document", "digest": "sha256:" + hashlib.sha256(content).hexdigest(),
                             "association_to_prefix": "unverified"}}

    def run(self, view: dict, findings: dict, model: ReadModel | None = None) -> dict:
        model = model or ReadModel(view, findings, self.routes, self.client.qualify)
        model.assert_view(view)
        return read_views.run(model, _json(self.proposals), _json(self.memory))

    # ---- BUILD: the product being built ----------------------------------------------------------------------
    def build(self, view: dict, findings: dict, main: str, model: ReadModel | None = None) -> dict:
        model = model or ReadModel(view, findings, main=main)
        model.assert_view(view)
        return read_views.build(model, self.repo, self.inbox, self.requests, _json(self.request_notes), main)

    def requests_of(self, view: dict, findings: dict, main: str, model: ReadModel | None = None) -> list:
        model = model or ReadModel(view, findings, main=main)
        model.assert_view(view)
        return read_views.requests_of(model, self.repo, self.requests, _json(self.request_notes), main)

    def draft_rules(self, body: dict) -> dict:
        """The full new rules for the human to sign: the rules in force with these changes, each value checked against
        its schema. The kernel judges the signed rules against the socle; this only drafts."""
        from context.policy import change
        view = self.client.view()
        drop = [tuple(x) for x in body.get("drop", []) if isinstance(x, list) and len(x) == 2]
        client = change(view["law"]["client"], settings=body.get("settings"), routes=body.get("routes"),
                        sections=body.get("sections"), drop=drop, values=body.get("values"))
        return {"client": client, "domain": view["prefix"]["genesis"], "as_of": view["health"]["as_of"]}

    def store_request(self, body: dict) -> dict:
        """Keep a request's specification and contract by digest; the person then signs the digests."""
        import hashlib
        out = {}
        for key in ("spec", "contract"):
            data = str(body.get(key, "")).encode()
            if not data or len(data) > 200_000:
                raise ValueError(f"{key} is between 1 byte and 200 kB")
            digest = hashlib.sha256(data).hexdigest()
            self.requests.mkdir(parents=True, exist_ok=True)
            (self.requests / digest).write_bytes(data)
            out[key] = f"sha256:{digest}"
        return out

    def history(self, limit: int = 20) -> list:
        out = git(self.repo, "log", f"-{limit}", "--format=%H%x09%an%x09%at%x09%s", "main", check=False)
        return [dict(zip(("sha", "author", "at", "subject"), line.split("\t", 3))) for line in out.splitlines()]

    def state(self) -> dict:
        view = self.client.view()
        findings = _json(self.findings)
        main = git(self.repo, "rev-parse", "main").strip()
        model = self.read_model(view, findings, main)
        law = view["law"]["effective"]
        health = view["health"]
        played = moves(view, main=main)
        return {
            "prefix": view["prefix"], "assessment": view["assessment"], "law_digest": view["law"]["digest"],
            "health": {"state": health["state"], "open": len(health["open"]), "escalated": health["escalated"],
                       "proven": len(health["proven"]), "as_of": health["as_of"]},
            "main": main, "history": self.history(),
            "product": self.product, "products": self.products,
            "requirements": (reqs := self.requirements(view, findings, model)),
            "autonomy": self.autonomy(reqs),
            "drift": gap_dossiers(view, model=model),
            "moves": played, "queue": [m for m in played if m["status"] == "yours" and m["wanted"]],
            "run": self.run(view, findings, model), "build": self.build(view, findings, main, model),
            "progress": WorkEngine.read_progress(self.work_db),
            "law": {"targets": [{k: t.get(k) for k in ("id", "resource", "property", "expect", "coverage", "repair",
                                                        "human", "due_ms")} for t in law["targets"]],
                    "routes": {op: sorted(spec["routes"]) for op, spec in law["ops"].items()}},
            "signing": {"domain": view["prefix"]["genesis"], "as_of": health["as_of"], "grants": self.people(view)},
        }

    def autonomy(self, requirements: list) -> dict:
        """What Standard does without the human, requirement by requirement, under the rules in force, and why not more.

        autonomous: an autonomous route of the rules holds on the scanner's facts, the agent lands it alone;
        decision: the rules keep the move for the human: the agent proposes, the human says yes or no;
        human: no move of the rules reaches it (a provider's settings): the human repairs it;
        observed: Standard measures, nobody acts through it on this installation."""
        why = {
            "autonomous": "Une route automatique des règles tient sur les faits du scanner : l'agent joue seul, dans le périmètre.",
            "decision": "Les règles gardent ce coup pour toi : l'agent prépare, tu dis oui ou non.",
            "human": "Aucun coup des règles n'y touche (un réglage du fournisseur) : c'est toi qui répares.",
            "observed": "Standard mesure ce composant mais n'agit pas dessus : aucune mise en production ne lui est confiée sur "
                        "cette installation (section [deploy]).",
        }
        why["acting"] = ("Standard met main en production et revient seul à la version précédente dans les bornes des "
                         "règles, sur des faits signés par le scanner, comme les changements de code.")
        rows = []
        for r in requirements:
            lv = r["level"] if r["level"] in ("autonomous", "decision", "human") else "observed"
            production = r["resource"].startswith("run:") and lv == "autonomous"
            rows.append({"id": r["id"], "level": lv, "why": why["acting"] if production else why[lv],
                         "blocked": "Non mesurée sur cette installation : aucune autonomie possible tant que rien ne la mesure."
                         if r["state"] == "unmeasured" else None})
        count = {lv: sum(1 for x in rows if x["level"] == lv) for lv in ("autonomous", "decision", "human")}
        runtime = {"level": "autonomous", "why": why["acting"]} if self.rollback else {"level": "observed",
                                                                                         "why": why["observed"]}
        return {"levels": why, "requirements": rows, "count": count, "total": len(rows), "runtime": runtime}

    def run_report(self, window: int) -> dict:
        """The product in production: its APIs and their metrics, and the latest releases."""
        openapi = git(self.repo, "show", "main:openapi.json", check=False)
        from surface.telemetry import declared_routes
        findings, view = _json(self.findings), self.client.view()
        policy = self.settle(view)
        report = self.telemetry.report(declared_routes(openapi), window=window)
        self.frontier(report, findings, policy)
        report["burn"] = self.burn()
        return {**report, "product": self.product, "releases": self.history(8),
                "live": self.live(findings, view), "openapi": bool(openapi.strip())}

    BURN = ((300, 14.4, "page"), (3600, 6.0, "ticket"))   # SRE workbook: budget spent 14.4x / 6x too fast

    def burn(self) -> list:
        """Error-budget burn rate over short and long windows: the rate the budget is spent at, 1 = exactly on budget."""
        out = []
        for seconds, threshold, action in self.BURN:
            fleet = self.telemetry.report(window=seconds)["fleet"]
            er = fleet["error_rate"]
            rate = None if er is None else er / max(1 - self.telemetry.slo, 1e-9)
            out.append({"window": seconds, "rate": rate, "threshold": threshold, "action": action,
                        "firing": rate is not None and rate >= threshold, "requests": fleet["requests"]})
        return out

    def facts(self) -> dict:
        """The latest signed facts of the journal, as an engineer greps them: resource, property, status, who, when."""
        view = self.client.view()
        return {"facts": view.get("facts", []), "prefix": view["prefix"], "law": view["law"]["digest"]}

    def settle(self, view: dict | None = None):
        """The rules in force, so that the console judges and alerts with the same settings as the agent (D36)."""
        from context.policy import Rules
        rules = Rules((view or self.client.view())["law"]["effective"])
        self.telemetry.limits, self.telemetry.late_periods = rules.limits, int(rules.get("late_periods", 2))
        self.telemetry.slo = float(rules.get("objective", 99.9)) / 100
        return rules

    @staticmethod
    def flagged(findings: dict, policy) -> dict:
        """The SLOs the scanner measured, with the engineers' alert thresholds applied: fast is a page, slow a ticket."""
        return {sid: {**e, "fast": (e.get("fast_burn") or 0) >= float(policy.get("burn_fast", 14.4)),
                      "slow": (e.get("slow_burn") or 0) >= float(policy.get("burn_slow", 6))}
                for sid, e in (findings.get("run:slos", {}).get("details") or {}).items()}

    def burning(self) -> dict:
        """The SLOs burning their error budget, as open conditions for the alerts: fast is a page, slow a ticket."""
        out, policy = {}, self.settle()
        for sid, s in (_json(self.findings).get("run:slos", {}).get("details") or {}).items():
            fast = (s.get("fast_burn") or 0) >= float(policy.get("burn_fast", 14.4))
            if fast or (s.get("slow_burn") or 0) >= float(policy.get("burn_slow", 6)):
                span = "1h" if fast else "6h"
                out[("slo", "page" if fast else "ticket", s["name"])] = (
                    "failing" if fast else "degraded",
                    {"rule": "burn", "slo": sid, "span": span, "value": s["burn"][span], "budget": s["budget"]})
        return out

    def preview(self, query: dict) -> dict:
        """What an SLO would have said over the console's recorded history (30 days): compliance, budget left, and how
        many times its fast and slow burn alerts would have fired. Nothing is signed: it helps choose before signing."""
        from instruments.production import SPANS, good_under, matches
        policy = self.settle()
        target, window_d = float(query.get("target", 99.9)), max(1, min(90, int(float(query.get("window_d", 30)))))
        sli, threshold = query.get("sli", "availability"), float(query.get("threshold_ms") or 1000)
        selector = query.get("selector", "counted")
        fast, slow = (float(query.get("burn_fast") or policy.get("burn_fast", 14.4)),
                      float(query.get("burn_slow") or policy.get("burn_slow", 6)))
        now_minute = int(time.time()) // 60
        own = lambda cid: policy.get("components", {}).get(cid, {}).get("counted")
        counted = lambda cid, kind: own(cid) == "on" if own(cid) else kind != "dependency"
        total, bad = {}, {}
        for minute, cid, kind, t, b, buckets in self.telemetry.minutes(now_minute - window_d * 1440):
            if matches(selector, cid, kind, counted):
                total[minute] = total.get(minute, 0.0) + t
                bad[minute] = bad.get(minute, 0.0) + (b if sli == "availability"
                                                       else t - good_under(buckets, threshold))
        if not total:
            return {"minutes": 0}
        first, allowed = min(total), 1 - target / 100
        minutes = list(range(first, now_minute + 1))
        cum_t, cum_b, acc_t, acc_b = [], [], 0.0, 0.0
        for m in minutes:
            acc_t, acc_b = acc_t + total.get(m, 0.0), acc_b + bad.get(m, 0.0)
            cum_t.append(acc_t)
            cum_b.append(acc_b)

        def burn(i, span):
            j = max(-1, i - span)
            t = cum_t[i] - (cum_t[j] if j >= 0 else 0)
            b = cum_b[i] - (cum_b[j] if j >= 0 else 0)
            return None if t < 20 else (b / t) / allowed
        episodes = {"fast": 0, "slow": 0}
        firing = {"fast": False, "slow": False}
        for i in range(len(minutes)):
            for name, (long, short, limit) in {"fast": (SPANS["1h"], SPANS["5m"], fast),
                                               "slow": (SPANS["6h"], SPANS["30m"], slow)}.items():
                a, b = burn(i, long), burn(i, short)
                on = a is not None and b is not None and a >= limit and b >= limit
                episodes[name] += on and not firing[name]
                firing[name] = on
        events, failures = cum_t[-1], cum_b[-1]
        return {"minutes": len(minutes), "events": int(events), "compliance": 1 - failures / events,
                "budget": 1 - (failures / events) / allowed, "fast_alerts": episodes["fast"],
                "slow_alerts": episodes["slow"], "window_d": window_d}

    def coverage(self) -> dict:
        """The rule catalog against this product: each category's signed state and debt, each rule's state as the
        scanner published it, and the access matrix: routes read on main with the id their allow() names, and the
        roles @access gives each id (lots 5 and 8)."""
        import re as _re
        from instruments.surfaces import scan
        from instruments.tree import GitTree
        from catalog import categories, contracts, load, render_contracts
        cat, findings, view = load(), _json(self.findings), self.client.view()
        signed = {(f["resource"], f["property"]): f for f in view.get("facts", [])}
        debts = {o.get("target"): o for o in view["health"].get("open", []) if str(o.get("target", "")).startswith("rules-")}
        rules = self.settle(view)
        values = rules.values()
        stacks = ()
        out = []
        for c in categories():
            resource = f"repo:rules:{c}"
            published = findings.get(f"{resource}|failing", {}).get("details") or []
            states = dict(d.split("=", 1) for d in published if _re.fullmatch(r"[A-Z0-9-]+=[a-z/]+", d))
            why = [d for d in published if "=" not in d.split(" ")[0]]
            fact = signed.get((resource, "failing"))
            members = [r for r in cat["rules"] if _re.sub(r"[^a-z0-9]+", "-", r["category"].lower()).strip("-") == c]
            out.append({"id": c, "name": members[0]["category"] if members else c, "status": fact and fact["status"],
                        "at": fact and fact["at"], "due": (debts.get(f"rules-{c}") or {}).get("due"), "why": why[:20],
                        "rules": [{"id": r["id"], "do": r["do"], "who": r["who"], "block": r["block"],
                                   "state": states.get(r["id"], "unmeasured")} for r in members]})
        routes = {}
        try:
            main = scan(GitTree(self.repo, "main"))
            stacks = main["stacks"]
            for path, d in sorted(main["files"].items()):
                for endpoint, ident in d.get("access", {}).items():
                    routes[endpoint] = {"id": ident, "file": path}
        except Exception as exc:
            routes = {"error": {"id": None, "file": str(exc)[:200]}}
        for category in out:
            category["contract"] = render_contracts(contracts(cat, cat["vocabulary"]["features"], values,
                                                             category=category["id"], stacks=stacks))
        return {"categories": out, "routes": routes, "access": values.get("access", {}), "app": values.get("app"),
                "public": values.get("public", [])}

    @staticmethod
    def named_values(rules) -> dict:
        """The catalog's named values as the human edits them: what each means, its strict default, what is chosen."""
        from catalog import load
        cat, current, chosen = load(), rules.values(), rules.get("values") or {}
        return {name: {"doc": spec["doc"], "type": spec["type"], "default": spec.get("default"),
                       "current": current.get(name), "chosen": name in chosen,
                       "rules": sorted(r["id"] for r in cat["rules"] if name in r.get("values", []))}
                for name, spec in cat["values"].items()}

    def settings(self) -> dict:
        """The rules of the game as the human edits them: every move and its routes (on or off), every setting with
        the socle's bound, the components to tune, who changed the rules and when (D51)."""
        from context.policy import SCHEMA, socle
        from catalog import load as catalog
        findings, view = _json(self.findings), self.client.view()
        rules = self.settle(view)
        report = self.telemetry.report(window=3600)
        components = [{k: r.get(k) for k in ("id", "kind", "operation", "name", "state", "availability", "p99",
                                             "counted")} for rows in report["components"].values() for r in rows
                      if r.get("id")]
        floor = socle()
        return {"main": git(self.repo, "rev-parse", "main").strip(),
                "rules": {"settings": rules.settings, "routes": rules.routes(), "socle": floor["routes"],
                          "bounds": floor["bounds"], "policy": catalog()["policy"],
                          "schema": {k: v[1] for k, v in SCHEMA.items() if v[1] is not None},
                          "history": view.get("rules_history", []),
                          "values": self.named_values(rules),
                          "silences": rules.silences(int(time.time() * 1000))},
                "components": components, "slos": self.flagged(findings, rules),
                "probes": findings.get("run:probes", {}).get("details", []), "configured": self.deploy_root is not None,
                "signing": {"domain": view["prefix"]["genesis"], "as_of": view["health"]["as_of"],
                            "grant": self.people(view).get("human")}}

    def live(self, findings: dict, view: dict | None = None) -> dict:
        """What production runs, as the scanner signed it, the switches the guard made (D30), and the decisions an
        engineer may sign now: deploy main, step back, restart (D31)."""
        lag = findings.get("run:release:all|lag", {})
        history = []
        if self.deploy_root and (self.deploy_root / "history.jsonl").exists():
            history = [json.loads(x) for x in (self.deploy_root / "history.jsonl").read_text().splitlines() if x]
        current = next((h["to"] for h in reversed(history) if h.get("op") in ("deploy", "rollback")), None)
        why = _json(self.moves_notes).get("why") or {}                                 # the agent's restraint (D36)
        production = [m for m in moves(view or self.client.view()) if m["op"] in ("deploy", "canary", "rollback",
                                                                               "restart", "abort")]
        return {"configured": self.deploy_root is not None, "lag": lag.get("status"),
                "details": lag.get("details", []) + [f"{k}: {v}" for k, v in sorted(why.items())],
                "slo": findings.get("run:service:all|slo", {}).get("status"), "switches": history[-12:][::-1],
                "canary": self.canary_state(history),
                "slos": self.flagged(findings, self.settle(view)),
                "current": current, "moves": production, "grant": self.people(view).get("human")}

    def acts(self, rules) -> str:
        """What Standard does alone in production, under the rules in force (D31, D36)."""
        get, auto = rules.get, {op: r["auto"] for op, r in rules.routes().items()}
        parts = [f"Retour à la version précédente si l'objectif casse dans les {get('rollback_horizon_min', 30)} min "
                 "qui suivent une mise en production, ou si la nouvelle version ne démarre pas"
                 if auto.get("rollback") else "Retour arrière sur ta décision",
                 ("mise en production de main seule, dans la fenêtre des règles" if "direct" in auto.get("deploy", [])
                  else "mise en production par canari" if auto.get("canary") else "mise en production sur ta décision"),
                 f"redémarrage sans coupure (au plus {get('restarts_per_hour', 2)} par heure)" if auto.get("restart")
                 else "redémarrage sur ta décision"]
        return (" ; ".join(parts).capitalize() + ". Jamais à travers une migration non déclarée compatible. Au-delà, ou si "
                "la cause est hors du code (service externe, machine), c'est toi.")

    def canary_state(self, history: list) -> dict | None:
        """The release on a share of traffic, if any: which, since when, on what share."""
        if not self.deploy_root:
            return None
        try:                                                # the register is a small file, not a link (bt/register.py)
            release = (self.deploy_root / "canary").read_text().strip()
        except OSError:
            return None
        if not SHA.fullmatch(release):
            return None
        start = next((h for h in reversed(history) if h.get("op") == "canary" and h.get("to") == release), {})
        return {"release": release, "since": start.get("at"), "percent": start.get("percent")}

    FRONTIER = ("see", "alert", "act", "prove")

    def frontier(self, report: dict, findings: dict | None = None, policy=None) -> None:
        """For every component, what Standard does about it without a person, capability by capability, and why not.

        see: its metrics are collected and judged against published rules; alert: someone is told when it degrades;
        act: an operation of the law can repair it in production; prove: its state is a signed fact an auditor can
        check. A component that degrades where Standard does not act is an uncovered gap: a person must take it."""
        sources_up = all(t["up"] for t in report["targets"]) and bool(report["targets"])
        interval = int(self.telemetry.interval)
        reasons = {
            "see": (f"Mesuré toutes les {interval} s depuis ses métriques et jugé selon les seuils publiés.",
                    "Source muette ou absente : Standard ne voit pas ce composant en ce moment."),
            "alert": ("Signalé dans la console dès qu'il se dégrade. Pas encore d'e-mail ni de messagerie.",
                      "Personne n'est prévenu : Standard ne le voit pas en ce moment."),
            "act": (self.acts(policy or self.settle()),
                    "Aucune action en production n'est configurée : Standard ne déploie pas, ne revient pas à la version "
                    "précédente, ne redémarre pas et n'ajoute pas de capacité."),
            "prove": ("Son état entre dans le fait signé « run:service:all slo » du journal, vérifiable par un auditeur.",
                      "Ces mesures ne sont pas des faits signés du journal : elles ne prouvent rien à un auditeur."),
        }
        slo = (findings or {}).get("run:service:all|slo", {}).get("status") or ""
        signed = bool(slo) and not slo.startswith("uncovered")
        report["frontier_reasons"] = {k: {"yes": v[0], "no": v[1]} for k, v in reasons.items()}
        report["uncovered"] = []
        for kind, rows in report["components"].items():
            for row in rows:
                seen = sources_up and (row.get("observed", True) or row["state"] == "idle")
                judged = seen and kind not in ("process", "dependency")   # shown, not counted in the signed objective
                row["frontier"] = {"see": seen, "alert": seen, "act": seen and self.rollback,
                                   "prove": judged and signed}
                if row["state"] in ("degraded", "failing") or not seen:
                    report["uncovered"].append({"kind": kind, "name": row["name"], "operation": row.get("operation"),
                                                "state": row["state"], "why": row.get("why"), "seen": seen})
        rows = [r for rs in report["components"].values() for r in rs]
        report["frontier_total"] = {k: sum(1 for r in rows if r["frontier"][k]) for k in self.FRONTIER} | {"of": len(rows)}

    def alerts(self, view: dict | None = None) -> dict:
        """Production incidents and overdue obligations. A silence (in the rules) mutes one in the console, never a
        signed fact; an overdue obligation escalates to the human in the journal whatever the console shows."""
        view = view or self.client.view()
        now = int(time.time() * 1000)
        slug = lambda s: re.sub(r"[^A-Za-z0-9._@-]+", "-", str(s)).strip("-")[:80] or "x"
        out = []
        for i in self.telemetry.incidents(int(time.time()) - 86400):
            resource = f"repo:alert/{i['kind']}/{slug(i['operation'] + '-' + i['name'] if i['operation'] else i['name'])}/{i['opened_at']}"
            out.append({**i, "source": "run", "resource": resource, "opened_ms": i["opened_at"] * 1000})
        for e in view["health"]["escalated"]:
            resource = f"repo:alert/obligation/{slug(e['obligation'])}/{e['opened']}"
            out.append({"id": e["obligation"], "kind": "obligation", "operation": "", "name": e["obligation"],
                        "state": "escalated", "worst": "escalated", "why": {"rule": "overdue", "due": e["due"]},
                        "opened_ms": e["due"], "closed_at": None, "source": "law", "resource": resource})
        from instruments.production import component_id
        silences = self.settle(view).silences(now)
        for a in out:
            a["severity"] = ("page" if a["kind"] == "obligation" or a.get("operation") == "page"
                             or a["state"] == "failing" else "ticket")
            a["subject"] = ((a.get("why") or {}).get("slo") if a["kind"] == "slo" else
                            component_id(a["kind"], a.get("operation") or "", a["name"])
                            if a["kind"] not in ("obligation", "source") else a["name"])
            a["silenced"] = next((dict(m, id=mid) for mid, m in silences.items()
                                  if m.get("target_of") in ("all", a["subject"]) and m.get("until", 0) > now), None)
        live = [a for a in out if a["closed_at"] is None]
        loud = [a for a in live if not a["silenced"]]
        return {"alerts": out, "open": len(loud), "silenced": len(live) - len(loud),
                "signing": {"domain": view["prefix"]["genesis"], "as_of": view["health"]["as_of"]}}

    def dossier(self, head: str) -> dict:
        if not SHA.fullmatch(head):
            raise ValueError("a commit is 40 hex characters")
        return {"head": head, "message": git(self.repo, "log", "-1", "--format=%an <%ae>%n%n%B", head),
                "diff": git(self.repo, "show", "--stat", "--patch", "--format=", head)[:120_000]}


LOCAL_HOSTS = ("127.0.0.1", "localhost", "[::1]")


def host_name(header: str | None) -> str | None:
    """The host name a request addresses, without its port; None when malformed."""
    value = (header or "").strip().lower()
    m = re.fullmatch(r"(\[[0-9a-f:]+\]|[a-z0-9.-]+)(?::[0-9]{1,5})?", value)
    return m[1] if m else None


def handler(inst: Installation, allowed_hosts=LOCAL_HOSTS):
    allowed = frozenset(h.lower() for h in allowed_hosts)

    class Handler(BaseHTTPRequestHandler):
        server_version = "Standard"

        def _foreign(self) -> bool:
            """DNS rebinding: a page of another site that resolves to this address must not read or write here."""
            if host_name(self.headers.get("Host")) in allowed:
                return False
            self._ok({"error": "unknown host"}, HTTPStatus.FORBIDDEN)
            return True

        def log_message(self, fmt, *args):
            log.event("console.http", route=self.path.partition("?")[0], outcome="error")

        def log_request(self, code="-", size="-"):
            log.event("console.request", route=self.path.partition("?")[0], status=code)

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
            if self._foreign():
                return None
            route = self.path.split("?", 1)[0]
            try:
                if route in ("/", "/index.html"):
                    return self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
                if route in ("/sign.js", "/app.js", "/rules.js"):
                    return self._send(200, (STATIC / route[1:]).read_bytes(), "text/javascript; charset=utf-8")
                if route == "/app.css":
                    return self._send(200, (STATIC / "app.css").read_bytes(), "text/css; charset=utf-8")
                if route == "/api/state":
                    return self._ok(inst.state())
                if route == "/api/context":
                    query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                    return self._ok(inst.context(query.get("task", [""])[0]))
                if route == "/api/agent-context":
                    query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                    return self._ok(inst.agent_context(query.get("kind", [""])[0], query.get("id", [""])[0]))
                if route == "/api/alerts":
                    return self._ok(inst.alerts())
                if route == "/api/settings":
                    return self._ok(inst.settings())
                if route == "/api/coverage":
                    return self._ok(inst.coverage())
                if route == "/api/preview":
                    query = dict(q.split("=", 1) for q in self.path.partition("?")[2].split("&") if "=" in q)
                    return self._ok(inst.preview({k: urllib.parse.unquote(v) for k, v in query.items()}))
                if route == "/api/facts":
                    return self._ok(inst.facts())
                if route == "/api/run":
                    query = dict(q.split("=", 1) for q in self.path.partition("?")[2].split("&") if "=" in q)
                    window = int(query.get("window", 3600))
                    if not 60 <= window <= 30 * 86400:
                        raise ValueError("window: 60 s to 30 days")
                    return self._ok(inst.run_report(window))
                if route.startswith("/api/dossier/"):
                    return self._ok(inst.dossier(route.rsplit("/", 1)[1]))
                return self._ok({"error": "not found"}, HTTPStatus.NOT_FOUND)
            except ValueError as exc:
                return self._ok({"error": str(exc)[:200]}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:                       # unreachable or unqualified: say so, attest nothing
                return self._ok({"error": f"{type(exc).__name__}: {exc}"[:400]}, HTTPStatus.SERVICE_UNAVAILABLE)

        def do_POST(self):
            if self._foreign():
                return None
            if self.path not in ("/api/admit", "/api/requests", "/api/rules/draft"):
                return self._ok({"error": "not found"}, HTTPStatus.NOT_FOUND)
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return self._ok({"error": "application/json only"}, HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
            try:
                size = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return self._ok({"error": "bad length"}, HTTPStatus.BAD_REQUEST)
            if not 0 < size <= MAX_BODY:
                return self._ok({"error": "bad length"}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            try:
                body = strict_json(self.rfile.read(size), max_bytes=MAX_BODY)
                if not isinstance(body, dict):
                    raise ValueError("a JSON object is required")
            except ValueError as exc:
                return self._ok({"error": str(exc)[:200]}, HTTPStatus.BAD_REQUEST)
            if self.path in ("/api/requests", "/api/rules/draft"):   # D34: store only; D51: draft only
                try:
                    return self._ok(inst.store_request(body) if self.path == "/api/requests" else inst.draft_rules(body))
                except (ValueError, OSError) as exc:
                    return self._ok({"error": str(exc)[:300]}, HTTPStatus.BAD_REQUEST)
            try:
                return self._ok({"admitted": inst.client.admit(body)})
            except Exception as exc:
                return self._ok({"refused": getattr(exc, "code", None) or str(exc)[:300]}, HTTPStatus.CONFLICT)
    return Handler


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m surface.web")
    parser.add_argument("config")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--allow-host", action="append", default=[],
                        help="a host name a TLS proxy in front forwards (repeatable); localhost names are always allowed")
    args = parser.parse_args(argv)
    inst = Installation(args.config)
    inst.telemetry.start()
    server = ThreadingHTTPServer((args.bind, args.port), handler(inst, (*LOCAL_HOSTS, *args.allow_host)))
    print(f"Standard interface on http://{args.bind}:{args.port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
