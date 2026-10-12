"""U08 — the web interface (ARCHITECTURE.md §11.9): BUILD and RUN of one installation, reviews to sign, the law.

    python -m standard.surface.web standard.toml [--bind 127.0.0.1] [--port 8080]

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
import os
import re
import subprocess
import sys
import time
import tomllib
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from standard.autonomy.projection import installed_routes, project
from standard.autonomy.context import task_context
from instruments.data import EMPTY
from bt.gateway import GatewayClient
from instruments.recipes import recipes_for

STATIC = Path(__file__).with_name("static")
SHA = re.compile(r"[0-9a-f]{40}")
BRANCH = re.compile(r"([0-9a-f]{40})\trefs/heads/([a-z0-9][a-z0-9_-]{0,63})/(\S+)")
HOLDERS = {"reviewer": "h3", "officer": "h2", "engineer": "h1", "product": "h1"}           # the demo ceremony's grants to people (tools/ceremony.py)
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
        self.routes = installed_routes(c.get("agent", {}).get("scopes", ()),
                                       model=bool(c.get("llm") or c.get("agent", {}).get("api_key_file")))
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
        run = c.get("run", {})
        from .telemetry import Telemetry
        self.telemetry = Telemetry(Path(run.get("store", Path.home() / ".standard" / "telemetry.db")).expanduser(),
                                   run.get("metrics", []), slo=float(run.get("slo", 99.9)) / 100,
                                   interval=float(run.get("interval", 15)))
        self.rollback = bool(c.get("deploy")) and "agent_rollback" in c["grants"]     # D30: can act in production
        self.slo_db = base / "slo.db"
        self.requests = resolve(c.get("build", {}).get("store", "requests"))          # D34: specs and contracts
        self.request_notes = agent / "requests.json"                                                   # D32: the operator's SLO data
        self.telemetry.extra = self.burning
        self.deploy_root = resolve(c["deploy"]["root"]) if c.get("deploy") else None
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
    def context(self, task_id: str) -> dict:
        view = self.client.view()
        plan = project(view, self.routes, self.client.qualify, mode="RUN")
        task = next((t for t in plan["tasks"] if t["id"] == task_id), None)
        if task is None:
            raise ValueError("no task at this prefix")
        return task_context(view, task, _json(self.findings))

    def run(self, view: dict, findings: dict) -> dict:
        plan = project(view, self.routes, self.client.qualify, mode="RUN")
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
        for item in contributions:                              # D34: a contribution may answer a request
            from instruments.suite import claimed
            item["request"] = claimed(git(self.repo, "log", "-1", "--format=%B", item["head"], check=False)) \
                if not item["landed"] else None
            item["facts"].setdefault("acceptance", None)
        return {"contributions": contributions, "requests": self.requests_of(view, findings, main)}

    def requests_of(self, view: dict, findings: dict, main: str) -> list:
        """Every request: its state, what the scanner says of its contract, its candidate implementations."""
        from instruments.suite import contract_path, load
        notes = _json(self.request_notes)
        out = []
        for resource, e in sorted(view.get("entities", {}).items(), key=lambda kv: -kv[1].get("created", 0)):
            if e.get("type") != "request":
                continue
            rid = resource.split("/", 1)[1]
            spec, contract = (load(self.requests, e["fields"][k]) for k in ("spec", "contract"))
            facts = view["transitions"].get(resource, {})
            features = []
            for r, f in view["transitions"].items():
                if r.startswith(f"repo:feature:{rid}/"):
                    base, head = r.split("/")[1:3]
                    landed = subprocess.run(["git", "-C", str(self.repo), "merge-base", "--is-ancestor", head, "main"],
                                            capture_output=True, timeout=60).returncode == 0
                    features.append({"resource": r, "base": base, "head": head, "facts": f, "kind": "feature",
                                     "request": rid, "title": e["fields"]["title"], "landed": landed,
                                     "stale": base != main and not landed,
                                     "why": [d.splitlines()[0][:200] for p in ("acceptance", "tests", "regressions")
                                             for d in findings.get(f"{r}|{p}", {}).get("details", [])[:3]],
                                     "awaiting_review": not landed and base == main and f.get("acceptance") == "green"
                                     and f.get("tests") == "green" and f.get("regressions") == "none"
                                     and f.get("review") != "approved"})
            out.append({"id": rid, "resource": resource, "title": e["fields"]["title"], "state": e["state"],
                        "owner": e.get("owner"), "created": e.get("created"), "expected": e["expected"],
                        "facts": facts, "path": contract_path(rid),
                        "contract_details": findings.get(f"{resource}|contract", {}).get("details", []),
                        "spec": spec.decode(errors="replace") if spec else None,
                        "contract": contract.decode(errors="replace") if contract else None,
                        "agent": notes.get(rid, {}).get("state"), "features": features})
        return out

    def store_rules(self, body: dict) -> dict:
        """D35: keep a new standard/rules.json by digest, as the bytes the agent will commit; the engineer signs it."""
        import hashlib
        doc = body.get("document")
        if not isinstance(doc, dict):
            raise ValueError("a rules document is a JSON object")
        doc = {k: v for k, v in doc.items() if k in ("global", "components", "slos", "probes")}
        data = (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode()
        digest = hashlib.sha256(data).hexdigest()
        self.requests.mkdir(parents=True, exist_ok=True)
        (self.requests / digest).write_bytes(data)
        return {"digest": f"sha256:{digest}", "base": git(self.repo, "rev-parse", "main").strip()}

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
        law = view["law"]["effective"]
        health = view["health"]
        return {
            "prefix": view["prefix"], "assessment": view["assessment"], "law_digest": view["law"]["digest"],
            "health": {"state": health["state"], "open": len(health["open"]), "escalated": health["escalated"],
                       "proven": len(health["proven"]), "as_of": health["as_of"]},
            "main": main, "history": self.history(),
            "product": self.product, "products": self.products,
            "requirements": (reqs := self.requirements(view, findings)),
            "autonomy": self.autonomy(reqs),
            "run": self.run(view, findings), "build": self.build(view, findings, main),
            "law": {"targets": [{k: t.get(k) for k in ("id", "resource", "property", "expect", "coverage", "repair",
                                                        "human", "due_ms")} for t in law["targets"]],
                    "conditions": law["conditions"], "ops": sorted(law["ops"])},
            "signing": {"domain": view["prefix"]["genesis"], "as_of": health["as_of"], "grants": self.grants},
        }

    def autonomy(self, requirements: list) -> dict:
        """What Standard does without a person, for each requirement and each kind of component, and why not more.

        autonomous: the agent repairs alone, because an independent instrument recomputes the repair byte for byte;
        supervised: the agent prepares, a person signs, because the repair needs judgment no instrument can prove;
        human: only people act, because what is asked is not in the repository (a procedure, a platform setting);
        observed: Standard measures, nobody acts through it yet, because the law has no operation for it."""
        why = {
            "autonomous": "La correction se recalcule à l'identique par un instrument indépendant : la loi peut l'accepter sans personne.",
            "supervised": "La correction demande un jugement. Aucun instrument ne peut prouver qu'elle est juste, donc une personne signe.",
            "human": "Ce qui est demandé n'est pas dans le code : une procédure, un registre ou un réglage de plateforme qu'une personne atteste.",
            "observed": "Standard mesure ce composant mais n'agit pas dessus : aucune mise en production ne lui est confiée sur "
                        "cette installation (section [deploy]). Il ne déploie pas et ne revient pas à la version précédente.",
        }
        why["acting"] = ("Standard met main en production et revient seul à la version précédente quand l'objectif casse juste "
                         "après une mise en production, sur des faits signés par le scanner et par la garde, comme les "
                         "changements de code. Il ne redémarre pas une machine et n'ajoute pas de capacité.")
        conditions = {
            "run-slo": "Seulement si la rupture suit de moins de 30 min une mise en production et que la version remplacée "
                       "tenait l'objectif ; sinon une personne, à l'échéance.",
            "run-live": "Sauf une version déjà retirée par un retour arrière : il faut alors un nouveau commit sur main.",
            "vulns": "Seulement si l'instantané de données connaît une version corrigée ; sinon une personne décide.",
            "actions": "Seulement si l'instantané de données connaît le commit de l'action ; sinon une personne décide.",
            "sbom": None,
        }
        level = {"agent": "autonomous", "review": "supervised", "people": "human"}
        rows = []
        for r in requirements:
            lv = level[r["who"]]
            blocked = r["state"] == "unmeasured"
            production = r["resource"].startswith("run:") and lv == "autonomous"
            rows.append({"id": r["id"], "level": lv, "why": why["acting"] if production else why[lv],
                         "condition": conditions.get(r["id"]),
                         "blocked": "Non mesurée sur cette installation : aucune autonomie possible tant que rien ne la mesure."
                         if blocked else None})
        count = {lv: sum(1 for x in rows if x["level"] == lv) for lv in ("autonomous", "supervised", "human")}
        runtime = {"level": "autonomous", "why": why["acting"]} if self.rollback else {"level": "observed",
                                                                                         "why": why["observed"]}
        return {"levels": why, "requirements": rows, "count": count, "total": len(rows), "runtime": runtime}

    def run_report(self, window: int) -> dict:
        """The product in production: its APIs and their metrics, and the latest releases."""
        openapi = git(self.repo, "show", "main:openapi.json", check=False)
        from .telemetry import declared_routes
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

    def rules_doc(self, commit: str = "main") -> dict:
        try:
            doc = json.loads(git(self.repo, "show", f"{commit}:standard/rules.json", check=False) or "{}")
        except ValueError:
            doc = {}
        return doc if isinstance(doc, dict) else {}

    def settle(self, view: dict | None = None):
        """The engineers' settings as main carries them, and the signed silences (D36), so that the console judges
        and alerts with them."""
        from standard.autonomy.policy import Policy
        policy = Policy(self.rules_doc(), transitions=(view or {}).get("transitions"))
        self.telemetry.limits, self.telemetry.late_periods = policy.limits, int(policy.get("late_periods"))
        self.telemetry.slo = policy.get("objective") / 100
        return policy

    def changes(self) -> list:
        """The rules file's history on main: who changed what, when (git keeps it; the journal keeps the proofs)."""
        from standard.autonomy.policy import history
        log = git(self.repo, "log", "-30", "--format=%H %at %an", "main", "--", "standard/rules.json", check=False)
        versions = [(int(at) * 1000, author, self.rules_doc(h)) for h, at, author in
                    (line.split(" ", 2) for line in log.splitlines()[::-1] if line.count(" ") >= 2)]
        return history(versions)

    @staticmethod
    def flagged(findings: dict, policy) -> dict:
        """The SLOs the scanner measured, with the engineers' alert thresholds applied: fast is a page, slow a ticket."""
        return {sid: {**e, "fast": (e.get("fast_burn") or 0) >= policy.get("burn_fast"),
                      "slow": (e.get("slow_burn") or 0) >= policy.get("burn_slow")}
                for sid, e in (findings.get("run:slos", {}).get("details") or {}).items()}

    def burning(self) -> dict:
        """The SLOs burning their error budget, as open conditions for the alerts: fast is a page, slow a ticket."""
        out, policy = {}, self.settle()
        for sid, s in (_json(self.findings).get("run:slos", {}).get("details") or {}).items():
            fast = (s.get("fast_burn") or 0) >= policy.get("burn_fast")
            if fast or (s.get("slow_burn") or 0) >= policy.get("burn_slow"):
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
        fast, slow = (float(query.get("burn_fast") or policy.get("burn_fast")),
                      float(query.get("burn_slow") or policy.get("burn_slow")))
        now_minute = int(time.time()) // 60
        counted = lambda cid, kind: (policy.get("counted", cid) == "on" if policy.get("counted", cid)
                                     else kind != "dependency")
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

    def settings(self) -> dict:
        """Everything an engineer may set, its effective value, what is pending, and every component to tune (D31)."""
        from standard.autonomy.policy import law_bounds
        findings, view = _json(self.findings), self.client.view()
        policy = self.settle(view)
        report = self.telemetry.report(window=3600)
        components = [{k: r.get(k) for k in ("id", "kind", "operation", "name", "state", "availability", "p99",
                                             "counted")} for rows in report["components"].values() for r in rows
                      if r.get("id")]
        main = git(self.repo, "rev-parse", "main").strip()
        notes = _json(self.request_notes.with_name("rules.json"))
        landing = [{"digest": k.split("/", 1)[1], **v} for k, v in notes.items() if k.startswith(main + "/")]
        return {"main": main, "rules_landing": landing,
                "rules_file": bool(git(self.repo, "ls-tree", "--name-only", "main", "standard/rules.json", check=False).strip()),
                "policy": policy.published(int(time.time() * 1000), law_bounds(view["law"]["effective"]["conditions"]),
                                           self.changes()), "components": components,
                "slos": self.flagged(findings, policy),
                "probes": findings.get("run:probes", {}).get("details", []), "configured": self.deploy_root is not None,
                "signing": {"domain": view["prefix"]["genesis"], "as_of": view["health"]["as_of"],
                            "grant": self.grants.get("engineer")}}

    def live(self, findings: dict, view: dict | None = None) -> dict:
        """What production runs, as the scanner signed it, the switches the guard made (D30), and the decisions an
        engineer may sign now: deploy main, step back, restart (D31)."""
        lag = findings.get("run:release:all|lag", {})
        history = []
        if self.deploy_root and (self.deploy_root / "history.jsonl").exists():
            history = [json.loads(x) for x in (self.deploy_root / "history.jsonl").read_text().splitlines() if x]
        offered = lambda prefix, prop: next((r for r, f in sorted((view or {}).get("transitions", {}).items())
                                             if r.startswith(prefix) and f.get(prop) == "yes"), None)
        current = next((h["to"] for h in reversed(history) if h.get("op") in ("deploy", "rollback")), None)
        restarts = [h for h in history if h.get("op") == "restart" and h.get("to") == current]
        why = _json(self.request_notes.with_name("releases.json")).get("why") or {}    # the agent's restraint (D36)
        return {"configured": self.deploy_root is not None, "lag": lag.get("status"),
                "details": lag.get("details", []) + [f"{k}: {v}" for k, v in sorted(why.items())],
                "slo": findings.get("run:service:all|slo", {}).get("status"), "switches": history[-12:][::-1],
                "canary": self.canary_state(history),
                "slos": self.flagged(findings, self.settle(view)),
                "actions": {"deploy": offered("run:release:all/", "candidate"),
                            "abort": offered("run:canary:abort/", "running") or (
                                f"run:canary:abort/{current}/{self.canary_state(history)['release']}"
                                if self.canary_state(history) else None),
                            "rollback": offered("run:service:all/", "previous"),
                            "restart": f"run:process:all/{current}/{len(restarts) + 1}" if current else None},
                "grant": self.grants.get("engineer")}

    def acts(self, policy) -> str:
        """What Standard does alone in production, in the engineers' current settings (D31)."""
        get = policy.get
        parts = [f"Retour à la version précédente si l'objectif casse dans les {get('rollback_horizon_min') or 30} min "
                 "qui suivent une mise en production, ou si la nouvelle version ne démarre pas"
                 if get("auto_rollback") != "off" else "Retour arrière décidé par un ingénieur",
                 "mise en production de main seul" if get("auto_deploy") != "off" else "mise en production approuvée par un ingénieur",
                 f"redémarrage sans coupure (au plus {get('restarts_per_hour')} par heure)" if get("auto_restart") == "on"
                 else "redémarrage décidé par un ingénieur"]
        return (" ; ".join(parts).capitalize() + ". Jamais à travers une migration non déclarée compatible. Au-delà, ou si "
                "la cause est hors du code (service externe, machine), une personne.")

    def canary_state(self, history: list) -> dict | None:
        """The release on a share of traffic, if any: which, since when, on what share."""
        if not self.deploy_root:
            return None
        try:
            release = Path(os.readlink(self.deploy_root / "canary")).name
        except OSError:
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
            "alert": ("Signalé dans l'interface dès qu'il se dégrade ; une personne le prend en charge par une signature. "
                      "Pas encore d'e-mail ni de messagerie.",
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

    ACK_MS = 10 * 60_000      # an alert nobody takes within ten minutes is flagged as not taken

    def alerts(self, view: dict | None = None) -> dict:
        """Production incidents and overdue obligations, each with who took it. Taking an alert is a statement a person
        signs in their browser (property `ack` on `repo:alert/<kind>/<name>/<opened>`), admitted by the kernel and kept
        in the journal: the proof that someone was told is the person's own signature, not a delivery receipt."""
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
            facts = view["transitions"].get(a["resource"], {})
            a["taken"] = facts.get("ack") == "taken"
            a["severity"] = ("page" if a["kind"] == "obligation" or a.get("operation") == "page"
                             or a["state"] == "failing" else "ticket")
            a["subject"] = ((a.get("why") or {}).get("slo") if a["kind"] == "slo" else
                            component_id(a["kind"], a.get("operation") or "", a["name"])
                            if a["kind"] not in ("obligation", "source") else a["name"])
            a["silenced"] = next((dict(m, id=mid) for mid, m in silences.items()
                                  if m.get("target_of") in ("all", a["subject"]) and m.get("until", 0) > now), None)
            a["unattended"] = (a["closed_at"] is None and not a["taken"] and not a["silenced"]
                               and now - a["opened_ms"] > self.ACK_MS)
        live = [a for a in out if a["closed_at"] is None]
        loud = [a for a in live if not a["silenced"]]
        return {"alerts": out, "open": len(loud), "untaken": sum(1 for a in loud if not a["taken"]),
                "unattended": sum(1 for a in loud if a["unattended"]), "silenced": len(live) - len(loud),
                "ack_ms": self.ACK_MS, "signing": {"domain": view["prefix"]["genesis"], "as_of": view["health"]["as_of"],
                                                   "grant": self.grants.get("reviewer"),
                                                   "engineer": self.grants.get("engineer")}}

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
                if route == "/api/context":
                    query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                    return self._ok(inst.context(query.get("task", [""])[0]))
                if route == "/api/alerts":
                    return self._ok(inst.alerts())
                if route == "/api/settings":
                    return self._ok(inst.settings())
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
            if self.path not in ("/api/admit", "/api/requests", "/api/rules"):
                return self._ok({"error": "not found"}, HTTPStatus.NOT_FOUND)
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return self._ok({"error": "application/json only"}, HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
            size = int(self.headers.get("Content-Length") or 0)
            if not 0 < size <= MAX_BODY:
                return self._ok({"error": "bad length"}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            if self.path in ("/api/requests", "/api/rules"):   # D34, D35: store, nothing signed or admitted here
                try:
                    body = json.loads(self.rfile.read(size))
                    return self._ok(inst.store_request(body) if self.path == "/api/requests" else inst.store_rules(body))
                except (ValueError, OSError) as exc:
                    return self._ok({"error": str(exc)[:300]}, HTTPStatus.BAD_REQUEST)
            try:
                envelope = json.loads(self.rfile.read(size))
                return self._ok({"admitted": inst.client.admit(envelope)})
            except Exception as exc:
                return self._ok({"refused": getattr(exc, "code", None) or str(exc)[:300]}, HTTPStatus.CONFLICT)
    return Handler


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m standard.surface.web")
    parser.add_argument("config")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)
    inst = Installation(args.config)
    inst.telemetry.start()
    server = ThreadingHTTPServer((args.bind, args.port), handler(inst))
    print(f"Standard interface on http://{args.bind}:{args.port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
