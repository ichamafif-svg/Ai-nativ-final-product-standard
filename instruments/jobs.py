"""The programs' entry point: `plan` routes what to measure, the jobs measure it (D37).

The host calls `python -I -c "...jobs.main()"` as the isolated runner with {"job", "inputs"} on stdin, every input
already materialised (an exported commit, the bytes of a blob, a recorded value), and reads {"facts", "extra"} on
stdout. `plan` is cheap and sees the ledger's extract; the measuring jobs see only what they measure, so the host can
cache them by their inputs and anyone can replay them.

    plan          main, proposals, inbox, requests, registers, the rules in force  ->  jobs, with their inputs
    floors        main's tree, pinned data, protections, lineage  ->  every probed floor target
    remediation   base, head (a proposal)  ->  tests, regressions, scoped (+ reproduced when a recipe recomputes it)
                  on repo:{area}:{item}/…
    feature       base, head with a Standard-Request trailer  ->  acceptance, tests, regressions, scoped on
                  repo:feature:…
    contribution  base, head from the inbox  ->  tests, regressions (+ acceptance) on repo:contrib:…
    request       main, a request's contract  ->  contract (proposed) or accepted (contracted) on build:request/…
    production    scrapes, probes, registers  ->  coverage, slo, lag, what is on each switch, numbers
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from kernel.types import ID

from . import probes, production, scope, suite
from .data import EMPTY, TrustedData
from .recipes import recipes_for
from .tree import DirTree, Measure, verdict

TARGET_TRAILER = re.compile(r"(?m)^Standard-Target: (" + ID.pattern + r")$")
AUTHOR = re.compile(r"refs/heads/([a-z0-9][a-z0-9_-]{0,63})/[^\s]+")


def _bytes(x) -> bytes | None:
    return None if x is None else Path(x["bytes"]).read_bytes()


def _data(inp) -> TrustedData:
    raw = _bytes(inp.get("data"))
    return TrustedData(json.loads(raw)) if raw else EMPTY


# ---- routing ---------------------------------------------------------------------------------------------------------
def plan(p: dict) -> list:
    """Which jobs to run, with which inputs, on this pass."""
    main, data, install = p["main"], {"data": True}, {"value": p["install"]}
    targets, settings = {"value": p["targets"]}, p.get("settings") or {}
    scopes = {"value": settings.get("scopes") if isinstance(settings.get("scopes"), dict) else {}}
    entities = p["entities"]
    contracted = {r.split("/", 1)[1]: e["fields"]["contract"] for r, e in entities.items()
                  if e["type"] == "request" and e["state"] == "contracted"}
    jobs = [{"job": "floors", "inputs": {"main": {"commit": main}, "data": data, "targets": targets,
                                         "protections": {"world": "protections"}, "history": {"log": [p["anchor"], main]},
                                         "judged": {"value": sorted(p["judged"])},
                                         "now": {"value": -(-p["now"] // 3_600_000) * 3_600_000},
                                         "install": install}, "network": p["install"]}]   # next hour: cache expires early
    for c in p["proposals"]:
        if c["parents"] != [main]:
            continue                                        # only transitions from the current main are measured
        base, head = {"commit": main}, {"commit": c["head"]}
        rid = suite.claimed(c["message"])
        if rid in contracted:
            jobs.append({"job": "feature", "inputs": {"base": base, "head": head, "data": data, "targets": targets,
                                                      "request": {"value": rid},
                                                      "contract": {"store": "requests", "digest": contracted[rid]}, "install": install},
                         "network": p["install"]})
        elif rid is None:
            jobs.append({"job": "remediation", "inputs": {"base": base, "head": head, "data": data, "targets": targets,
                                                          "scopes": scopes, "install": install},
                         "network": p["install"]})
    for c in p["inbox"]:
        author = AUTHOR.fullmatch(c["ref"])
        if author is None or c["parents"] != [main]:
            continue                                        # not on the current main: the author rebases
        rid = suite.claimed(c["message"])
        extra = {"request": {"value": rid}, "contract": {"store": "requests", "digest": contracted[rid]}} \
            if rid in contracted else {}
        jobs.append({"job": "contribution", "inputs": {"base": {"commit": main}, "head": {"commit": c["head"]},
                                                       "author": {"value": author[1]}, "data": data,
                                                       "targets": targets, "install": install, **extra},
                         "network": p["install"]})
    for r, e in sorted(entities.items()):
        if e["type"] == "request" and e["state"] in ("proposed", "contracted"):
            jobs.append({"job": "request", "inputs": {"main": {"commit": main}, "request": {"value": r.split("/", 1)[1]},
                                                      "state": {"value": e["state"]},
                                                      "contract": {"store": "requests", "digest": e["fields"]["contract"]}},
                         "network": p["install"]})
    if p["production"]:
        regs = p["registers"] or {"current": None, "canary": None, "history": []}
        live = regs.get("current")
        switch = next((h for h in reversed(regs["history"]) if h.get("to") == live and h.get("op") != "restart"), None)
        shas = [x for x in {live, (switch or {}).get("from")} if x and re.fullmatch(r"[0-9a-f]{40}", x)]
        jobs.append({"job": "production", "inputs": {
            "now": {"value": p["now"]}, "main": {"value": main}, "deploy": {"value": p["registers"] is not None},
            "registers": {"value": regs}, "series": {"series": "*"}, "rules": {"value": settings},
            "facts": {"value": [f for f in p["facts"] if f["resource"].startswith("run:") and f["author"] == p["scanner"]]},
            **{f"manifest_{s}": {"manifest": s} for s in shas}}})
    return jobs


# ---- measuring jobs ------------------------------------------------------------------------------------------------
def floors(inp: dict) -> list:
    tree, targets, data = DirTree(inp["main"]["tree"]), {t["id"]: t for t in inp["targets"]}, _data(inp)
    ctx = {"data": data, "history": inp["history"], "judged": set(inp["judged"]), "install": inp.get("install", False),
           "world": type("World", (), {"protections": lambda _: set(inp["protections"])})()}
    facts = [["repo:inventory:all", "coverage", verdict("complete", probes.inventory(tree)), []]]
    for tid, probe in probes.PROBES.items():
        target = targets.get(tid)
        if target is None:
            continue
        try:
            if tid in probes.DATA_PROBES and not data.fresh(inp["now"], target["fresh_ms"]):
                raise LookupError("the pinned data snapshot is older than the target's freshness")
            if tid == "branch" and inp["protections"] is None:
                raise LookupError("the provider did not answer")
            measure = probe(tree, ctx)
        except Exception as exc:
            measure = exc
        details = ([f"{type(measure).__name__}: {str(measure)[:300]}"] if isinstance(measure, BaseException)
                   else list(measure.details or map(str, measure.findings))[:50])
        facts.append([target["resource"], target["property"], verdict(target["expect"], measure), details])
    return facts


def reproduced(base: DirTree, head: DirTree, recipe) -> str:
    """`yes` only if head is a direct child of base whose whole tree is base plus exactly the recipe's files."""
    try:
        if head.parents != [base.commit]:
            return "no:not-a-child"
        expected = recipe(base)
        if not expected:
            return "no:recipe"
        expected = {p: c for p, c in expected.items() if p not in base.paths() or base.read(p) != c}
        changed = {p for p in base.entries.keys() | head.entries.keys() if base.entries.get(p) != head.entries.get(p)}
        if changed != set(expected):
            return "no:paths"
        if any(head.entries[p][0] != "100644" or head.read(p) != c for p, c in expected.items()):
            return "no:content"
        return "yes"
    except Exception as exc:
        return f"no:{type(exc).__name__}"


def _regressions(base, head, inp, data):
    targets = {t["id"]: t for t in inp["targets"]}
    return probes.regressions(base, head, targets, {"data": data}, frozenset(recipes_for(data)))


def remediation(inp: dict) -> list:
    base, head, data = DirTree(inp["base"]["tree"]), DirTree(inp["head"]["tree"]), _data(inp)
    targets = {t["id"]: t for t in inp["targets"]}
    tid, facts = None, {}
    for name, recipe in recipes_for(data).items():
        if name in targets and reproduced(base, head, recipe) == "yes":
            tid, facts = name, {"reproduced": ("yes", [])}
            break
    if tid is None:
        claimed = TARGET_TRAILER.search(head.message)
        tid = claimed[1] if claimed else None
    if tid not in targets or targets[tid].get("repair") != "remediate":
        return []
    _, area, item = targets[tid]["resource"].split(":", 2)
    facts["tests"] = suite.tests_report(base, head, install=inp.get("install", False))
    facts["regressions"] = _regressions(base, head, inp, data)       # a repair opens no other gap
    facts["scoped"] = scope.scoped(scope.changed(base, head), lambda path: scope.repair(tid, path, inp.get("scopes")))
    return [[f"repo:{area}:{item}/{base.commit}/{head.commit}", p, s, d] for p, (s, d) in facts.items()]


def feature(inp: dict) -> list:
    base, head, data = DirTree(inp["base"]["tree"]), DirTree(inp["head"]["tree"]), _data(inp)
    contract, rid = _bytes(inp["contract"]), inp["request"]
    facts = {"acceptance": suite.acceptance_on(head, rid, contract) if contract else ("uncovered:store", []),
             "tests": suite.tests_report(base, head, install=inp.get("install", False)),
             "regressions": _regressions(base, head, inp, data),
             "scoped": scope.scoped(scope.changed(base, head), lambda path: scope.feature(rid, path))}
    return [[f"repo:feature:{rid}/{base.commit}/{head.commit}", p, s, d] for p, (s, d) in facts.items()]


def contribution(inp: dict) -> list:
    """Main's own suite against the contribution's code, so it cannot weaken the tests that judge it; every floor
    probe on main and on the contribution, so it cannot open a new gap; and its request's contract if it claims one."""
    base, head, data = DirTree(inp["base"]["tree"]), DirTree(inp["head"]["tree"]), _data(inp)
    facts = {"tests": suite.tests_report(base, head, install=inp.get("install", False)),
             "regressions": _regressions(base, head, inp, data)}
    if inp.get("contract"):
        facts["acceptance"] = suite.acceptance_on(head, inp["request"], _bytes(inp["contract"]))
    return [[f"repo:contrib:{inp['author']}/{base.commit}/{head.commit}", p, s, d] for p, (s, d) in facts.items()]


def request(inp: dict) -> list:
    main, rid, contract = DirTree(inp["main"]["tree"]), inp["request"], _bytes(inp["contract"])
    resource = f"build:request/{rid}"
    if contract is None:
        return [[resource, "contract" if inp["state"] == "proposed" else "accepted", "uncovered:store",
                 ["the contract is not in the request store"]]]
    if inp["state"] == "proposed":
        status, details = suite.contract_on(main, rid, contract)
        return [[resource, "contract", status, details]]
    status, details = suite.acceptance_on(main, rid, contract)
    return [[resource, "accepted", "yes" if status == "green" else "no", details]]


def run_production(inp: dict) -> dict:
    inp = dict(inp)
    for name, s in inp["series"].items():
        s["points"] = [(at, None if f is None else (json.loads(Path(f).read_text()) if s["role"] == "probes"
                                                    else Path(f).read_text())) for at, f in s["points"]]
    inp["rules"] = inp["rules"] if isinstance(inp.get("rules"), dict) else {}
    inp["manifests"] = {k[len("manifest_"):]: json.loads(Path(v["manifest"]).read_text())["entries"]
                        for k, v in inp.items() if k.startswith("manifest_")}
    return production.measure(inp)


JOBS = {"floors": floors, "remediation": remediation, "feature": feature,
        "contribution": contribution, "request": request}


def run(job: str, inputs: dict) -> dict:
    if job == "plan":
        return {"jobs": plan(inputs["subjects"]), "facts": []}
    if job == "production":
        return run_production(inputs)
    return {"facts": JOBS[job](inputs), "extra": {}}


def main() -> None:
    request_ = json.loads(sys.stdin.read())
    try:
        out = run(request_["job"], request_["inputs"])
    except Exception as exc:                               # an exception is an answer: the host signs nothing from it
        out = {"error": f"{type(exc).__name__}: {str(exc)[:500]}"}
    sys.stdout.write(json.dumps(out, sort_keys=True, default=lambda x: sorted(x) if isinstance(x, (set, frozenset))
                                else str(x)) + "\n")


__all__ = ["main", "run", "Measure"]
