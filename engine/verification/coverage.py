"""Coverage of the rule catalog on one tree: which rules apply, which Standard measured, which fail (lot 5).

For each rule that applies to the product (its features), each check is evaluated on the tree:

    blocks          no API the rule's block covers is used around it, and the block is used where the rule is
                    triggered (Python blocks: an import of standard_blocks.<block>)
    probe:<name>    Standard's own probe: of the running app (engine/verification/rule_probes.py, started from @app) or of
                    the tree (sri, migrations-reversible, lock-hashes)
    bandit:B<nnn>   bandit's finding of that id in product code

Each check answers pass | fail | na (nothing in the product to check) | unrun:<why> (Standard can measure it once the
product declares what it needs, e.g. @app) | gap (this release has no instrument for it yet: semgrep, test
templates, identity-provider probes) | ai | human. A rule is failing when a check fails, uncovered when a check is
unrun, measured or partial when every measurable check passes, and patrolled, human or gap when Standard measures
none of it.

A category target (`rules-<category>`) holds when no applicable rule is failing or uncovered: those are the product's
debt, with the target's due date (F0-11). Patrolled rules and the release's own gaps stay visible, never debt.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import surfaces
from .bans import analysis_gaps, block_calls, violations
from .tree import Measure

STATIC_PROBES = ("sri", "migrations-reversible", "lock-hashes")
RUN_PROBES = ("tls", "https-redirect", "no-vcs", "dir-listing", "egress", "telemetry", "idor", "redirects",
              "idp-password-policy", "idp-brute-force", "idp-mfa", "idp-reset", "idp-enumeration", "csrf-pages")
def adoptable(block: dict, stack: str) -> str | None:
    """The module a product on this stack adopts for the block, or None: no implementation on that stack yet (the
    bans still hold, nothing is owed), or an implementation that is configuration, not code."""
    impl = block["stacks"].get(stack)
    module = (impl or {}).get("module", "")
    return module if re.fullmatch(r"[\w@][\w@/.-]*", module) and (stack not in ("python", "fastapi") or "/" not in module) else None


def adopted(module: str, imports) -> bool:
    """Python: the module, a submodule, or the package; JS: the package path or a re-export of it (a local
    `@/lib/standard` wrapper that imports it counts, since its import is in the tree too)."""
    package = module.split(".")[0] if "/" not in module else module.rsplit("/", 1)[0]
    return any(i == module or i.startswith(module + ".") or i.startswith(module + "/") or i == package
               for i in imports)


def slug(category: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", category.lower()).strip("-")


def _materialise(tree, paths=None) -> Path:
    work = Path(tempfile.mkdtemp())
    for p in sorted(tree.paths() if paths is None else paths):
        dest = work / p
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(tree.read(p))
    return work


def static_probe(name: str, tree) -> tuple[str, list]:
    paths = sorted(tree.paths())
    if name == "sri":
        bad = []
        for p in paths:
            if p.endswith(surfaces.TEMPLATES):
                for m in re.finditer(r"<(script|link)\b[^>]*(src|href)=[\"']https?://[^>]*>", tree.read(p).decode("utf-8", "replace"), re.I):
                    if "integrity=" not in m.group(0):
                        bad.append(f"{p}: {m.group(0)[:80]}")
        return ("fail", bad[:30]) if bad else ("pass" if any(p.endswith(surfaces.TEMPLATES) for p in paths) else "na", [])
    if name == "migrations-reversible":
        versions = [p for p in paths if re.search(r"(^|/)(alembic/versions|migrations)/[^/]+\.py$", p)
                    and not p.endswith("__init__.py")]
        bad = []
        for p in versions:
            text = tree.read(p).decode("utf-8", "replace")
            m = re.search(r"def downgrade\([^)]*\)[^:]*:\s*\n((?:[ \t]+.*\n?)+)", text)
            body = [line.strip() for line in (m.group(1).splitlines() if m else []) if line.strip()
                    and not line.strip().startswith(("#", '"""', "'''"))]
            if not body or body == ["pass"] or body[0].startswith("raise"):
                bad.append(f"{p}: no reverse step")
        return ("fail", bad) if bad else ("pass" if versions else "na", [])
    if name == "lock-hashes":
        locks = [p for p in paths if re.fullmatch(r"(.*/)?(uv\.lock|poetry\.lock|package-lock\.json|pnpm-lock\.yaml)", p)]
        reqs = [p for p in paths if re.fullmatch(r"(.*/)?requirements[\w.-]*\.(txt|hashes)", p)]
        if locks:
            return "pass", []
        if not reqs:
            return "na", []
        bad = []
        for p in reqs:
            for line in tree.read(p).decode("utf-8", "replace").splitlines():
                s = line.strip()
                if s and not s.startswith(("#", "--hash", "-r ", "-c ", "--")) and "--hash=" not in s and \
                        not line.startswith((" ", "\t")):
                    bad.append(f"{p}: {s[:60]} has no hash")
        return ("fail", bad[:30]) if bad else ("pass", [])
    raise KeyError(name)


def bandit_report(tree, files) -> dict:
    """One isolated, complete scanner invocation shared by SAST and catalog checks.
    Only requested Python sources are materialised: product .bandit files cannot configure the scanner, and -I
    prevents a product bandit.py/sitecustomize.py from replacing the trusted installed tool."""
    if not files:
        return {"results": [], "errors": [], "metrics": {}}
    work = _materialise(tree, files)
    try:
        r = subprocess.run([sys.executable, "-I", "-m", "bandit", "--ignore-nosec", "-f", "json", "-q", "--", *files],
                           cwd=work, capture_output=True, timeout=900)
        report = json.loads(r.stdout)
        if (r.returncode not in (0, 1) or not isinstance(report, dict)
                or not isinstance(report.get("results"), list) or report.get("errors") != []):
            raise ValueError("bandit did not complete its analysis")
        metrics = report.get("metrics")
        if not isinstance(metrics, dict):
            raise ValueError("bandit reported no scan coverage")
        scanned = set()
        for filename in metrics:
            path = Path(filename)
            if path.is_absolute():
                try:
                    path = path.relative_to(work)
                except ValueError:
                    continue
            scanned.add(path.as_posix().removeprefix("./"))
        if not set(files) <= scanned:
            raise ValueError("bandit omitted requested source files")
        results = report["results"]
        if any(not isinstance(x, dict) or not all(k in x for k in ("test_id", "filename", "line_number"))
               for x in results) or bool(results) != (r.returncode == 1):
            raise ValueError("inconsistent bandit report")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return report


def bandit_findings(tree) -> dict:
    """test id -> locations; any unavailable or incomplete scan raises instead of returning an empty result."""
    files = [p for p in sorted(tree.paths()) if p.endswith(".py") and not surfaces.SKIP.search(p)]
    report = bandit_report(tree, files)
    out = {}
    for x in report["results"]:
        out.setdefault(x["test_id"], []).append(f"{x['filename'].removeprefix('./')}:{x['line_number']}")
    return out


def app_probes(tree, values: dict, paths=()) -> dict:
    """Standard's probes of the product's app, in a separate process with the tree as working directory."""
    from .rule_probes import APP_PROBES
    if not values.get("app"):
        return {p: ["unrun:declare @app", []] for p in APP_PROBES}
    if re.match(r"https?://", str(values["app"])):              # a product Standard cannot import: probed over HTTP
        endpoints = sorted({e for d in surfaces.scan(tree)["files"].values() for e in d["endpoints"]})
        payload = {"base_url": values["app"], "values": values, "endpoints": endpoints}
        try:
            r = subprocess.run([sys.executable, "-I", str(Path(__file__).with_name("rule_probes.py"))],
                               input=json.dumps(payload).encode(), capture_output=True, timeout=900)
            return json.loads(r.stdout)
        except Exception as exc:
            return {p: [f"unrun:{type(exc).__name__}", []] for p in APP_PROBES}
    work = _materialise(tree)
    payload = {"app": values["app"], "values": values, "paths": list(paths)}
    try:
        r = subprocess.run([sys.executable, "-I", str(Path(__file__).with_name("rule_probes.py"))],
                           input=json.dumps(payload).encode(), cwd=work, capture_output=True, timeout=900,
                           env={"PATH": "/usr/bin:/bin", "HOME": str(work)})
        return json.loads(r.stdout)
    except Exception as exc:
        return {p: [f"unrun:{type(exc).__name__}", []] for p in APP_PROBES}


def evaluate(tree, catalog: dict, values: dict, *, declared=(), probes=None, bandit=None, blocks_paths=()) -> dict:
    """rule id -> {"state", "checks": {check: [result, details]}} for every rule of the catalog."""
    scan = surfaces.scan(tree, declared)
    features = set(scan["features"])
    present = {f"surface:{s}" for d in scan["files"].values() for s in d["surfaces"]} | \
        {f"construct:{c}" for d in scan["files"].values() for c in d["constructs"]}
    imports = {i for d in scan["files"].values() for i in d["imports"]}
    stacks = scan["stacks"]
    team = "team" in features
    blocks = catalog["blocks"]
    probes = probes if probes is not None else None
    cache = {}

    def static_gaps():
        if "static_gaps" not in cache:
            cache["static_gaps"] = [f"{p}: {why}" for p in sorted(tree.paths()) if not surfaces.SKIP.search(p)
                                    for why in analysis_gaps(p, tree.read(p))]
        return cache["static_gaps"]

    def calls(module):
        key = "calls:" + module
        if key not in cache:
            cache[key] = set().union(*(block_calls(p, tree.read(p), module) for p in tree.paths()
                                      if not surfaces.SKIP.search(p)))
        return cache[key]

    def get_probes():
        if "probes" not in cache:
            cache["probes"] = probes if probes is not None else app_probes(tree, values, blocks_paths)
        return cache["probes"]

    def get_bandit():
        if "bandit" not in cache:
            try:
                cache["bandit"] = bandit if bandit is not None else bandit_findings(tree)
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                cache["bandit"] = f"unrun:bandit:{type(exc).__name__}"
        return cache["bandit"]

    def block_check(rule) -> list:
        name = rule["block"]
        found = violations(tree, {name: blocks[name]["bans"]})
        if found:
            return ["fail", [f"{p}:{line}:{pat}" for p, line, pat in found[:30]]]
        gaps = static_gaps()
        if gaps:
            return ["unrun:static analysis incomplete", gaps[:30]]
        triggered = not rule["when"] or bool(present & set(rule["when"]))
        if triggered:
            for stack in stacks:
                module = adoptable(blocks[name], stack)
                if module and not adopted(module, imports):
                    return [f"unrun:adopt {module}", [f"{module} is not used where the rule applies ({stack})"]]
                if module and not calls(module):
                    return [f"unrun:wire {module}", ["import present, no resolved block call; wiring is not verified"]]
                if stack == "fastapi" and name in ("access", "session") and module and not any(
                        q.endswith(".bind") for q in calls(module)):
                    return [f"unrun:bind {module}", ["the block has not been bound to the application"]]
        return ["pass" if triggered else "na", []]

    out = {}
    for rule in catalog["rules"]:
        applies = set(rule["applies"]) <= features and (team or not rule.get("team_only"))
        if not applies:
            out[rule["id"]] = {"state": "n/a", "checks": {}}
            continue
        missing = [v for v in rule.get("values", []) if v not in values]
        checks = {}
        for check in rule["check"]:
            kind, _, arg = check.partition(":")
            if check == "blocks":
                checks[check] = block_check(rule)
            elif kind == "probe" and arg in STATIC_PROBES:
                checks[check] = list(static_probe(arg, tree))
            elif kind == "probe" and arg in RUN_PROBES:
                checks[check] = ["gap", ["measured on the running product or with the identity provider (not yet)"]]
            elif kind == "probe":
                checks[check] = list(get_probes().get(arg, ["gap", ["no such probe in this release"]]))
            elif kind == "bandit":
                measured = get_bandit()
                hits = measured.get(arg, []) if isinstance(measured, dict) else []
                checks[check] = ([measured, []] if isinstance(measured, str) else
                                 ["fail", hits[:30]] if hits else ["pass", []])
            elif check == "patrol":
                checks[check] = ["ai", []]
            elif check == "human":
                checks[check] = ["human", []]
            else:                                           # semgrep, test templates, mypy, production facts
                checks[check] = ["gap", ["no instrument for it in this release"]]
        if missing:
            checks["values"] = ["unrun:set " + ", ".join(f"@{v}" for v in missing), []]
        results = [r[0] for r in checks.values()]
        measurable = [r for r in results if r in ("pass", "fail", "na") or r.startswith("unrun")]
        if "fail" in results:
            state = "failing"
        elif any(r.startswith("unrun") for r in results):
            state = "uncovered"
        elif measurable:
            state = "measured" if all(r in ("pass", "na") for r in results) else "partial"
        else:
            state = "patrolled" if "ai" in results else "human" if "human" in results else "gap"
        out[rule["id"]] = {"state": state, "checks": checks,
                           "limits": ["static block checks inspect call sites; runtime coverage needs probes"]
                           if "blocks" in checks else []}
    return out


def category_measure(states: dict, catalog: dict, category: str, *, regression: bool = False) -> Measure:
    """The debt of one category: universe = applicable rules Standard can measure; covered = those measured;
    findings = those failing. No applicable measurable rule: held. For a regression (`regression=True`), only what
    Standard measured counts: a change that makes a rule apply before the product adopted its block leaves a debt
    with a due date, not a refused change; a change that breaks a measured rule is refused."""
    rules = [r for r in catalog["rules"] if slug(r["category"]) == category]
    if not rules:
        raise ValueError("unknown rule category")
    kept = ("failing", "measured", "partial") if regression else ("failing", "uncovered", "measured", "partial")
    universe = {r["id"] for r in rules if states[r["id"]]["state"] in kept}
    # Every rule's state first (the console's coverage map reads them), then why each failing or unmeasured one is.
    summary = [f"{r['id']}={states[r['id']]['state']}" for r in sorted(rules, key=lambda r: r["id"])]
    why = [f"{i}: {c} {r[0]} {'; '.join(r[1][:3])}".strip() for i in sorted(universe)
           for c, r in states[i]["checks"].items() if r[0] == "fail" or r[0].startswith("unrun")]
    # A regression compares what each side found: only the failures, never the state summary.
    details = tuple(why[:50]) if regression else tuple(summary + why[:max(0, 50 - len(summary))])
    if not universe:
        return Measure(frozenset({category}), frozenset({category}), (), details)
    covered = {i for i in universe if states[i]["state"] != "uncovered"}
    failing = sorted(i for i in universe if states[i]["state"] == "failing")
    return Measure(frozenset(universe), frozenset(covered), tuple(failing), details)
