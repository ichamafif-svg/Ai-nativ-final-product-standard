"""U — the whole law, before proposing: what the agent checks on its own candidate, in its sandbox.

A repair of one target must not open another gap. Before any proposal the agent measures base and candidate with every
floor probe it can run (the same library the judge uses, on its own reading of its own store), runs main's suite
against the candidate's code in the sandbox, and lints and type-checks the files it changed. A candidate that fixes
nothing, regresses a target no recipe repairs, breaks a test or adds a lint or type error is not proposed: it goes
back to the agent as feedback. A regression a recipe closes on the next pass (a bumped pin makes the SBOM stale) is a
follow-up, not a reason to hold back a fix.

This is the agent being careful, not the agent being judged: the instruments still measure the exact commit.
"""
from __future__ import annotations

import re
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

import trusted.instruments as probes
from trusted.instruments import Snapshot
from trusted.recipes import recipes_for

from .sandbox import Sandbox

LOCAL = ("secrets", "sbom", "actions", "vulns", "licenses", "deps-age", "sast")   # needs no provider and no ledger
COUNT = re.compile(r"found:(\d+)")


def _worse(expect: str, before: str, after: str) -> bool:
    if after == expect or after == before:
        return False
    if before == expect or after.startswith("uncovered"):
        return True
    b, a = COUNT.fullmatch(before), COUNT.fullmatch(after)
    return bool(b and a and int(a[1]) > int(b[1]))


def measure(tree, targets: dict, data) -> dict:
    out = {}
    for tid in LOCAL:
        if tid not in targets:
            continue
        try:
            m = probes.PROBES[tid](tree, {"data": data})
        except Exception as exc:
            m = exc
        out[tid] = (probes.verdict(targets[tid]["expect"], m),
                    [] if isinstance(m, BaseException) else list(m.details or map(str, m.findings))[:20])
    return out


def environment(requirements: Path, cache) -> str:
    """A Python with the candidate's pinned dependencies, built outside the sandbox (it needs the index), from wheels
    only so that no package's build code runs, and reused for the same requirements."""
    import hashlib
    import subprocess
    import sys
    if not requirements.exists() or cache is None:
        return sys.executable
    venv = Path(cache) / hashlib.sha256(requirements.read_bytes()).hexdigest()[:16]
    python = venv / "bin" / "python"
    if not python.exists():
        subprocess.run([sys.executable, "-m", "venv", "--system-site-packages", str(venv)], check=True, timeout=300)
        r = subprocess.run([str(python), "-m", "pip", "install", "-q", "--only-binary=:all:", "-r", str(requirements)],
                           capture_output=True, timeout=1800)
        if r.returncode != 0:
            import shutil
            shutil.rmtree(venv, ignore_errors=True)
            raise RuntimeError(f"dependencies: {r.stderr.decode(errors='replace')[-500:]}")
    return str(python)


def suite(sandbox: Sandbox, store, base: str, head: str, cache=None) -> tuple[str, list]:
    """Main's tests against the candidate's code, in the sandbox: (green|red|uncovered, failures)."""
    with sandbox.checkout(store, base) as main_tree, sandbox.checkout(store, head) as code:
        if not (main_tree / "tests").is_dir():
            return "uncovered", ["main has no tests/"]
        try:
            python = environment(code / "requirements.txt", cache)
        except Exception as exc:
            return "uncovered", [str(exc)]
        report = Path(tempfile.mkdtemp()) / "report.xml"
        (report.parent / "pytest.ini").write_text("[pytest]\n")
        sandbox.run([python, "-m", "pytest", "-c", report.parent / "pytest.ini", "--rootdir", code, "-p",
                     "no:cacheprovider", "-q", f"--junitxml={report}", main_tree / "tests"], code, pythonpath=code)
        if not report.exists():
            return "uncovered", ["the suite produced no report"]
        failed = []
        for case in ET.parse(report).iter("testcase"):
            bad = [c for c in case if c.tag in ("failure", "error")]
            if bad:
                failed.append(f"{case.get('classname')}::{case.get('name')}\n{(bad[0].text or '')[-1200:]}")
        return ("red" if failed else "green"), failed


def tools(sandbox: Sandbox, store, base: str, head: str, changed: list) -> dict:
    """Lint and type errors in the changed Python files that were not there on base."""
    py = [p for p in changed if p.endswith(".py")]
    out = {}
    if not py:
        return out
    for name, args in (("ruff", ("check", "--no-cache", "--output-format=concise", "--isolated", "--select", "E9,F")),
                       ("mypy", ("--ignore-missing-imports", "--no-incremental", "--follow-imports=silent"))):
        lines = {}
        for label, commit in (("base", base), ("head", head)):
            with sandbox.checkout(store, commit) as tree:
                present = [p for p in py if (tree / p).exists()]
                r = sandbox.python_module(name, *args, *present, cwd=tree) if present else None
                lines[label] = {re.sub(r":\d+:\d+:", ":", ln) for ln in (r.out.splitlines() if r else [])
                                if re.match(r"[^\s:]+\.py:\d+", ln)}
        new = sorted(lines["head"] - lines["base"])
        if new:
            out[name] = new[:30]
    return out


def precheck(store, base: str, head: str, target_id: str, targets: dict, data, sandbox: Sandbox,
             cache=None) -> dict:
    """{"ok": bool, "problems": [str], "fixed": bool, ...}: whether this candidate is worth proposing."""
    before, after = measure(Snapshot(store, base), targets, data), measure(Snapshot(store, head), targets, data)
    worse = [tid for tid in after if tid != target_id and _worse(targets[tid]["expect"], before[tid][0], after[tid][0])]
    autonomous = set(recipes_for(data))                   # a gap a recipe closes on the next pass is a follow-up
    problems = [f"{tid}: {before[tid][0]} -> {after[tid][0]} {after[tid][1][:5]}" for tid in worse
                if tid not in autonomous]
    follow_ups = [tid for tid in worse if tid in autonomous]
    fixed = target_id not in after or after[target_id][0] == targets[target_id]["expect"]
    if not fixed:
        problems.append(f"{target_id} is still {after[target_id][0]}: {after[target_id][1][:5]}")
    status, failures = suite(sandbox, store, base, head, cache)
    if status != "green":
        problems.append(f"main's tests are {status} on this candidate: {failures[:3]}")
    changed = probes.git(store, "diff", "--name-only", base, head).split()
    lint = tools(sandbox, store, base, head, changed)
    problems += [f"{name} reports new errors: {errs[:10]}" for name, errs in lint.items()]
    return {"ok": not problems, "fixed": fixed, "problems": problems, "follow_ups": follow_ups, "tests": status,
            "lint": lint,
            "isolation": sandbox.isolation, "changed": changed}
