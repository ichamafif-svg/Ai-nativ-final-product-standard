"""U — the whole law, before proposing: what the agent checks on its own candidate, in its sandbox.

A repair of one target must not open another gap. Before any proposal the agent measures base and candidate with every
floor probe it can run (the same library the judge uses, on its own reading of its own store), runs main's suite
against the candidate's code in the sandbox, and lints and type-checks the files it changed. A candidate that fixes
nothing, regresses a target no recipe repairs, breaks a test, adds a lint or type error, or makes the tests touch a
wall of the bac that base's code did not touch (D69: green tests on code that hit the wall are not a pass) is not
proposed: it goes back to the agent as feedback, each collision as a lesson read against the capability map. A regression a recipe closes on the next pass (a bumped pin makes the SBOM stale) is a
follow-up, not a reason to hold back a fix.

This is the agent being careful, not the agent being judged: the instruments still measure the exact commit.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

import engine.verification.probes as probes
from engine.verification.tree import Snapshot
from engine.verification.recipes import recipes_for
from engine.verification.suite import contract_path, report_measure

from engine.agents.sandbox import Sandbox
from fabric.runtime.bac import capability_map
from fabric.runtime.refusals import read as read_refusals
from interface.context.feedback import item, render, route
from engine.agents.quality import COMPLEXITY

LOCAL = probes.LOCAL_PROBES
_worse = probes._worse


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


def environment(sandbox: Sandbox, requirements: Path, cache) -> str:
    """Fetch inert wheels by exact name/version; install and start candidate dependencies only inside the jail."""
    import hashlib
    import subprocess
    import sys
    from packaging.requirements import Requirement
    test_environment = getattr(sandbox, "prepare_environment", None)
    if callable(test_environment):
        return test_environment(requirements, cache)
    if not requirements.exists() or cache is None:
        return sys.executable
    if not sandbox.isolated:
        raise RuntimeError("candidate dependency installation requires the network and filesystem jail")
    packages = []
    for line in requirements.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        req = Requirement(line)
        specs = list(req.specifier)
        if req.url or len(specs) != 1 or specs[0].operator != "==" or "*" in specs[0].version:
            raise ValueError("candidate requirements must be exact package pins")
        if req.marker is None or req.marker.evaluate():
            packages.append(f"{req.name}{req.specifier}")
    venv = Path(cache) / hashlib.sha256(requirements.read_bytes()).hexdigest()[:16]
    python = venv / "bin" / "python"
    if not python.exists():
        Path(cache).mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="standard-wheels-") as wheels:
            if packages:
                download = subprocess.run([sys.executable, "-m", "pip", "download", "--isolated", "--only-binary=:all:",
                                           "--dest", wheels, *packages], capture_output=True, timeout=1800)
                if download.returncode:
                    raise RuntimeError("candidate wheels unavailable: " + download.stderr.decode(errors="replace")[-300:])
            created = sandbox.run([sys.executable, "-m", "venv", "--system-site-packages", str(venv)],
                                  Path(cache), writable=(Path(cache),))
            if not created.ok:
                raise RuntimeError("candidate venv could not be isolated: " + created.out[-300:])
            installed = sandbox.run([str(python), "-m", "pip", "install", "--isolated", "--no-index",
                                     "--find-links", wheels, *packages], Path(cache), readable=(Path(wheels),),
                                    writable=(Path(cache),)) if packages else None
            if installed is not None and not installed.ok:
                raise RuntimeError("candidate dependencies could not be isolated: " + installed.out[-300:])
            probe = sandbox.run([str(python), "-m", "pytest", "--version"], Path(cache),
                                writable=(Path(cache),))
            if not probe.ok:
                raise RuntimeError("candidate Python failed inside jail: " + probe.out[-300:])
    return str(python)


def _quality(sandbox, store, base: str, head: str, changed: list, cache, *, tests_green: bool) -> dict:
    """D70 quality: mutation of the changed lines (only when main's tests are green), complexity, duplication."""
    from engine.agents.quality import complexity, duplication, mutation
    out = {"complexity": complexity(store, base, head, changed), "duplication": duplication(store, base, head, changed),
           "mutation": {"mutants": 0, "killed": 0, "survivors": [], "score": None}}
    if not tests_green or not any(p.endswith(".py") for p in changed):
        return out
    with sandbox.checkout(store, base) as main_tree:
        if not (main_tree / "tests").is_dir():
            return out

        def green(tree: Path) -> bool:
            try:
                python = environment(sandbox, tree / "requirements.txt", cache)
            except Exception:
                return False
            result = sandbox.run([python, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", main_tree / "tests"],
                                 tree, pythonpath=tree, readable=(main_tree, *([Path(cache)] if cache else [])))
            return result.code == 0

        out["mutation"] = mutation(sandbox, store, base, head, changed, green)
    return out


def _observer(scratch: Path) -> Path:
    """Standard's read-only observer (sitecustomize), copied into the run's scratch so the bac may mount it."""
    import shutil
    target = scratch / "observe"
    target.mkdir(exist_ok=True)
    shutil.copy(Path(__file__).resolve().parents[2] / "fabric/runtime" / "observe" / "sitecustomize.py", target)
    return target


def _capabilities(sandbox) -> dict:
    bac = getattr(sandbox, "bac", None)
    return capability_map(bac.walls, groups=bac.groups) if bac is not None else capability_map()


def _rules_held(holder: str) -> list:
    """The catalog rules a part of the platform holds (`held_by`): the text the agent saw before coding."""
    from engine.catalog import load
    return sorted(r["id"] for r in load()["rules"] if r["held_by"] == holder)


def _with_rules(lessons: list) -> list:
    return [{**lesson, "rules": _rules_held(lesson["held_by"])} for lesson in lessons]


def values_in_force(context) -> dict | None:
    """The named values in force for a task's context (D68: `@start` runs the product behind the gateway)."""
    from interface.context.policy import Rules
    law = (context or {}).get("effective_law")
    try:
        return Rules(law).values() if law else None
    except Exception:
        return None


def _entry(sandbox, store, base: str, head: str, values: dict | None, cache) -> tuple[list, str | None]:
    """The gate's lessons on the candidate's product that base's product did not earn (D68 step 2)."""
    from engine.agents.entry import lessons as entry_lessons
    if not values or not values.get("start"):
        return [], "@start is not set: the product was not run behind the gateway"
    found = {}
    for label, commit in (("base", base), ("head", head)):
        with sandbox.checkout(store, commit) as tree:
            try:
                python = environment(sandbox, tree / "requirements.txt", cache)
            except Exception as exc:
                return [], f"the product's environment could not be prepared: {exc}"
            path = str(Path(python).parent)
            found[label], why = entry_lessons(tree, values, during="behind the gateway",
                                              env={"PATH": f"{path}:/usr/local/bin:/usr/bin:/bin", "PYTHONPATH": str(tree)},
                                              readable=(*([Path(cache)] if cache else []),))
            if why:
                return [], why
    known = {(lesson["capability"], lesson["route"]) for lesson in found["base"]}
    return [{**lesson, "new": (lesson["capability"], lesson["route"]) not in known} for lesson in found["head"]], None


def suite(sandbox: Sandbox, store, base: str, head: str, cache=None, *, refusals: list | None = None) -> tuple[str, list]:
    """Main's tests against the candidate's code, in the sandbox: (green|red|uncovered, failures).

    With `refusals`, the lessons of the run (D69) are appended to it."""
    with sandbox.checkout(store, base) as main_tree, sandbox.checkout(store, head) as code:
        if not (main_tree / "tests").is_dir():
            return "uncovered", ["main has no tests/"]
        try:
            python = environment(sandbox, code / "requirements.txt", cache)
        except Exception as exc:
            return "uncovered", [str(exc)]
        report = Path(tempfile.mkdtemp()) / "report.xml"
        (report.parent / "pytest.ini").write_text("[pytest]\n")
        observer = _observer(report.parent)
        result = sandbox.run([python, "-m", "pytest", "-c", report.parent / "pytest.ini", "--rootdir", code, "-p",
                     "no:cacheprovider", "-q", "-rA", f"--junitxml={report}", main_tree / "tests"], code,
                             pythonpath=f"{code}:{observer}",
                             readable=(main_tree, *([Path(cache)] if cache else [])), writable=(report.parent,))
        if refusals is not None:
            refusals += read_refusals(result, _capabilities(sandbox), during="main's tests", root=code)
        if not report.exists():
            return "uncovered", ["the suite produced no report"]
        try:
            measure = report_measure(report, result.code)
            status = probes.verdict("green", measure)
            return ("red" if status.startswith("found:") else status), list(measure.details)
        except Exception as exc:
            return "uncovered", [f"{type(exc).__name__}: {exc}"]


def tools(sandbox: Sandbox, store, base: str, head: str, changed: list) -> dict:
    """Lint and type errors in the changed Python files that were not there on base."""
    py = [p for p in changed if p.endswith(".py")]
    out = {}
    if not py:
        return out
    for name, args in (("ruff", ("check", "--no-cache", "--output-format=concise", "--isolated", "--select", "E9,F")),
                       ("mypy", ("--ignore-missing-imports", "--no-incremental", "--follow-imports=silent",
                                  "--cache-dir=/dev/null"))):
        lines = {}
        for label, commit in (("base", base), ("head", head)):
            with sandbox.checkout(store, commit) as tree:
                present = [p for p in py if (tree / p).exists()]
                r = sandbox.python_module(name, *args, *present, cwd=tree) if present else None
                lines[label] = {re.sub(r":\d+:\d+:", ":", ln) for ln in (r.out.splitlines() if r else [])
                                if re.match(r"[^\s:]+\.py:\d+", ln)}
                if r is not None and not r.ok and not lines[label]:
                    out[name] = [f"{label}: tool failed without usable diagnostics (exit {r.code}): {r.out[-500:]}"]
                    break
        if name in out:
            continue
        new = sorted(lines["head"] - lines["base"])
        if new:
            out[name] = new[:30]
    return out


def precheck(
    store,
    base: str,
    head: str,
    target_id: str | None,
    targets: dict,
    data,
    sandbox: Sandbox,
    cache=None,
    *,
    request: str | None = None,
    values: dict | None = None,
) -> dict:
    """Candidate checks only; fixed=None means no local instrument measured that requirement, never a success."""
    before, after = measure(Snapshot(store, base), targets, data), measure(Snapshot(store, head), targets, data)
    worse = [tid for tid in after if tid != target_id and _worse(targets[tid]["expect"], before[tid][0], after[tid][0])]
    autonomous = set(recipes_for(data))  # a gap a recipe closes on the next pass is a follow-up
    problems = [
        f"{tid}: {before[tid][0]} -> {after[tid][0]} {after[tid][1][:5]}"
        for tid in worse
        if target_id is None or tid not in autonomous
    ]
    # D70: every problem is also one item of the one feedback dossier the agent reads.
    items = [item("lesson", f"probe:{tid}", "build", where=tid,
                  attempt=f"{before[tid][0]} -> {after[tid][0]} {after[tid][1][:5]}")
             for tid in worse if target_id is None or tid not in autonomous]
    follow_ups = [tid for tid in worse if tid in autonomous]
    fixed = after[target_id][0] == targets[target_id]["expect"] if target_id in after else None
    if fixed is False:
        problems.append(f"{target_id} is still {after[target_id][0]}: {after[target_id][1][:5]}")
        items.append(item("lesson", f"probe:{target_id}", "build", where=target_id,
                          attempt=f"still {after[target_id][0]}: {after[target_id][1][:5]}"))
    if request is not None:
        with sandbox.checkout(store, head) as code, tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "acceptance.xml"
            result = sandbox.python_module(
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                f"--junitxml={report}",
                contract_path(request),
                cwd=code,
                pythonpath=code,
                writable=(Path(tmp),),
            )
            try:
                accepted = probes.verdict("green", report_measure(report, result.code))
            except Exception as exc:
                accepted = f"uncovered:{type(exc).__name__}"
            if accepted != "green":
                problems.append(f"the contract does not pass yet ({accepted}):\n{result.out[-3000:]}")
                items.append(item("lesson", "acceptance", "build", where="the acceptance contract",
                                  attempt=f"{accepted}: {result.out[-200:]}"))
            lessons = read_refusals(result, _capabilities(sandbox), during="the acceptance contract", root=code)
    else:
        lessons = []
    status, failures = suite(sandbox, store, base, head, cache, refusals=lessons)
    if lessons:
        # Only a collision base's code does not have is the candidate's; an older one stays a lesson, not a block.
        before_lessons: list = []
        suite(sandbox, store, base, base, cache, refusals=before_lessons)
        known = {lesson["capability"] for lesson in before_lessons}
        new = sorted({lesson["capability"] for lesson in lessons} - known)
        items += [item("lesson", "wall", "build", rules=_rules_held(lesson["held_by"]),
                       where=" <- ".join(reversed(lesson["stack"])) or lesson["capability"],
                       attempt=f"{lesson['capability']}: {lesson['attempt']}", new=lesson["capability"] in new, available=str(lesson["available"]),
                       instead=lesson["instead"], ask=lesson["ask"]) for lesson in lessons]
        if new:
            told = "\n".join(f"- {lesson['capability']} (held by {lesson['held_by']}): tried `{lesson['attempt']}`; "
                             f"available: {lesson['available']}; instead: {lesson['instead']}"
                             for lesson in lessons if lesson["capability"] in new)
            problems.append("the candidate's code touched the bac's walls, even if its tests pass. Change the design, "
                            f"or draft the value for the human to sign:\n{told}")
    entry_lessons, entry_note = _entry(sandbox, store, base, head, values, cache)
    if entry_lessons:
        new_entry = [lesson for lesson in entry_lessons if lesson["new"]]
        items += [item("lesson", "gateway", "build", rules=_rules_held(lesson["held_by"]), where=lesson["route"],
                       attempt=f"{lesson['capability']}: {lesson['attempt']}", new=lesson["new"],
                       instead=lesson["instead"]) for lesson in entry_lessons]
        if new_entry:
            told = "\n".join(f"- {lesson['attempt']}; instead: {lesson['instead']}" for lesson in new_entry)
            problems.append("behind the gateway, the candidate's product needed corrections base's did not:\n" + told)
        lessons += entry_lessons
    lessons = _with_rules(lessons)
    if target_id == "ci":
        fixed = status == "green"
    if status != "green":
        problems.append(f"main's tests are {status} on this candidate: {failures[:3]}")
        items += [item("lesson", "tests", "build", where="main's tests",
                       attempt=f"main's tests are {status} on this candidate: {failure}")
                  for failure in (failures[:5] or [""])]
    changed = probes.git(store, "diff", "--name-only", base, head).split()
    lint = tools(sandbox, store, base, head, changed)
    problems += [f"{name} reports new errors: {errs[:10]}" for name, errs in lint.items()]
    items += [item("lesson", name, "build", where=str(err).split(":")[0], attempt=str(err))
              for name, errs in lint.items() for err in errs[:10]]
    quality = _quality(sandbox, store, base, head, changed, cache, tests_green=status == "green")
    for c in quality["complexity"]:
        problems.append(f"complexity: {c['where']} {c['function']} is {c['complexity']} (limit {COMPLEXITY}); split it")
        items.append(item("lesson", "complexity", "build", where=f"{c['where']} {c['function']}",
                          attempt=f"complexity {c['complexity']}, was {c['before'] or 'new'}",
                          instead=f"split it into functions of complexity {COMPLEXITY} or less"))
    for d in quality["duplication"]:
        problems.append(f"duplication: {d['where']} repeats code of {d['copy_of']}; reuse it instead of copying")
        items.append(item("lesson", "duplication", "build", where=d["where"], attempt=f"copies {d['copy_of']}",
                          instead=f"call or extend what {d['copy_of']} already defines"))
    # Agents may not write tests in a maintained repository: weak tests are for the human who signs contracts.
    items += [item("need", "mutation", "build", where=s["where"], attempt=f"tests still pass after {s['change']}")
              for s in quality["mutation"].get("survivors", [])]
    dossier = route(items)
    return {
        "ok": not problems,
        "fixed": fixed,
        "problems": problems,
        "follow_ups": follow_ups,
        "tests": status,
        "lint": lint,
        "isolation": sandbox.isolation,
        "changed": changed,
        "refusals": lessons,
        "entry": entry_note,
        "quality": quality,
        "feedback": dossier,
        "feedback_text": render(dossier),
    }
