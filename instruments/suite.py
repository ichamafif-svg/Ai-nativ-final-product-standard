"""Test suites: main's tests against a head's code, and a request's acceptance contract (D33, D34).

The program runs as the isolated runner (no key, no network unless the host allows installing dependencies), so the
code under test runs with it. Known limit: code under test runs in the same account as the program that reads its
report; it could forge that report. The verdict of a suite is therefore necessary, never sufficient (§11.4): a
transition never lands on tests alone.

    tests      `green` only if every test main's suite runs on base also runs and passes on head
    contract   on main, before it is signed: `red` when every acceptance test fails, `passes:N`, `empty`
    acceptance on a head: `green` when it carries the contract byte for byte and passes it; `missing`, `altered`,
               `red:N`
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from .tree import DirTree, Measure, verdict

TRAILER = re.compile(r"(?m)^Standard-Request: ([A-Za-z0-9][A-Za-z0-9._-]{0,63})$")


def contract_path(request: str) -> str:
    return f"tests/acceptance/test_{re.sub(r'[^A-Za-z0-9_]', '_', request)}.py"


def load(store, digest: str) -> bytes | None:
    """The bytes a store holds under this digest, only if they hash to it."""
    import hashlib
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest or ""):
        return None
    try:
        data = (Path(store) / digest.split(":")[1]).read_bytes()
    except OSError:
        return None
    return data if "sha256:" + hashlib.sha256(data).hexdigest() == digest else None


def claimed(message: str) -> str | None:
    """The request a commit says it implements (its `Standard-Request:` trailer; untrusted, used only to look)."""
    m = TRAILER.search(message)
    return m[1] if m else None


def run_suite(code: DirTree, suite_files: dict, tests_dir: str, *, install: bool = False) -> Measure:
    """`suite_files` ({path: bytes}) against the code of `code`. The universe is the set of tests the suite runs."""
    work = Path(tempfile.mkdtemp())
    try:
        src, suite = work / "code", work / "suite"
        shutil.copytree(code.files, src, symlinks=True)
        for path, data in suite_files.items():
            (suite / path).parent.mkdir(parents=True, exist_ok=True)
            (suite / path).write_bytes(data)
        (suite / tests_dir).mkdir(parents=True, exist_ok=True)
        python, env = sys.executable, {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(src), "HOME": str(work),
                                       "PYTHONDONTWRITEBYTECODE": "1"}
        if install and (src / "requirements.txt").exists():
            subprocess.run([sys.executable, "-m", "venv", str(work / "venv")], check=True, timeout=300,
                           capture_output=True)
            python = str(work / "venv" / "bin" / "python")
            subprocess.run([python, "-m", "pip", "install", "-q", "--only-binary=:all:", "-r",   # wheels only
                            str(src / "requirements.txt"), "pytest"], check=True, timeout=1800, capture_output=True,
                           env={**env, **{k: v for k, v in os.environ.items() if k.endswith(
                               ("_PROXY", "_proxy", "CA_BUNDLE", "CERT_FILE"))}})
        (work / "pytest.ini").write_text("[pytest]\n")
        report = work / "report.xml"
        subprocess.run([python, "-m", "pytest", "-c", str(work / "pytest.ini"), "--rootdir", str(src), "-p",
                        "no:cacheprovider", "-q", f"--junitxml={report}", str(suite / tests_dir)],
                       cwd=src, env=env, capture_output=True, timeout=1800)
        if not report.exists():
            raise RuntimeError("no test report")
        names, failed, traces = set(), [], []
        for case in ET.parse(report).iter("testcase"):
            if any(child.tag == "skipped" for child in case):
                continue
            name = f"{case.get('classname')}::{case.get('name')}"
            names.add(name)
            bad = [child for child in case if child.tag in ("failure", "error")]
            if bad:
                failed.append(name)
                traces.append(f"{name}\n{(bad[0].get('message') or '')[:300]}\n{(bad[0].text or '')[-1500:]}")
        return Measure(frozenset(), frozenset(names), tuple(failed), tuple(traces))
    finally:
        shutil.rmtree(work, ignore_errors=True)


def suite_of(tree: DirTree, tests_dir: str = "tests") -> dict:
    return {p: tree.read(p) for p in tree.paths() if p.startswith(tests_dir + "/")}


def tests_report(base: DirTree, head: DirTree, *, install: bool = False) -> tuple[str, list]:
    """(status, details): the failing tests with their traces, and main's tests the head no longer runs."""
    try:
        suite = suite_of(base)
        on_base = run_suite(base, suite, "tests", install=install)
        on_head = run_suite(head, suite, "tests", install=install)
        lost = [f"{n}\nruns on main, not on this head" for n in sorted(on_base.covered - on_head.covered)]
        status = verdict("green", Measure(on_base.covered, on_head.covered & on_base.covered, on_head.findings))
        return status, [*on_head.details, *lost][:20]
    except Exception as exc:                               # an exception is a measure: nothing was covered
        return verdict("green", exc), [f"{type(exc).__name__}: {str(exc)[:500]}"]


def _contract(tree: DirTree, request: str, contract: bytes):
    path = contract_path(request)
    return run_suite(tree, {path: contract}, str(Path(path).parent))


def contract_on(main: DirTree, request: str, contract: bytes) -> tuple[str, list]:
    try:
        m = _contract(main, request, contract)
    except Exception as exc:
        return f"uncovered:{type(exc).__name__}", [str(exc)[:300]]
    if not m.covered:
        return "empty", ["the contract collects no test"]
    passing = sorted(m.covered - set(m.findings))
    return ("red", []) if not passing else (f"passes:{len(passing)}", [f"{t}\npasses on main already" for t in passing])


def acceptance_on(head: DirTree, request: str, contract: bytes) -> tuple[str, list]:
    path = contract_path(request)
    if path not in head.paths():
        return "missing", [f"{path} is not in this commit"]
    if head.read(path) != contract:
        return "altered", [f"{path} differs from the signed contract"]
    try:
        m = _contract(head, request, contract)
    except Exception as exc:
        return f"uncovered:{type(exc).__name__}", [str(exc)[:300]]
    if not m.covered:
        return "empty", ["the contract collects no test"]
    return ("green", []) if not m.findings else (f"red:{len(m.findings)}", list(m.details)[:10])
