"""T06 — instruments: what the scanner measures, and the one rule that turns a measure into a status (§7.3).

These facts can open rights (an autonomous repair needs `tests = green` and `reproduced = yes`), so they belong to
the effective TCB: own budget, own identity, no agent key, never driven by the content they measure.

Rules carried from the findings register:
- a pass is a proof of coverage: a status equals the expected one only when the whole non-empty universe was covered
  without finding; an exception, a skipped element or an empty universe is `uncovered` (M2-r1: never "OK by default");
- the universe is fixed by Standard, not by the measured content (R12, M2-r2): every tracked file is in the secrets
  universe whatever its bytes; every `uses` of a parsed workflow counts; the lock is the dependency universe and any
  other manifest makes it uncovered (R13);
- one immutable snapshot per measurement (R07): a checkout is read at one commit, and every fact names it;
- tests run main's suite against the head's code with an empty runner configuration (M2-r2); their verdict is
  necessary, never sufficient (§11.4);
- `reproduced` recomputes a recipe from the base and compares the whole tree, modes and gitlinks included.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from .signing import Signer, envelope

PIN = re.compile(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)")
OTHER_MANIFESTS = ("setup.py", "setup.cfg", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock")
SECRETS = [re.compile(p) for p in (
    rb"AKIA[0-9A-Z]{16}", rb"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----", rb"gh[pousr]_[A-Za-z0-9]{36,}",
    rb"sk-ant-[A-Za-z0-9_-]{20,}", rb"xox[baprs]-[A-Za-z0-9-]{10,}",
    rb"(?i)(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"][A-Za-z0-9/+_=-]{16,}['\"]")]
MAX_FILE = 5_000_000
WORKFLOW = re.compile(r"\.github/workflows/[^/]+\.ya?ml|(.*/)?action\.ya?ml")


@dataclass(frozen=True)
class Measure:
    universe: frozenset
    covered: frozenset
    findings: tuple = ()


def verdict(expect: str, measure) -> str:
    """The only place a status is decided."""
    if isinstance(measure, BaseException):
        return f"uncovered:{type(measure).__name__}"
    if not measure.universe:
        return "uncovered:empty"
    missing = measure.universe - measure.covered
    if missing:
        return f"uncovered:{len(missing)}"
    return f"found:{len(measure.findings)}" if measure.findings else expect


def git(repo, *args, check=True, input=None) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, input=input, timeout=300)
    if check and r.returncode != 0:
        raise RuntimeError(f"git {args[0]}: {r.stderr.decode(errors='replace')[:200]}")
    return r.stdout.decode(errors="replace")


class Snapshot:
    """The tracked tree of one exact commit, read from the object store: no working tree, no checkout to tamper with.
    Entries keep their mode, so a mode change or a gitlink is part of the tree."""

    def __init__(self, repo, commit: str):
        self.repo, self.commit = Path(repo), git(repo, "rev-parse", "--verify", commit + "^{commit}").strip()
        self.entries = {}
        for line in git(repo, "ls-tree", "-r", "-z", "--full-tree", self.commit).split("\0"):
            if line:
                meta, path = line.split("\t", 1)
                mode, kind, sha = meta.split()
                self.entries[path] = (mode, kind, sha)

    def paths(self) -> set:
        return {p for p, (_, kind, _) in self.entries.items() if kind == "blob"}

    def read(self, path: str) -> bytes:
        mode, kind, sha = self.entries[path]
        if kind != "blob" or mode == "120000":
            raise FileNotFoundError(path)                  # symlinks and gitlinks are never followed
        return subprocess.run(["git", "-C", str(self.repo), "cat-file", "blob", sha], capture_output=True,
                              check=True, timeout=60).stdout


# ---- probes: snapshot -> Measure ------------------------------------------------------------------------------------
def lock(tree) -> dict:
    present = [m for m in OTHER_MANIFESTS if m in tree.paths()]
    if "pyproject.toml" in tree.paths() and re.search(rb"(?m)^\s*(dependencies|requires)\s*=", tree.read("pyproject.toml")):
        present.append("pyproject.toml")
    if present:
        raise ValueError(f"dependencies declared outside the lock: {present}")
    pins, bad = {}, []
    for line in tree.read("requirements.txt").decode().splitlines():
        line = line.split("#")[0].strip()
        if line:
            m = PIN.fullmatch(line)
            (pins.__setitem__(m[1].lower(), m[2]) if m else bad.append(line[:80]))
    if bad:
        raise ValueError(f"not exact pins: {bad[:3]}")
    return pins


def secrets(tree) -> Measure:
    files, covered, hits = tree.paths(), set(), []
    for p in files:
        data = tree.read(p)
        if len(data) < MAX_FILE:
            covered.add(p)
            hits += [p for rx in SECRETS if rx.search(data)]
    return Measure(frozenset(files), frozenset(covered), tuple(hits))


def sbom(tree) -> Measure:
    pins = lock(tree)
    listed = set()
    if "sbom.json" in tree.paths():
        listed = {(c["name"], c["version"]) for c in json.loads(tree.read("sbom.json"))["components"]}
    return Measure(frozenset(pins), frozenset(pins), tuple(n for n, v in sorted(pins.items()) if (n, v) not in listed))


def actions(tree) -> Measure:
    files = sorted(p for p in tree.paths() if WORKFLOW.fullmatch(p))
    loose = []
    for p in files:
        for m in re.finditer(rb"(?m)^\s*-?\s*uses:\s*['\"]?([^\s'\"#]+)", tree.read(p)):
            use = m[1].decode()
            if not use.startswith("./") and not re.search(r"@[0-9a-f]{40}$", use):
                loose.append(use)
    if not files:
        return Measure(frozenset({"<no workflow>"}), frozenset({"<no workflow>"}))     # nothing to pin is covered
    return Measure(frozenset(files), frozenset(files), tuple(loose))


def vulns(tree) -> Measure:
    pins = lock(tree)
    r = subprocess.run([sys.executable, "-m", "pip_audit", "-r", "/dev/stdin", "--no-deps", "--disable-pip", "-f",
                        "json", "--progress-spinner", "off"], input=tree.read("requirements.txt"),
                       capture_output=True, timeout=900)
    deps = json.loads(r.stdout)["dependencies"]
    audited = {d["name"].lower() for d in deps if "skip_reason" not in d}
    return Measure(frozenset(pins), frozenset(audited & set(pins)), tuple(v["id"] for d in deps for v in d.get("vulns", [])))


def inventory(tree) -> Measure:
    """Coverage of the declared universe: every tracked path is readable as a blob or a declared gitlink/symlink."""
    universe = frozenset(tree.entries)
    covered = frozenset(p for p, (mode, kind, _) in tree.entries.items() if kind in ("blob", "commit"))
    return Measure(universe, covered)


PROBES = {"secrets": secrets, "sbom": sbom, "actions": actions, "vulns": vulns}


def run_suite(repo, suite_commit: str, code_commit: str, *, install: bool = False) -> Measure:
    """Main's tests/ against the code of `code_commit`, in a fresh environment with an empty runner configuration.
    The universe is the set of tests main's suite runs on main."""
    work = Path(tempfile.mkdtemp())
    code, suite = work / "code", work / "suite"
    for target, commit in ((code, code_commit), (suite, suite_commit)):
        git(repo, "worktree", "add", "--detach", str(target), commit)
    try:
        python = sys.executable
        if install and (code / "requirements.txt").exists():
            venv = work / "venv"
            subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, timeout=300)
            python = str(venv / "bin" / "python")
            subprocess.run([python, "-m", "pip", "install", "-q", "-r", str(code / "requirements.txt"), "pytest"],
                           check=True, timeout=1800)
        (work / "pytest.ini").write_text("[pytest]\n")
        report = work / "report.xml"
        env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(code), "HOME": str(work)}
        subprocess.run([python, "-m", "pytest", "-c", str(work / "pytest.ini"), "--rootdir", str(code), "-p",
                        "no:cacheprovider", "-q", f"--junitxml={report}", str(suite / "tests")],
                       cwd=code, env=env, capture_output=True, timeout=1800)
        if not report.exists():
            raise RuntimeError("no test report")
        names, failed = set(), []
        for case in ET.parse(report).iter("testcase"):
            if any(child.tag == "skipped" for child in case):
                continue
            name = f"{case.get('classname')}::{case.get('name')}"
            names.add(name)
            if any(child.tag in ("failure", "error") for child in case):
                failed.append(name)
        return Measure(frozenset(), frozenset(names), tuple(failed))
    finally:
        for target in (code, suite):
            git(repo, "worktree", "remove", "--force", str(target), check=False)


def tests(repo, base: str, head: str, *, install: bool = False) -> str:
    """`green` only if every test main's suite runs on base also runs and passes on head."""
    try:
        on_base = run_suite(repo, base, base, install=install)
        on_head = run_suite(repo, base, head, install=install)
        return verdict("green", Measure(on_base.covered, on_head.covered & on_base.covered, on_head.findings))
    except Exception as exc:                               # an exception is a measure: nothing was covered
        return verdict("green", exc)


def reproduced(repo, base: str, head: str, recipe) -> str:
    """`yes` only if head is a direct child of base whose whole tree is base plus exactly the recipe's files."""
    try:
        parents = git(repo, "rev-list", "--parents", "-n", "1", head).split()
        if parents[1:] != [git(repo, "rev-parse", base).strip()]:
            return "no:not-a-child"
        b, h = Snapshot(repo, base), Snapshot(repo, head)
        expected = recipe(b)
        if not expected:
            return "no:recipe"
        expected = {p: c for p, c in expected.items() if p not in b.paths() or b.read(p) != c}
        changed = {p for p in b.entries.keys() | h.entries.keys() if b.entries.get(p) != h.entries.get(p)}
        if changed != set(expected):
            return "no:paths"
        if any(h.entries[p][0] != "100644" or h.read(p) != c for p, c in expected.items()):
            return "no:content"
        return "yes"
    except Exception as exc:
        return f"no:{type(exc).__name__}"


# ---- signing measurements -------------------------------------------------------------------------------------------
class Instrument:
    """An instrument identity: turns measures into signed observations under its own capability."""

    def __init__(self, signer: Signer, capability: str, clock):
        self.signer, self.capability, self.clock = signer, capability, clock

    def observation(self, domain: str, resource: str, prop: str, status: str, level: str = "real") -> dict:
        body = {"id": f"obs-{uuid.uuid4().hex}", "at": self.clock(), "author": self.signer.identity,
                "under": self.capability, "resource": resource, "property": prop, "status": status, "level": level}
        return envelope(domain, "observation", body, [self.signer])

    def measure_targets(self, domain: str, repo, commit: str, targets: dict) -> list:
        """Signed observations of every probed floor target at one snapshot of main."""
        tree = Snapshot(repo, commit)
        out = [self.observation(domain, "repo:inventory:all", "coverage", verdict("complete", inventory(tree)))]
        for tid, probe in PROBES.items():
            target = targets.get(tid)
            if target is None:
                continue
            try:
                measure = probe(tree)
            except Exception as exc:
                measure = exc
            out.append(self.observation(domain, target["resource"], target["property"], verdict(target["expect"], measure)))
        return out
