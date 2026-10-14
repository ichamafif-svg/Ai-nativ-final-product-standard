"""Floor probes: one snapshot of main -> one Measure per technical target, and regressions between two trees.

The universe is fixed by Standard, not by the measured content (R12, M2-r2): every tracked file is in the secrets
universe whatever its bytes; every `uses` of a parsed workflow counts; the lock is the dependency universe and any
other manifest makes it uncovered (R13). Findings (path:line:rule) help whoever repairs; a secret's finding names
where it is, never its value.
"""
from __future__ import annotations

import json
import re
from collections import Counter
import subprocess
import sys
import tempfile
from pathlib import Path

from .tree import Measure, git, verdict  # noqa: F401  (git: shared with U's precheck)

PIN = re.compile(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)")
OTHER_MANIFESTS = ("setup.py", "setup.cfg", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock")
SECRETS = [re.compile(p) for p in (
    rb"AKIA[0-9A-Z]{16}", rb"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----", rb"gh[pousr]_[A-Za-z0-9]{36,}",
    rb"sk-ant-[A-Za-z0-9_-]{20,}", rb"xox[baprs]-[A-Za-z0-9-]{10,}",
    rb"(?i)(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"][A-Za-z0-9/+_=-]{16,}['\"]")]
MAX_FILE = 5_000_000
WORKFLOW = re.compile(r"\.github/workflows/[^/]+\.ya?ml|(.*/)?action\.ya?ml")


# ---- probes: snapshot -> Measure ------------------------------------------------------------------------------------
NO_DEPENDENCY = "<no dependency>"


def deps_universe(pins: dict) -> frozenset:
    """An empty, exact lock is a measured fact (nothing to audit), not an empty universe."""
    return frozenset(pins) or frozenset({NO_DEPENDENCY})


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
    """Every tracked regular file is in the universe; a symbolic link is not content and is declared as excluded
    (its target is another tracked path or outside the repository); an unreadable file is uncovered, alone."""
    links = sorted(p for p in tree.paths() if tree.entries[p][0] == "120000")
    files, covered, hits, where = tree.paths() - set(links), set(), [], [f"{p}: symbolic link, excluded" for p in links]
    for p in sorted(files):
        try:
            data = tree.read(p)
        except OSError:
            where.append(f"{p}: unreadable, not covered")
            continue
        if len(data) < MAX_FILE:
            covered.add(p)
            for rule, rx in enumerate(SECRETS):
                lines = sorted({data.count(b"\n", 0, m.start()) + 1 for m in rx.finditer(data)})
                hits += [p] if lines else []
                where += [f"{p}:{n}:secret-rule-{rule}" for n in lines]
    return Measure(frozenset(files), frozenset(covered), tuple(hits), tuple(where))


def sbom(tree) -> Measure:
    pins = lock(tree)
    listed = set()
    if "sbom.json" in tree.paths():
        listed = {(c["name"], c["version"]) for c in json.loads(tree.read("sbom.json"))["components"]}
    stale = sorted(f"{n}=={v} listed, not pinned" for n, v in listed - set(pins.items()))
    return Measure(deps_universe(pins), deps_universe(pins),
                   tuple(n for n, v in sorted(pins.items()) if (n, v) not in listed) + tuple(stale))


def _uses(tree) -> tuple[list, list]:
    files = sorted(p for p in tree.paths() if WORKFLOW.fullmatch(p))
    uses = [m[1].decode() for p in files
            for m in re.finditer(rb"(?m)^\s*-?\s*uses:\s*['\"]?([^\s'\"#]+)", tree.read(p))]
    return files, [u for u in uses if not u.startswith("./")]


def actions(tree, ctx) -> Measure:
    files, uses = _uses(tree)
    if not files:
        return Measure(frozenset({"<no workflow>"}), frozenset({"<no workflow>"}))     # nothing to pin is covered
    return Measure(frozenset(files), frozenset(files), tuple(u for u in uses if not re.search(r"@[0-9a-f]{40}$", u)))


def vulns(tree, ctx) -> Measure:
    """Covered: every pin the pinned advisory snapshot audited. Findings: their advisories."""
    pins, adv = lock(tree), ctx["data"].advisories
    covered = {n for n, v in pins.items() if f"{n}=={v}" in adv} | ({NO_DEPENDENCY} if not pins else set())
    return Measure(deps_universe(pins), frozenset(covered),
                   tuple(a["id"] for n, v in sorted(pins.items()) for a in adv.get(f"{n}=={v}", [])))


PERMISSIVE = {"MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC", "PSF-2.0", "MPL-2.0", "Unlicense", "Zlib"}


def licenses(tree, ctx) -> Measure:
    """The license expression of each exact pin, interpreted by a pinned policy, never by substring (R14)."""
    pins, pkgs = lock(tree), ctx["data"].packages
    covered = {n for n in pins if n in pkgs}
    return Measure(deps_universe(pins), frozenset(covered | ({NO_DEPENDENCY} if not pins else set())),
                   tuple(n for n in sorted(covered) if pkgs[n].get("license") not in PERMISSIVE))


def deps_age(tree, ctx) -> Measure:
    pins, pkgs = lock(tree), ctx["data"].packages
    major = lambda v: int(v.split(".")[0]) if v.split(".")[0].isdigit() else None
    covered = {n for n in pins if n in pkgs and major(pins[n]) is not None and major(pkgs[n]["latest"]) is not None}
    covered |= {NO_DEPENDENCY} if not pins else set()
    return Measure(deps_universe(pins), frozenset(covered),
                   tuple(n for n in sorted(covered) if major(pkgs[n]["latest"]) > major(pins[n])))


def sast(tree, ctx) -> Measure:
    """bandit on the snapshot's Python files, `# nosec` ignored: the measured code does not configure its instrument."""
    files = sorted(p for p in tree.paths() if p.endswith(".py"))
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for p in files:
            (work / p).parent.mkdir(parents=True, exist_ok=True)
            (work / p).write_bytes(tree.read(p))
        r = subprocess.run([sys.executable, "-m", "bandit", "--ignore-nosec", "-f", "json", "-q", "--", *files],
                           cwd=work, capture_output=True, timeout=900)
    data = json.loads(r.stdout)
    covered = {k.removeprefix("./") for k in data["metrics"] if k != "_totals"} - {e["filename"] for e in data["errors"]}
    high = [x for x in data["results"] if x["issue_severity"] == "HIGH"]
    return Measure(frozenset(files), frozenset(covered) & frozenset(files), tuple(x["test_id"] for x in high),
                   tuple(f"{x['filename'].removeprefix('./')}:{x['line_number']}:{x['test_id']} {x['issue_text']}"
                         for x in high))


def branch(tree, ctx) -> Measure:
    """Only the guard may move main: the provider reports the protections in force."""
    need = frozenset({"update", "deletion", "non_fast_forward"})
    return Measure(need, need, tuple(sorted(need - ctx["world"].protections())))


def lineage(tree, ctx) -> Measure:
    """Every commit on main since the anchor is the head of a judged, applied effect: nothing reached main around it."""
    history = ctx["history"]                               # first-parent commits since the anchor, read by the host
    universe = frozenset(history) or frozenset({tree.commit})
    return Measure(universe, universe, tuple(c for c in history if c not in ctx["judged"]))


def inventory(tree) -> Measure:
    """Coverage of the declared universe: every tracked path is a readable blob or a declared gitlink."""
    universe = frozenset(tree.entries)
    return Measure(universe, frozenset(p for p, (_, kind, _) in tree.entries.items() if kind in ("blob", "commit")))


def ci(tree, ctx) -> Measure:
    """Standard's CI: execute the suite of this exact main snapshot, not a provider badge."""
    from .suite import run_suite, suite_of
    return run_suite(tree, suite_of(tree), "tests", install=ctx.get("install", False))


DATA_PROBES = ("vulns", "licenses", "deps-age")
PROBES = {"secrets": lambda t, c: secrets(t), "sbom": lambda t, c: sbom(t), "actions": actions, "vulns": vulns,
          "licenses": licenses, "deps-age": deps_age, "sast": sast, "branch": branch, "lineage": lineage, "ci": ci}


LOCAL_PROBES = ("secrets", "sbom", "actions", "vulns", "licenses", "deps-age", "sast")   # no provider, no ledger


def rule_states(tree, ctx) -> dict:
    """The catalog's rules evaluated on one tree (instruments/coverage.py), once per tree and pass."""
    from . import coverage
    rules = ctx.get("rules") or {}
    if not rules.get("catalog"):
        raise LookupError("no rule catalog in the inputs")
    cache = ctx.setdefault("_rule_states", {})
    key = getattr(tree, "commit", None) or id(tree)
    if key not in cache:
        cache[key] = coverage.evaluate(tree, rules["catalog"], rules.get("values") or {},
                                       declared=rules.get("declared") or (), blocks_paths=rules.get("paths") or ())
    return cache[key]


def probe_for(tid: str, *, regression: bool = False):
    """The probe of a floor target: a fixed one, or a category of the rule catalog (`rules-<category>`)."""
    if tid in PROBES:
        return PROBES[tid]
    if tid.startswith("rules-"):
        from . import coverage
        return lambda tree, ctx: coverage.category_measure(rule_states(tree, ctx), ctx["rules"]["catalog"], tid[6:],
                                                           regression=regression)
    return None
COUNT = re.compile(r"found:(\d+)")


def _worse(expect: str, before: str, after: str) -> bool:
    """Verdict-level comparison, kept for the agent's own precheck (U); the instrument compares measures."""
    if after == expect or after == before:
        return False
    if before == expect or after.startswith("uncovered"):
        return True
    b, a = COUNT.fullmatch(before), COUNT.fullmatch(after)
    return bool(b and a and int(a[1]) > int(b[1]))


LINE_NUMBER = re.compile(r"^([^:\s]+):\d+:")


def _signature(m) -> Counter:
    """What a measure found, independent of where lines moved: located details without their line, else findings."""
    if m.details:
        return Counter(LINE_NUMBER.sub(r"\1:", str(d)) for d in m.details if not str(d).endswith(("excluded",)))
    return Counter(map(str, m.findings))


def worse(before, after) -> list:
    """Why a head is worse than its base on one target, comparing measures, not verdicts: an error where there was
    none, an element left uncovered that was covered, or a finding the base did not have. Empty: not worse."""
    if isinstance(after, BaseException):
        same = isinstance(before, BaseException) and type(before) is type(after)
        return [] if same else [f"{type(after).__name__}: {str(after)[:200]}"]
    if isinstance(before, BaseException):
        before = Measure(after.universe, frozenset())      # nothing was known on the base: every finding is new
    lost = sorted((after.universe - after.covered) - (before.universe - before.covered))
    new = sorted((_signature(after) - _signature(before)).elements())
    return [f"uncovered {x}" for x in lost[:5]] + [f"new {x}" for x in new[:10]]


def regressions(b, h, targets: dict, ctx: dict, follow_ups=frozenset()) -> tuple[str, list]:
    """`none` only if no floor target measured on tree h is worse than on tree b: no new error, no newly uncovered
    element, no new finding (a moved line is not new). A base that was uncovered or failing does not hide what the
    head adds. A target a recipe closes on the next pass (`follow_ups`: a new pin makes the SBOM stale) is not a
    regression of the contribution."""
    try:
        found = []
        for tid in (*LOCAL_PROBES, *sorted(t for t in targets if t.startswith("rules-"))):
            if tid not in targets or tid in follow_ups:
                continue
            measures = []
            for tree in (b, h):
                try:
                    measures.append(probe_for(tid, regression=True)(tree, ctx))
                except Exception as exc:
                    measures.append(exc)
            why = worse(*measures)
            if why:
                found.append(f"{tid}: {'; '.join(why)}")
        return verdict("none", Measure(frozenset({"floors"}), frozenset({"floors"}), tuple(found))), found
    except Exception as exc:                               # an exception is a measure: nothing was covered
        return verdict("none", exc), [f"{type(exc).__name__}: {str(exc)[:300]}"]
