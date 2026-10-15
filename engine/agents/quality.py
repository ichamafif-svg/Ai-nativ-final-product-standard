"""U — the quality of a candidate beyond green tests (D70): how strong its tests are, how complex and how duplicated
its new code is. Measured in the agent's own precheck, on the exact candidate, never trusted as a fact.

- Mutation: small changes to the candidate's changed lines (an operator, a comparison, a constant, a return) run
  against main's tests in the bac. A change the tests still pass is a mutant that survived: the tests do not see
  that behaviour. Agents may not write tests in a maintained repository, so survivors go to the human (who signs
  acceptance contracts), never back as a reason to refuse the candidate.
- Complexity: cyclomatic complexity (radon) of the functions the candidate adds or changes.
- Duplication: windows of normalised lines the candidate adds that already exist elsewhere in the repository.
Complexity and duplication are the agent's own code: when they cross the limits below they are problems to fix.
"""
from __future__ import annotations

import ast
import re
import shutil
import tempfile
from pathlib import Path

import engine.verification.probes as probes

MUTANTS = 6                 # at most this many mutants per candidate: a sample, not a census
COMPLEXITY = 15             # a new or grown function above this is a problem
WINDOW = 8                  # this many identical normalised lines copied from elsewhere is a problem
SWAP = {ast.Add: ast.Sub, ast.Sub: ast.Add, ast.Mult: ast.FloorDiv, ast.Eq: ast.NotEq, ast.NotEq: ast.Eq,
        ast.Lt: ast.GtE, ast.GtE: ast.Lt, ast.Gt: ast.LtE, ast.LtE: ast.Gt, ast.And: ast.Or, ast.Or: ast.And}


def changed_lines(store, base: str, head: str, path: str) -> set[int]:
    diff = probes.git(store, "diff", "-U0", base, head, "--", path)
    lines = set()
    for m in re.finditer(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", diff, re.M):
        start, count = int(m.group(1)), int(m.group(2) or 1)
        lines.update(range(start, start + count))
    return lines


def _is_source(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return path.endswith(".py") and not path.startswith("tests/") and not name.startswith("test_")


def mutants(source: str, lines: set[int]) -> list[tuple[int, str, str]]:
    """(line, description, mutated source) for the first MUTANTS mutation points on `lines`."""
    tree = ast.parse(source)
    points = []
    for node in ast.walk(tree):
        if getattr(node, "lineno", None) not in lines:
            continue
        if isinstance(node, (ast.BinOp, ast.BoolOp)) and type(node.op) in SWAP:
            points.append((node, "op"))
        elif isinstance(node, ast.Compare) and len(node.ops) == 1 and type(node.ops[0]) in SWAP:
            points.append((node, "cmp"))
        elif isinstance(node, ast.Constant) and isinstance(node.value, bool):
            points.append((node, "bool"))
        elif isinstance(node, ast.Return) and node.value is not None:
            points.append((node, "return"))
    out = []
    for node, kind in sorted(points, key=lambda p: (p[0].lineno, p[0].col_offset))[:MUTANTS]:
        before = ast.unparse(node)
        saved = (getattr(node, "op", None), getattr(node, "ops", None), getattr(node, "value", None))
        if kind == "op":
            node.op = SWAP[type(node.op)]()
        elif kind == "cmp":
            node.ops = [SWAP[type(node.ops[0])]()]
        elif kind == "bool":
            node.value = not node.value
        else:
            node.value = ast.Constant(None)
        out.append((node.lineno, f"`{before}` -> `{ast.unparse(node)}`", ast.unparse(tree)))
        if kind == "op":
            node.op = saved[0]
        elif kind == "cmp":
            node.ops = saved[1]
        else:
            node.value = saved[2]
    return out


def mutation(sandbox, store, base: str, head: str, changed: list, run_tests) -> dict:
    """Run main's tests on each mutant of the candidate's changed lines. `run_tests(tree)` -> True when green."""
    survivors, killed, total = [], 0, 0
    with sandbox.checkout(store, head) as code:
        for path in [p for p in changed if _is_source(p) and (code / p).exists()]:
            source = (code / path).read_text(errors="replace")
            try:
                found = mutants(source, changed_lines(store, base, head, path))
            except SyntaxError:
                continue
            for line, change, mutated in found:
                total += 1
                with tempfile.TemporaryDirectory(prefix="mutant-") as tmp:
                    tree = Path(tmp) / "tree"
                    shutil.copytree(code, tree, ignore=shutil.ignore_patterns(".git"))
                    (tree / path).write_text(mutated)
                    if run_tests(tree):
                        survivors.append({"where": f"{path}:{line}", "change": change})
                    else:
                        killed += 1
    return {"mutants": total, "killed": killed, "survivors": survivors,
            "score": round(killed / total, 3) if total else None}


def complexity(store, base: str, head: str, changed: list) -> list[dict]:
    """Functions the candidate adds or grows above COMPLEXITY."""
    from radon.complexity import cc_visit
    out = []
    for path in [p for p in changed if _is_source(p)]:
        def scores(commit):
            try:
                return {b.fullname: b.complexity for b in cc_visit(probes.git(store, "show", f"{commit}:{path}"))}
            except Exception:
                return {}
        before, after = scores(base), scores(head)
        out += [{"where": path, "function": name, "complexity": value, "before": before.get(name)}
                for name, value in sorted(after.items())
                if value > COMPLEXITY and value > before.get(name, 0)]
    return out


def _normal(line: str) -> str:
    return re.sub(r"\s+", " ", line.split("#", 1)[0]).strip()


def duplication(store, base: str, head: str, changed: list) -> list[dict]:
    """Windows of WINDOW normalised lines the candidate adds that already exist in another file of the repository."""
    files = [p for p in probes.git(store, "ls-tree", "-r", "--name-only", head).split() if _is_source(p)]
    seen = {}
    for path in files:
        if path in changed:
            continue
        lines = [_normal(x) for x in probes.git(store, "show", f"{head}:{path}").splitlines()]
        lines = [x for x in lines if x]
        for i in range(len(lines) - WINDOW + 1):
            seen.setdefault("\n".join(lines[i:i + WINDOW]), f"{path}")
    out = []
    for path in [p for p in changed if _is_source(p) and p in files]:
        added = changed_lines(store, base, head, path)
        raw = probes.git(store, "show", f"{head}:{path}").splitlines()
        numbered = [(n, _normal(x)) for n, x in enumerate(raw, 1) if _normal(x)]
        for i in range(len(numbered) - WINDOW + 1):
            window = numbered[i:i + WINDOW]
            if not any(n in added for n, _ in window):
                continue
            other = seen.get("\n".join(x for _, x in window))
            if other:
                out.append({"where": f"{path}:{window[0][0]}", "copy_of": other})
                break
    return out
