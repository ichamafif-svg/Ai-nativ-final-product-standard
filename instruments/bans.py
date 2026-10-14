"""Banned APIs (standard/catalog/blocks.toml): product code reaches what a building block covers only through it.

Python is read on its syntax tree with imports resolved, as instruments/surfaces.py reads it; JavaScript lexically
(comments and strings removed). Patterns:

    import:M  call:Q  call-kw:Q:K=V  call-dyn:NAME:I  builtin:N  attr-set:A  js-call:Q  js-import:M

`*` in a qualified name matches one or more segments. The fact the scanner signs on a transition is `blocks`:
`clean` when the change adds no use of a banned API, `breaks:<n>` otherwise, with `path:line:pattern` details.
Like `regressions`, it judges the change, not the past: a product adopts the blocks one file at a time.
"""
from __future__ import annotations

import ast
import re
from collections import Counter
from fnmatch import fnmatchcase

from .surfaces import JS, PY, SKIP, _strip_js


def _matches(qual: str, pattern: str) -> bool:
    return qual == pattern or fnmatchcase(qual, pattern) or (pattern.startswith("*.") and qual.endswith(pattern[1:]))


class _Uses(ast.NodeVisitor):
    def __init__(self, patterns):
        self.patterns, self.alias, self.hits = patterns, {}, []

    def qual(self, node) -> str:
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            return ".".join([self.alias.get(node.id, node.id), *reversed(parts)])
        return "?." + ".".join(reversed(parts))

    def _hit(self, node, pattern):
        self.hits.append((node.lineno, pattern))

    def visit_Import(self, node):
        for a in node.names:
            self.alias[(a.asname or a.name).split(".")[0]] = a.asname and a.name or a.name.split(".")[0]
            for p in self.patterns:
                if p.startswith("import:") and (a.name == p[7:] or a.name.startswith(p[7:] + ".")):
                    self._hit(node, p)

    def visit_ImportFrom(self, node):
        if node.module and not node.level:
            for a in node.names:
                self.alias[a.asname or a.name] = f"{node.module}.{a.name}"
            for p in self.patterns:
                m = p[7:] if p.startswith("import:") else None
                if m and (node.module == m or node.module.startswith(m + ".")
                          or any(f"{node.module}.{a.name}" == m for a in node.names)):
                    self._hit(node, p)

    def visit_Call(self, node):
        q = self.qual(node.func)
        name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr \
            if isinstance(node.func, ast.Attribute) else ""
        for p in self.patterns:
            kind, _, rest = p.partition(":")
            if kind == "call" and _matches(q, rest):
                self._hit(node, p)
            elif kind == "builtin" and isinstance(node.func, ast.Name) and node.func.id == rest \
                    and rest not in self.alias:
                self._hit(node, p)
            elif kind == "call-kw":
                target, _, kv = rest.rpartition(":")
                key, _, value = kv.partition("=")
                if _matches(q, target) or target == "*":
                    for kw in node.keywords:
                        if kw.arg == key and isinstance(kw.value, ast.Constant) and str(kw.value.value) == value:
                            self._hit(node, p)
            elif kind == "call-dyn":
                target, _, index = rest.rpartition(":")
                i = int(index)
                if (q == target or "." not in target and name == target) and len(node.args) > i \
                        and not (isinstance(node.args[i], ast.Constant) and isinstance(node.args[i].value, str)):
                    self._hit(node, p)
        self.generic_visit(node)


def uses(path: str, source: bytes, patterns) -> list:
    """[(line, pattern)] for one file, sorted."""
    patterns = sorted(set(patterns))
    if path.endswith(PY):
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError):
            return []
        v = _Uses([p for p in patterns if not p.startswith(("js-", "attr-set:"))])
        v.visit(tree)
        return sorted(set(v.hits))
    if path.endswith(JS):
        raw = source.decode("utf-8", "replace")
        code = _strip_js(raw)
        out = []
        for p in patterns:
            kind, _, rest = p.partition(":")
            if kind == "attr-set":
                rx = re.compile(rf"\.{re.escape(rest)}\s*=(?!=)")
            elif kind == "js-call":
                target, _, arg = rest.partition(":")
                rx = re.compile(rf"\b{re.escape(target)}\s*\(" + (rf"\s*(['\"]){re.escape(arg)}\1" if arg else ""))
                code_or_raw = raw if arg else code
                out += [(code_or_raw[:m.start()].count("\n") + 1, p) for m in rx.finditer(code_or_raw)]
                continue
            elif kind == "js-import":
                rx = re.compile(rf"(from\s+|require\s*\(\s*)(['\"]){re.escape(rest)}\2")
                out += [(raw[:m.start()].count("\n") + 1, p) for m in rx.finditer(raw)]
                continue
            else:
                continue
            out += [(code[:m.start()].count("\n") + 1, p) for m in rx.finditer(code)]
        return sorted(set(out))
    return []


def violations(tree, bans: dict, paths=None) -> list:
    """[(path, line, pattern)] in product code (tests and vendored folders aside)."""
    patterns = sorted({p for block in bans.values() for p in block})
    out = []
    for path in sorted(paths if paths is not None else tree.paths()):
        if SKIP.search(path) or path not in tree.paths():
            continue
        out += [(path, line, p) for line, p in uses(path, tree.read(path), patterns)]
    return out


def blocks_fact(base, head, changed, bans: dict) -> tuple[str, list]:
    """(`clean` | `breaks:<n>`, details): uses of banned APIs the change adds, counted per file and pattern so
    moving a line does not count as a new use."""
    if not bans:
        return "clean", []
    vendored = [f"{p}:0:vendored-block" for p in changed if re.search(r"(^|/)standard_blocks/", p)]
    if vendored:                                     # a block is the pinned package, never a copy in the product
        return f"breaks:{len(vendored)}", vendored[:50]
    before = Counter((p, pat) for p, _, pat in violations(base, bans, changed))
    after = violations(head, bans, changed)
    added, seen = [], Counter()
    for path, line, pat in after:
        seen[(path, pat)] += 1
        if seen[(path, pat)] > before[(path, pat)]:
            added.append(f"{path}:{line}:{pat}")
    return ("clean", []) if not added else (f"breaks:{len(added)}", added[:50])
