"""Banned APIs (catalog/blocks.toml): product code reaches what a building block covers only through it.

Python is read on its syntax tree with imports resolved, as instruments/surfaces.py reads it; JavaScript lexically
(comments and strings removed). Patterns:

    import:M  call:Q  call-kw:Q:K=V  call-dyn:NAME:I  builtin:N  attr-set:A  js-call:Q[:arg]  js-word:W  js-import:M

`*` in a qualified name matches one or more segments. The fact the scanner signs on a transition is `blocks`:
`clean` when the change adds no use of a banned API, `breaks:<n>` otherwise, with `path:line:pattern` details.
Like `regressions`, it judges the change, not the past: a product adopts the blocks one file at a time.
"""
from __future__ import annotations

import ast
import re
from collections import Counter
from fnmatch import fnmatchcase

from .surfaces import JS, PY, SKIP, MAX_FILE, _strip_js


def _matches(qual: str, pattern: str) -> bool:
    return qual == pattern or fnmatchcase(qual, pattern) or (pattern.startswith("*.") and qual.endswith(pattern[1:]))


class _Uses(ast.NodeVisitor):
    def __init__(self, patterns):
        self.patterns, self.alias, self.hits, self.calls = patterns, {}, [], set()

    def qual(self, node) -> str:
        if isinstance(node, ast.Call):
            return self.qual(node.func)
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            return ".".join([self.alias.get(node.id, node.id), *reversed(parts)])
        if isinstance(node, ast.Call):
            return ".".join([self.qual(node.func), *reversed(parts)])
        return "?." + ".".join(reversed(parts))

    def visit_ClassDef(self, node):
        self.calls.update(self.qual(base) for base in node.bases)
        self.generic_visit(node)

    def _hit(self, node, pattern):
        self.hits.append((node.lineno, pattern))

    def visit_Assign(self, node):
        self.generic_visit(node)
        value = self.qual(node.value.func if isinstance(node.value, ast.Call) else node.value)
        if not value.startswith("?"):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.alias[target.id] = value

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
        self.calls.add(q)
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


def javascript(source: bytes) -> tuple[str, str]:
    """Resolve direct imports, aliases and literal member access. Ambiguous dynamic calls remain unmeasured."""
    raw = _strip_js(source.decode("utf-8", "replace"), keep_strings=True)
    raw = re.sub(r'''\[\s*(['"])([A-Za-z_$][\w$]*)\1\s*\]''', r".\2", raw)
    code = _strip_js(raw)
    aliases = {}
    for m in re.finditer(r'''import\s*\{([^}]+)\}\s*from\s*(['"])([^'"]+)\2''', raw):
        for part in m[1].split(","):
            names = part.strip().split(" as ")
            if len(names) == 2:
                aliases[names[1].strip()] = names[0].strip()
    for m in re.finditer(r'''\b(?:const|let|var)\s+\{([^}]+)\}\s*=\s*([\w$]+)''', code):
        for part in m[1].split(","):
            names = part.strip().split(":")
            if all(re.fullmatch(r"[\w$]+", n.strip()) for n in names):
                aliases[names[-1].strip()] = m[2] + "." + names[0].strip()
    aliases.update({m[1]: m[2] for m in re.finditer(
        r"\b(?:const|let|var)\s+([\w$]+)(?:\s*:\s*[\w$<>]+)?\s*=\s*([\w$]+(?:\.[\w$]+)*)\s*[;,]", code)})

    def expand(match):
        name, seen = match.group(), set()
        while name.split(".")[0] in aliases and name.split(".")[0] not in seen:
            first, _, rest = name.partition(".")
            seen.add(first)
            name = aliases[first] + ("." + rest if rest else "")
        return name
    # Only code positions are rewritten: words in strings remain data.
    replacements = [(m.start(), m.end(), expand(m)) for m in re.finditer(r"(?<![\w$.])[A-Za-z_$][\w$]*", code)]
    for start, end, value in reversed(replacements):
        raw, code = raw[:start] + value + raw[end:], code[:start] + value + code[end:]
    return raw, code


def analysis_gaps(path: str, source: bytes) -> list[str]:
    if not path.endswith(PY + JS):
        return []
    if len(source) > MAX_FILE:
        return ["source exceeds the static analysis bound"]
    if path.endswith(PY):
        try:
            ast.parse(source)
        except (SyntaxError, ValueError):
            return ["Python source cannot be parsed"]
        return []
    raw, code = javascript(source)
    gaps = []
    if re.search(r"\[[^\]\n]+\]\s*(?:\?\.)?\s*\(", code):
        gaps.append("computed JavaScript call")
    if re.search(r"\b(?:eval|Function|import)\s*\(", code):
        gaps.append("dynamic JavaScript execution or import")
    if re.search(r"`(?:\\.|[^`\\])*\$\{", raw):
        gaps.append("template interpolation needs a JavaScript parser")
    return gaps


def block_calls(path: str, source: bytes, module: str) -> set[str]:
    """Syntactic call sites, not proof that a call executes or guards every entry point."""
    if path.endswith(PY):
        try:
            v = _Uses(())
            v.visit(ast.parse(source))
            return {q for q in v.calls if q.startswith(module + ".")}
        except (SyntaxError, ValueError):
            return set()
    if path.endswith(JS):
        raw, code = javascript(source)
        names = set()
        for m in re.finditer(r'''import\s*\{([^}]+)\}\s*from\s*(['"])([^'"]+)\2''', raw):
            if m[3] == module:
                names.update(part.strip().split(" as ")[0].strip() for part in m[1].split(","))
        return {module + "." + name for name in names if re.search(rf"\b{re.escape(name)}\s*\(", code)}
    return set()


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
        raw, code = javascript(source)
        out = []
        for p in patterns:
            kind, _, rest = p.partition(":")
            if kind == "attr-set":
                rx = re.compile(rf"\.{re.escape(rest)}\s*=(?!=)")
            elif kind == "js-word":
                rx = re.compile(rf"(?<![\w$.]){re.escape(rest)}(?![\w$])")
            elif kind == "js-call":
                target, _, arg = rest.partition(":")
                before = r"(?<![\w$.])" if "." in target else r"(?<![\w$])"   # a bare name may be a method
                rx = re.compile(rf"{before}{re.escape(target)}\s*\(" + (rf"\s*(['\"]){re.escape(arg)}\1" if arg else ""))
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
    gaps = [f"{p}:0:unmeasured:{why}" for p in sorted(changed) if p in head.paths() and not SKIP.search(p)
            for why in analysis_gaps(p, head.read(p))]
    if gaps:
        return "uncovered:analysis", gaps[:50]
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
