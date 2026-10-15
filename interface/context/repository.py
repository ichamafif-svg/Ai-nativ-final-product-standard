"""U — a map of the repository for the agent: modules, their definitions, and who calls what.

Built from Python syntax trees and lexical JavaScript/TypeScript descriptions of one commit, never by running it. It tells the agent what a
change may break before it writes it: the callers of a function, the modules that import another. The map is rebuilt
for every base of main and costs nothing to the judge.
"""
from __future__ import annotations

import ast
import re
from collections import defaultdict
from engine.verification.surfaces import JS, describe, _strip_js


def _signature(fn) -> str:
    args = [a.arg for a in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs]
    return f"{fn.name}({', '.join(args)})"


def _doc(node) -> str:
    doc = ast.get_docstring(node) or ""
    return doc.strip().splitlines()[0][:100] if doc.strip() else ""


def _is_test(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return (path.startswith("tests/") or "/tests/" in path or name.startswith("test_") or name.endswith("_test.py")
            or ".test." in name or ".spec." in name)


class RepoMap:
    def __init__(self, tree):
        """tree: anything with paths() and read(path) -> bytes (a Snapshot)."""
        self.modules, self.calls, self.imports = {}, defaultdict(set), defaultdict(set)
        for path in sorted(p for p in tree.paths() if p.endswith((".py", *JS))):
            if path.endswith(JS):
                source = tree.read(path)
                d = describe(path, source)
                self.imports[path].update(d["imports"])
                code = _strip_js(source.decode("utf-8", "replace"))
                self.modules[path] = [f"export {n}" for n in re.findall(
                    r"\bexport\s+(?:default\s+)?(?:async\s+)?(?:function|class|const|let)\s+([\w$]+)", code)]
                self.modules[path] += [f"endpoint {e}" for e in d["endpoints"]]
                for name in re.findall(r"\b([A-Za-z_$][\w$]*)\s*\(", code):
                    self.calls[name].add(path)
                continue
            try:
                module = ast.parse(tree.read(path))
            except (SyntaxError, ValueError, FileNotFoundError, UnicodeDecodeError):
                self.modules[path] = ["<uninspectable Python source>"]
                continue
            defs = []
            for node in module.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    defs.append(f"def {_signature(node)}  {_doc(node)}".rstrip())
                elif isinstance(node, ast.ClassDef):
                    methods = [_signature(m) for m in node.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]
                    defs.append(f"class {node.name}: {', '.join(methods)}  {_doc(node)}".rstrip())
            self.modules[path] = defs
            for node in ast.walk(module):
                if isinstance(node, ast.Import):
                    self.imports[path] |= {a.name for a in node.names}
                elif isinstance(node, ast.ImportFrom) and node.module:
                    self.imports[path].add(node.module)
                elif isinstance(node, ast.Call):
                    f = node.func
                    name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
                    if name:
                        self.calls[name].add(path)

    def reading(self, focus) -> dict:
        """Before coding (D70): for each file the task touches, its definitions with the code and the tests that use
        them, and the definitions of its neighbours (same directory) to reuse rather than rewrite."""
        out = {}
        for path in sorted(set(focus) & set(self.modules)):
            touched = {}
            for d in self.modules[path]:
                if not d.startswith(("def ", "class ")):
                    continue
                name = d.split()[1].split("(")[0].rstrip(":")
                users = [u for u in self.callers(name) if u != path]
                touched[d] = {"tests": [u for u in users if _is_test(u)],
                              "code": [u for u in users if not _is_test(u)]}
            folder = path.rsplit("/", 1)[0] if "/" in path else ""
            neighbours = {p: self.modules[p] for p in sorted(self.modules)
                          if p != path and not _is_test(p) and (p.rsplit("/", 1)[0] if "/" in p else "") == folder
                          and p not in focus}
            out[path] = {"definitions": touched, "reuse": neighbours,
                         "untested": sorted(d for d, u in touched.items() if not u["tests"])}
        return out

    def callers(self, name: str) -> list:
        return sorted(self.calls.get(name, ()))

    def render(self, limit: int = 12_000, focus=()) -> str:
        """The map as text, the files named in `focus` first, with the callers of what they define."""
        order = sorted(self.modules, key=lambda p: (p not in focus, p))
        lines = []
        for path in order:
            lines.append(f"{path}: imports {', '.join(sorted(self.imports[path])) or '-'}")
            for d in self.modules[path]:
                lines.append(f"  {d}")
                if path in focus and d.startswith("def "):
                    name = d[4:d.index("(")]
                    users = [u for u in self.callers(name) if u != path]
                    if users:
                        lines.append(f"    called from: {', '.join(users)}")
        text = "\n".join(lines)
        return text if len(text) <= limit else text[:limit] + "\n…"
