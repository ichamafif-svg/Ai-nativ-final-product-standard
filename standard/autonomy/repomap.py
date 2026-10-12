"""U — a map of the repository for the agent: modules, their definitions, and who calls what.

Built from the abstract syntax tree of every Python file of one commit, never by running it. It tells the agent what a
change may break before it writes it: the callers of a function, the modules that import another. The map is rebuilt
for every base of main and costs nothing to the judge.
"""
from __future__ import annotations

import ast
from collections import defaultdict


def _signature(fn) -> str:
    args = [a.arg for a in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs]
    return f"{fn.name}({', '.join(args)})"


def _doc(node) -> str:
    doc = ast.get_docstring(node) or ""
    return doc.strip().splitlines()[0][:100] if doc.strip() else ""


class RepoMap:
    def __init__(self, tree):
        """tree: anything with paths() and read(path) -> bytes (a Snapshot)."""
        self.modules, self.calls, self.imports = {}, defaultdict(set), defaultdict(set)
        for path in sorted(p for p in tree.paths() if p.endswith(".py")):
            try:
                module = ast.parse(tree.read(path))
            except (SyntaxError, ValueError):
                self.modules[path] = ["<does not parse>"]
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
