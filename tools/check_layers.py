"""Check dependency boundaries, independent verification and kernel purity. No source-line ceilings.

Static checks of ordinary Python imports, not a proof of runtime isolation or physical trust.
Product agents and UI may reach BT only through signing and gateway; runtime assembles privileged roles.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STANDARD = {"kernel", "bt", "instruments", "product", "tools", "tests",
            "trusted", "floors", "autonomy", "surface", "demo"}
ALLOWED = {
    "kernel": ("kernel",),
    "bt": ("kernel", "bt"),
    "instruments": ("kernel", "instruments"),
    "product/__init__.py": (),
    "product/floors.py": ("kernel",),
    "product/runtime": ("kernel", "bt", "instruments", "product.floors", "product.runtime"),
    "product/autonomy": ("kernel", "instruments", "bt.signing", "bt.gateway", "product.autonomy"),
    "product/surface": ("kernel", "instruments", "bt.signing", "bt.gateway", "product.autonomy", "product.surface"),
}
CHECKER_ALLOWED = {"kernel.canon", "kernel.floor0"}
KERNEL_EFFECT_MODULES = {"os", "pathlib", "time", "socket", "sqlite3", "subprocess", "urllib", "http",
                         "threading", "asyncio", "multiprocessing", "io", "random", "secrets", "importlib",
                         "runpy", "pickle", "marshal", "ctypes", "builtins"}


def imports(path: Path, root: Path = ROOT) -> set[str]:
    """Resolve absolute/relative imports and module-valued aliases such as `from . import service`."""
    package = path.relative_to(root).with_suffix("").parts[:-1]
    found = set()
    for node in ast.walk(ast.parse(path.read_text(), str(path))):
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                if node.level > len(package):
                    raise ValueError("relative import escapes its package")
                base = ".".join((*package[:len(package) - node.level + 1], *filter(None, [node.module])))
            else:
                base = node.module or ""
            found.add(base)
            for alias in node.names:
                module = f"{base}.{alias.name}"
                local = root.joinpath(*module.split("."))
                if local.with_suffix(".py").is_file() or (local / "__init__.py").is_file():
                    found.add(module)
    return found


def _within(name: str, allowed) -> bool:
    return any(name == prefix or name.startswith(prefix + ".") for prefix in allowed)


def violations(root: Path = ROOT) -> list[str]:
    problems = []
    for layer, allowed in ALLOWED.items():
        target = root / layer
        if not target.exists():
            problems.append(f"missing layer {layer}")
            continue
        files = [target] if target.is_file() else sorted(target.rglob("*.py"))
        for path in files:
            rel = str(path.relative_to(root))
            try:
                names = imports(path, root)
            except (SyntaxError, ValueError) as exc:
                problems.append(f"{rel}: {exc}")
                continue
            for name in sorted(names):
                top = name.split(".")[0]
                if top in STANDARD and not _within(name, allowed):
                    problems.append(f"{rel} imports {name}: outside {layer}'s boundary")
                if layer == "kernel" and top in KERNEL_EFFECT_MODULES:
                    problems.append(f"{rel} imports {name}: kernel must not perform or observe physical effects")
                if rel == "bt/checker.py" and ((top == "kernel" and name not in CHECKER_ALLOWED) or top == "bt"):
                    problems.append(f"{rel} imports {name}: second judge must remain independent")
    # A new product module must have a declared role, never silently escape the policy.
    for path in sorted((root / "product").rglob("*.py")):
        rel = str(path.relative_to(root))
        if not (rel in ("product/__init__.py", "product/floors.py")
                or any(rel.startswith(prefix + "/") for prefix in
                       ("product/runtime", "product/autonomy", "product/surface", "product/tools", "product/demo"))):
            problems.append(f"{rel}: product module has no declared role")
    return problems


def main() -> int:
    problems = violations()
    for layer in ALLOWED:
        target = ROOT / layer
        files = [target] if target.is_file() else list(target.rglob("*.py"))
        lines = sum(len(p.read_text().splitlines()) for p in files)
        print(f"{layer:24} {len(files):2} files, {lines:5} lines (information only)")
    for problem in problems:
        print("VIOLATION", problem)
    return int(bool(problems))


if __name__ == "__main__":
    sys.exit(main())
