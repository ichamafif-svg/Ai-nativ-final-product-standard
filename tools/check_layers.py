"""Check dependency boundaries, independent verification and kernel purity. No source-line ceilings.

Static checks of ordinary Python imports, not a proof of runtime isolation or physical trust.
Standard agents and UI may reach BT only through signing and gateway; runtime assembles privileged roles.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STANDARD = {"fabric", "engine", "interface", "tools", "tests", "examples", "standard", "blocks", "standard_blocks",
            "kernel", "bt", "instruments", "catalog", "context", "agent", "surface", "runtime", "enclosure"}
K = "fabric.control.kernel"
BT = "fabric.control.bt"
PLATFORM = ("fabric.runtime", "fabric.network", "fabric.identity", "fabric.data", "fabric.evidence", "fabric.supply_chain")
ALLOWED = {
    "fabric/__init__.py": (),
    "fabric/control/__init__.py": (),
    "engine/__init__.py": (),
    "interface/__init__.py": (),
    "fabric/control/kernel": (K,),
    "fabric/control/bt": (K, BT, "fabric.runtime"),
    "fabric/control/runtime": (K, BT, "engine.verification", "engine.catalog", "fabric.control.runtime", *PLATFORM),
    "fabric/runtime": ("fabric.runtime",),
    "fabric/network": (*PLATFORM, "blocks.python.standard_blocks"),
    "fabric/identity": ("fabric.identity",),
    "fabric/data": ("fabric.data", "fabric.identity"),
    "fabric/evidence": ("fabric.evidence",),
    "fabric/recovery": ("fabric.recovery",),
    "fabric/supply_chain": ("fabric.supply_chain",),
    "engine/verification": (K, "engine.verification", "standard_blocks", *PLATFORM),
    "engine/catalog": (K, "engine.catalog"),
    "engine/agents": (K, "engine.verification", BT + ".signing", BT + ".gateway", "engine.catalog",
                      "interface.context", "engine.agents", "=fabric", *PLATFORM, "blocks.python.standard_blocks"),
    "interface/context": (K, "engine.verification", "engine.catalog", "interface.context", "engine.agents.work",
                          "=fabric", *PLATFORM),
    "interface/surface": (K, "engine.verification", BT + ".signing", BT + ".gateway", "engine.catalog",
                          "interface.context", "engine.agents", "interface.surface", "blocks.python.standard_blocks"),
    "blocks": ("blocks.python.standard_blocks",),
    "tools": (K, BT, "fabric.control.runtime", "fabric.recovery", *PLATFORM, "engine", "interface", "tools", "blocks.python.standard_blocks"),
    "examples": ("standard_blocks",),
}
CHECKER_ALLOWED = {"fabric.control.kernel.canon", "fabric.control.kernel.floor0"}
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
            resolved = False
            for alias in node.names:
                module = f"{base}.{alias.name}"
                local = root.joinpath(*module.split("."))
                if local.with_suffix(".py").is_file() or (local / "__init__.py").is_file():
                    found.add(module)
                    resolved = True
            if not resolved:
                found.add(base)
    return found


def _within(name: str, allowed) -> bool:
    return any(name == prefix[1:] if prefix.startswith("=") else name == prefix or name.startswith(prefix + ".")
               for prefix in allowed)


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
                if layer in ("fabric/__init__.py", "fabric/control/__init__.py", "engine/__init__.py", "interface/__init__.py"):
                    problems.append(f"{rel} imports {name}: namespace root must remain inert")
                if top in STANDARD and not _within(name, allowed):
                    problems.append(f"{rel} imports {name}: outside {layer}'s boundary")
                if layer == "fabric/control/kernel" and top in KERNEL_EFFECT_MODULES:
                    problems.append(f"{rel} imports {name}: kernel must not perform or observe physical effects")
                if rel == "fabric/control/bt/checker.py" and (((name == K or name.startswith(K + ".")) and name not in CHECKER_ALLOWED) or (name == BT or name.startswith(BT + "."))):
                    problems.append(f"{rel} imports {name}: second judge must remain independent")
    # Removed package paths must not silently reintroduce a second implementation.
    if any((root / "standard").rglob("*.py")):
        problems.append("standard/: obsolete parallel package")
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
