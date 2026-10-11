"""Mechanical checks of the layering and the TCB budgets (ARCHITECTURE.md §5.3, §20). Exit 1 on any violation.

Import rules: kernel imports nothing of Standard; floors imports only kernel; trusted imports only kernel and itself;
the second judge imports only kernel.canon and kernel.floor0. Every line of kernel/, trusted/ and floors/ is counted
in exactly one budget.
"""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUDGETS = json.loads((ROOT / "tcb-budget.json").read_text())
EXTERNAL = {"cryptography"}
STANDARD = {"kernel", "trusted", "floors", "autonomy", "surface", "compliance", "tools", "tests"}
ALLOWED = {
    "kernel": {"kernel"},
    "floors": {"kernel", "floors"},
    "trusted": {"kernel", "floors", "trusted"},
    "autonomy": {"kernel", "trusted", "autonomy"},
    "surface": {"kernel", "trusted", "autonomy", "surface"},
}
# U may use trusted code only as a library: what reads, signs with its own key, or talks to the gateway.
U_MAY_USE = {"trusted.instruments", "trusted.runtime", "trusted.recipes", "trusted.signing", "trusted.gateway", "trusted.data"}
TCB = ("kernel", "floors", "trusted")
CHECKER_ALLOWED = {"kernel.canon", "kernel.floor0"}


def imports(path: Path, package: str) -> set:
    tree = ast.parse(path.read_text(), str(path))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package.split(".")[: len(package.split(".")) - node.level + 1]
                found.add(".".join(base + ([node.module] if node.module else [])))
            else:
                found.add(node.module)
    return found


def main() -> int:
    problems = []
    for layer, allowed in ALLOWED.items():
        for path in sorted((ROOT / layer).rglob("*.py")):
            package = ".".join(path.relative_to(ROOT).with_suffix("").parts)
            for name in imports(path, package):
                top = name.split(".")[0]
                if top in STANDARD and top not in allowed:
                    problems.append(f"{path.relative_to(ROOT)} imports {name}")
                if layer in ("autonomy", "surface") and top == "trusted" and name not in U_MAY_USE:
                    problems.append(f"{path.relative_to(ROOT)} reaches {name}: U talks to K/T through the gateway")
                if path.name == "checker.py" and layer == "trusted" and top == "kernel" and name not in CHECKER_ALLOWED:
                    problems.append(f"the second judge imports {name}: it must stay independent of the kernel")
    counted = {}
    for budget, spec in ((k, v) for k, v in BUDGETS.items() if not k.startswith("_")):
        lines = 0
        for pattern in spec["files"]:
            for path in sorted(ROOT.glob(pattern)):
                rel = str(path.relative_to(ROOT))
                if rel in counted:
                    problems.append(f"{rel} is counted in {counted[rel]} and {budget}")
                counted[rel] = budget
                lines += len(path.read_text().splitlines())
        print(f"{budget:12} {lines:5} / {spec['ceiling']}")
        if lines > spec["ceiling"]:
            problems.append(f"budget {budget}: {lines} lines over its ceiling {spec['ceiling']}")
    for layer in TCB:
        for path in sorted((ROOT / layer).rglob("*.py")):
            if str(path.relative_to(ROOT)) not in counted:
                problems.append(f"{path.relative_to(ROOT)} is in no budget")
    for p in problems:
        print("VIOLATION", p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
