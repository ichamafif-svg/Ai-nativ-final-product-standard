"""T01 — the identity of the code release: one digest over every source file of the TCB (kernel, floors, trusted).

The genesis binds it; the kernel refuses a state that belongs to another release (HIST.CODE). Computing it here does
not prove that the running process loaded these files: that is the installation's part of T01 (immutable install,
verified before import and before any secret is read).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from kernel.canon import digest

TCB = ("kernel", "floors", "trusted")


def code_digest(root=None) -> str:
    root = Path(root) if root else Path(__file__).resolve().parents[1]
    files = {}
    for package in TCB:
        for path in sorted((root / package).rglob("*.py")):
            files[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest({"format": "standard-release/1", "files": files})
