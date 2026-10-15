"""T01 — one digest over explicitly selected trust-bearing source files.

The genesis binds it; the kernel refuses a state that belongs to another release (HIST.CODE). Computing it here does
not prove that the running process loaded these files: that is the installation's part of T01 (immutable install,
verified before import and before any secret is read).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from kernel.canon import digest

# The bac runs contributors' code for T06 (D68): its definition is trust-bearing, the rest of the platform is not.
CORE = ("kernel", "bt", "enclosure/__init__.py", "enclosure/bac.py", "enclosure/oci.py", "enclosure/capabilities.py",
        "enclosure/seccomp.json")


def code_digest(root=None, *, sources=CORE) -> str:
    """Core by default; installations also name their privileged assembly and release declarations.

    Moving code to standard/ must not remove it from the installation's pin. Missing sources refuse fingerprinting.
    """
    root = Path(root) if root else Path(__file__).resolve().parents[1]
    files = {}
    for source in sources:
        target = root / source
        if not target.exists():
            raise FileNotFoundError(f"release source missing: {source}")
        paths = [target] if target.is_file() else sorted(target.rglob("*.py"))
        if not paths:
            raise ValueError(f"release source is empty: {source}")
        for path in paths:
            files[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest({"format": "standard-release/1", "files": files})
