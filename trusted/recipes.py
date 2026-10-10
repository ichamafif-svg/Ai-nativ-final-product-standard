"""Recipes: repairs whose content is a pure function of the base tree and trusted data (§11.4).

Autonomy is reproducibility: a repair merges without a human only if an independent instrument recomputes it byte for
byte from the base. The agent runs a recipe to build its commit; the instrument runs it again from its own reading of
the base and compares the whole tree (instruments.reproduced). Because that comparison opens a right, recipes are
trusted code. Repairs that need judgment have no recipe: they need a signed human review.

A tree is anything with `paths()` and `read(path) -> bytes`.
"""
from __future__ import annotations

import json
import re

PIN = re.compile(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)(\s*#.*)?")


def _pins(tree) -> list:
    out = []
    for line in tree.read("requirements.txt").decode().splitlines():
        m = PIN.fullmatch(line.strip())
        if m:
            out.append((m[1].lower(), m[2]))
    return sorted(out)


def sbom(tree) -> dict | None:
    pins = _pins(tree)
    if not pins:
        return None
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"type": "library", "name": n, "version": v, "purl": f"pkg:pypi/{n}@{v}"} for n, v in pins]}
    return {"sbom.json": (json.dumps(doc, indent=2) + "\n").encode()}


def vulns(tree, advisories: dict) -> dict | None:
    """advisories: package -> [[fix versions of one vulnerability], ...]. Each vulnerable pin moves to the smallest
    version that fixes every one of its vulnerabilities; a vulnerability without a fix means no recipe."""
    from packaging.version import InvalidVersion, Version
    target = {}
    for name, vulns_ in advisories.items():
        try:
            target[name.lower()] = str(max(min(Version(v) for v in fixes) for fixes in vulns_))
        except (ValueError, InvalidVersion):
            return None
    if not target:
        return None
    lines = []
    for line in tree.read("requirements.txt").decode().splitlines():
        m = PIN.fullmatch(line.strip())
        lines.append(f"{m[1]}=={target[m[1].lower()]}{m[3] or ''}" if m and m[1].lower() in target else line)
    return {"requirements.txt": ("\n".join(lines) + "\n").encode()}


RECIPES = {"sbom": sbom}          # deterministic without outside data; vulns needs pinned advisories
