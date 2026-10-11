"""Recipes: repairs whose content is a pure function of the base tree and pinned trusted data (§11.4, D16, D17).

Autonomy is reproducibility: a repair merges without a human only if an independent instrument recomputes it byte for
byte from the base. The agent runs a recipe to build its commit; the instrument runs it again from its own reading of
the base and the same pinned data, and compares the whole tree. Because that comparison opens a right, recipes are
trusted code. Repairs that need judgment have no recipe: they need a signed human review.

A tree is anything with `paths()` and `read(path) -> bytes`. `recipes_for(data)` binds a snapshot; a recipe that
changes nothing returns None.
"""
from __future__ import annotations

import json
import re

PIN = re.compile(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)(\s*#.*)?")
USES = re.compile(r"^(\s*-?\s*uses:\s*)([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@([^\s#'\"]+)(.*)$")
SHA = re.compile(r"[0-9a-f]{40}")
WORKFLOW = re.compile(r"\.github/workflows/[^/]+\.ya?ml")


def _pins(tree) -> list:
    out = []
    for line in tree.read("requirements.txt").decode().splitlines():
        m = PIN.fullmatch(line.strip())
        if m:
            out.append((m[1].lower(), m[2]))
    return sorted(out)


def sbom(tree, data=None) -> dict | None:
    pins = _pins(tree)
    if not pins:
        return None
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"type": "library", "name": n, "version": v, "purl": f"pkg:pypi/{n}@{v}"} for n, v in pins]}
    return {"sbom.json": (json.dumps(doc, indent=2) + "\n").encode()}


def vulns(tree, data) -> dict | None:
    """Each vulnerable pin moves to the smallest version that fixes every one of its advisories; an advisory without a
    fix means no recipe (a human decides)."""
    from packaging.version import InvalidVersion, Version
    target = {}
    for name, version in _pins(tree):
        advisories = data.advisories.get(f"{name}=={version}", [])
        if not advisories:
            continue
        try:
            target[name] = str(max(min(Version(v) for v in a["fix_versions"]) for a in advisories))
        except (ValueError, InvalidVersion, KeyError):
            return None
    if not target:
        return None
    lines = []
    for line in tree.read("requirements.txt").decode().splitlines():
        m = PIN.fullmatch(line.strip())
        lines.append(f"{m[1]}=={target[m[1].lower()]}{m[3] or ''}" if m and m[1].lower() in target else line)
    return {"requirements.txt": ("\n".join(lines) + "\n").encode()}


def actions(tree, data) -> dict | None:
    """Pin every `uses: owner/repo@ref` to the commit the pinned snapshot resolves; the ref stays as a comment.
    An unresolved ref means no recipe."""
    out = {}
    for path in sorted(p for p in tree.paths() if WORKFLOW.fullmatch(p)):
        lines, changed = [], False
        for line in tree.read(path).decode().splitlines():
            m = USES.match(line)
            if m and not SHA.fullmatch(m[3]):
                sha = data.actions.get(f"{m[2]}@{m[3]}")
                if sha is None or not SHA.fullmatch(sha):
                    return None
                line, changed = f"{m[1]}{m[2]}@{sha} # {m[3]}", True
            lines.append(line)
        if changed:
            out[path] = ("\n".join(lines) + "\n").encode()
    return out or None


def recipes_for(data) -> dict:
    return {"sbom": lambda tree: sbom(tree), "vulns": lambda tree: vulns(tree, data),
            "actions": lambda tree: actions(tree, data)}
