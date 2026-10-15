"""Where a move may write: one definition, read by the agent before it proposes and by the scanner that judges.

The scanner signs `scoped = yes` on a transition only when every path the commit changes lies in the write scope of
its move: a repair stays in its target's scope, an implementation in source code plus its own contract file. No move
of the agent ever touches tests (a request's contract aside), the CI, Standard's own directory or the files Python
runs on its own at start-up. The rules may add scopes for the client's own targets (`settings.scopes`); they can
never open the reserved paths.
"""
from __future__ import annotations

import re
from fnmatch import fnmatchcase

from .suite import contract_path

SEGMENT = r"[A-Za-z0-9_(@\[][A-Za-z0-9_.@()\[\]-]{0,99}"
RESERVED = re.compile(r"(tests|\.github|standard)(/.*)?|(.*/)?(conftest|sitecustomize|usercustomize)\.py")
SOURCE = rf"({SEGMENT}/){{0,8}}{SEGMENT}\.(py|md|js|mjs|cjs|jsx|ts|tsx|html|css)"
DEPENDENCIES = r"requirements[A-Za-z0-9_.-]*\.txt|sbom\.json"
FEATURE = rf"({SEGMENT}/){{0,8}}{SEGMENT}\.(py|md|txt|json|toml|ya?ml|sql|html|css|js|mjs|cjs|jsx|ts|tsx)"
REPAIR = {
    "vulns": DEPENDENCIES, "licenses": DEPENDENCIES, "sbom": r"sbom\.json", "deps-age": rf"{DEPENDENCIES}|{SOURCE}",
    "sast": SOURCE, "ci": SOURCE, "secrets": SOURCE, "run-platform": SOURCE,
}
WORKFLOWS = rf"\.github/workflows/{SEGMENT}\.ya?ml"             # the one reserved scope a target owns: `actions`


def relative(path) -> bool:
    return (isinstance(path, str) and bool(path) and len(path) <= 500 and "\\" not in path and "\x00" not in path
            and not path.startswith("/") and all(p not in ("", ".", "..", ".git") for p in path.split("/")))


def repair(target: str, path: str, scopes=None) -> bool:
    """Whether a repair of `target` may write `path`."""
    if not relative(path):
        return False
    if target == "actions":
        return re.fullmatch(WORKFLOWS, path) is not None
    if RESERVED.fullmatch(path):
        return False
    if target in REPAIR:
        return re.fullmatch(REPAIR[target], path) is not None
    if target.startswith("rules-"):                 # a rule is held in the product's code: source, templates, scripts
        return re.fullmatch(FEATURE, path) is not None
    patterns = (scopes or {}).get(target) if isinstance(scopes, dict) else None
    return isinstance(patterns, list) and any(isinstance(p, str) and fnmatchcase(path, p) for p in patterns)


def feature(request: str, path: str) -> bool:
    """Whether an implementation of `request` may write `path`: source code, and its own contract file."""
    if path == contract_path(request):
        return True
    return relative(path) and not RESERVED.fullmatch(path) and re.fullmatch(FEATURE, path) is not None


def changed(base, head) -> list:
    """The paths whose entry differs between two trees (added, changed or removed)."""
    return sorted(p for p in base.entries.keys() | head.entries.keys() if base.entries.get(p) != head.entries.get(p))


def scoped(paths, allowed) -> tuple[str, list]:
    """(`yes` | `no`, the paths outside the scope)."""
    outside = [p for p in paths if not allowed(p)]
    return ("no" if outside or not paths else "yes"), [f"outside the write scope: {p}" for p in outside[:50]]
