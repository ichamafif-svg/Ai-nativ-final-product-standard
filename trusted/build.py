"""T06 — what a request's contract says about a commit (D34).

A request's contract is a file of acceptance tests, written and signed by a person before any code. It lives in the
request store under its sha256 digest (anyone may write the store; nothing is read unless its digest is the one the
signed request names) and lands in the product at tests/acceptance/test_<request>.py.

    contract   on main, before it is signed: `red` when every acceptance test fails (it asks for something main does
               not do yet), `passes:N` when N already pass, `empty` when it collects no test
    acceptance on a transition: `green` when the head carries the contract byte for byte and passes every test,
               `missing` / `altered` when it does not carry it, `red:N` when N fail
    accepted   on main, once contracted: `yes` when main carries the contract unchanged and passes it

The tests run as every contribution's code runs: as the isolated runner (trusted/isolation.py).
"""
from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

from .instruments import git, run_suite

TRAILER = re.compile(r"(?m)^Standard-Request: ([A-Za-z0-9][A-Za-z0-9._-]{0,63})$")


def contract_path(request: str) -> str:
    return f"tests/acceptance/test_{re.sub(r'[^A-Za-z0-9_]', '_', request)}.py"


def load(store, digest: str) -> bytes | None:
    """The bytes the store holds under this digest, only if they hash to it."""
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest or ""):
        return None
    path = Path(store) / digest.split(":")[1]
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return data if "sha256:" + hashlib.sha256(data).hexdigest() == digest else None


def claimed(repo, commit: str) -> str | None:
    """The request a commit says it implements (its `Standard-Request:` trailer; untrusted, used only to look)."""
    m = TRAILER.search(git(repo, "log", "-1", "--format=%B", commit))
    return m[1] if m else None


def _run(repo, commit: str, request: str, contract: bytes):
    return run_suite(repo, None, commit, suite_files={contract_path(request): contract},
                     tests_dir=str(Path(contract_path(request)).parent))


def contract_on(repo, main: str, request: str, contract: bytes) -> tuple[str, list]:
    try:
        m = _run(repo, main, request, contract)
    except Exception as exc:
        return f"uncovered:{type(exc).__name__}", [str(exc)[:300]]
    if not m.covered:
        return "empty", ["the contract collects no test"]
    passing = sorted(m.covered - set(m.findings))
    return ("red", []) if not passing else (f"passes:{len(passing)}", [f"{t}\npasses on main already" for t in passing])


def acceptance_on(repo, head: str, request: str, contract: bytes) -> tuple[str, list]:
    path = contract_path(request)
    r = subprocess.run(["git", "-C", str(repo), "cat-file", "blob", f"{head}:{path}"], capture_output=True, timeout=60)
    if r.returncode != 0:
        return "missing", [f"{path} is not in this commit"]
    if r.stdout != contract:
        return "altered", [f"{path} differs from the signed contract"]
    try:
        m = _run(repo, head, request, contract)
    except Exception as exc:
        return f"uncovered:{type(exc).__name__}", [str(exc)[:300]]
    if not m.covered:
        return "empty", ["the contract collects no test"]
    return ("green", []) if not m.findings else (f"red:{len(m.findings)}", list(m.details)[:10])
