"""T07/T08 — provider adapters for `remediate`: move main fast-forward from an exact base to an exact child head.

An adapter is trusted code: it holds the write credential, receives only the judged canonical request, and must use a
primitive that guarantees the precondition atomically (§8.6, D05). Otherwise the route is inexecutable.

- GitRepository: a repository on the guard's host. `git update-ref refs/heads/main HEAD BASE` is an atomic
  compare-and-swap: it moves main only if main is still exactly BASE. The head is fetched from the proposals store
  first; the agent never writes to the maintained repository.
- readback (T08): `applied` when main contains head; never `not_applied` by absence (D09).
"""
from __future__ import annotations

import re
import subprocess
import uuid
from pathlib import Path

from .signing import Signer, envelope

SHA = re.compile(r"[0-9a-f]{40}")


def _git(repo, *args) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=300)


class GitRepository:
    def __init__(self, repo, proposals, branch: str = "main"):
        self.repo, self.proposals, self.branch = Path(repo), str(proposals), branch

    def remediate(self, resource: str, args: dict, reservation_key: str) -> str:
        base, head = args["base"], args["head"]
        if not SHA.fullmatch(base) or not SHA.fullmatch(head):
            return "failed"                                  # nothing sent: the arguments cannot name commits
        if _git(self.repo, "fetch", "--no-tags", "-q", self.proposals, head).returncode != 0:
            return "failed"                                  # the head is unreachable: nothing moved
        parents = _git(self.repo, "rev-list", "--parents", "-n", "1", head).stdout.split()
        if parents[1:] != [base]:
            return "failed"                                  # not a direct child of base: never sent
        moved = _git(self.repo, "update-ref", "-m", f"standard {reservation_key}", f"refs/heads/{self.branch}",
                     head, base)
        if moved.returncode == 0:
            return "ok"
        current = _git(self.repo, "rev-parse", f"refs/heads/{self.branch}").stdout.strip()
        return "ok" if current == head else "failed"        # the compare-and-swap refused: main was not base

    def applied(self, head: str) -> bool:
        return _git(self.repo, "merge-base", "--is-ancestor", head, f"refs/heads/{self.branch}").returncode == 0


class Readback:
    """T08: an independent reader of the provider, signing reconciliations under its own capability."""

    def __init__(self, repository: GitRepository, signer: Signer, capability: str, clock):
        self.repository, self.signer, self.capability, self.clock = repository, signer, capability, clock

    def readback(self, intent_id: str, state: dict):
        it = state["intents"][intent_id]
        if it["op"] != "remediate" or not self.repository.applied(it["args"]["head"]):
            return None                                      # unknown stays unknown
        body = {"id": f"rec-{uuid.uuid4().hex}", "at": max(self.clock(), state["last_at"] + 1),
                "author": self.signer.identity, "under": self.capability, "intent": intent_id, "result": "applied"}
        return envelope(state["domain"], "reconciliation", body, [self.signer])
