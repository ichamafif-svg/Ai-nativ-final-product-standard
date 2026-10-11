"""T07/T08 — provider adapters for `remediate`: move main fast-forward from an exact base to an exact child head.

An adapter is trusted code: it holds the write credential, receives only the judged canonical request, and must use a
primitive that guarantees the precondition atomically (§8.6, D05). Otherwise the route is inexecutable.

- GitRepository: a repository on the guard's host. `git update-ref refs/heads/main HEAD BASE` is an atomic
  compare-and-swap: it moves main only if main is still exactly BASE. The head is fetched from the proposals store
  first; the agent never writes to the maintained repository.
- read (T08, D38 RESOLVE): `applied` when main contains head. `update-ref` runs to completion inside the adapter, and
  main only moves forward by the guard's own compare-and-swap: once the adapter returned, a head main does not contain
  was never written and no request can still land, so `not_applied` is established, for this reservation (D09).
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path


SHA = re.compile(r"[0-9a-f]{40}")


def _git(repo, *args) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=300)


class GitRepository:
    profile = "cas"

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

    perform = remediate

    def applied(self, head: str) -> bool:
        return _git(self.repo, "merge-base", "--is-ancestor", head, f"refs/heads/{self.branch}").returncode == 0

    def read(self, it: dict, key: str) -> str:
        return "applied" if self.applied(it["args"]["head"]) else "not_applied"

    def satisfied(self, it: dict) -> bool:
        return self.applied(it["args"]["head"])
