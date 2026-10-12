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

import base64
import json
import re
import urllib.request
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


# Remote Git: atomic precondition on main, but a lost answer can never establish absence.
MUTATION = ("mutation($id: ID!, $before: GitObjectID!, $after: GitObjectID!) { updateRefs(input: "
            "{repositoryId: $id, refUpdates: [{name: \"refs/heads/main\", beforeOid: $before, afterOid: $after, "
            "force: false}]}) { clientMutationId } }")


def http(method: str, url: str, token: str, body=None) -> tuple[int, dict]:
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                                          "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


class GitHub:
    profile = "cas"

    def __init__(self, repository: str, token: str, *, api: str = "https://api.github.com", transport=http,
                 push_from=None):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ValueError("owner/name")
        self.repository, self.token, self.api, self.http = repository, token, api.rstrip("/"), transport
        self._node, self.push_from = None, push_from

    def _node_id(self) -> str:
        if self._node is None:
            status, body = self.http("GET", f"{self.api}/repos/{self.repository}", self.token)
            if status != 200:
                raise RuntimeError(f"repository lookup: {status}")
            self._node = body["node_id"]
        return self._node

    def remediate(self, resource: str, args: dict, reservation_key: str) -> str:
        base, head = args["base"], args["head"]
        if not SHA.fullmatch(base) or not SHA.fullmatch(head):
            return "failed"
        if self.push_from:
            return self._push(base, head)
        else:
            try:
                node = self._node_id()
            except Exception:
                return "failed"                             # before the send: nothing left
            status, body = self.http("POST", f"{self.api}/graphql", self.token,
                                     {"query": MUTATION, "variables": {"id": node, "before": base, "after": head}})
        if status == 200 and "data" in body and not body.get("errors"):
            return "ok"
        if status in (200, 400, 401, 403, 404, 409, 422):
            return "failed"                                 # GitHub answered and refused: atomic, nothing moved
        return "unknown"                                    # a server error may follow an applied update

    def _push(self, base: str, head: str) -> str:
        auth = base64.b64encode(f"x-access-token:{self.token}".encode()).decode()
        r = subprocess.run(["git", "-C", str(self.push_from), "-c", f"http.extraHeader=Authorization: Basic {auth}",
                            "-c", "remote.origin.mirror=false",
                            "push", "--porcelain", f"--force-with-lease=refs/heads/main:{base}", "origin",
                            f"{head}:refs/heads/main"], capture_output=True, text=True, timeout=300)
        if r.returncode == 0:
            return "ok"
        return "failed" if "[rejected]" in r.stdout or "[remote rejected]" in r.stdout else "unknown"

    def applied(self, head: str) -> bool:
        status, body = self.http("GET", f"{self.api}/repos/{self.repository}/compare/{head}...main", self.token)
        return status == 200 and body.get("status") in ("identical", "ahead")

    def perform(self, resource: str, args: dict, reservation_key: str) -> str:
        return self.remediate(resource, args, reservation_key)

    def read(self, it: dict, key: str) -> str | None:
        return "applied" if self.applied(it["args"]["head"]) else None

    def satisfied(self, it: dict) -> bool:
        return self.applied(it["args"]["head"])

    def protections(self) -> set:
        status, body = self.http("GET", f"{self.api}/repos/{self.repository}/rules/branches/main", self.token)
        if status != 200 or not isinstance(body, list):
            raise RuntimeError(f"rules lookup: {status}")
        return {rule.get("type") for rule in body}
