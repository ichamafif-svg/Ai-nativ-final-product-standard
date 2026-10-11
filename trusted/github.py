"""T07/T08 on GitHub (§8.6, D05).

- remediate: the GraphQL `updateRefs` mutation moves refs/heads/main from `beforeOid` (the judged base) to `afterOid`
  (the judged head), `force: false`. GitHub documents beforeOid as a precondition and the update as atomic: if main
  is not exactly the base, nothing moves. A response with errors is a definitive refusal; a lost response is unknown.
  `push_from=<mirror>` (where GraphQL is unreachable) does the same CAS over git: `push --force-with-lease=main:base`
  sends base as the expected old value and the server refuses the update if main is anything else.
- read (T08, D38 RESOLVE): the compare API says whether main contains the head. A request to a remote provider may
  still land after a lost answer: absence is never `not_applied` (D09).
- protections (instrument of the `branch` target): the rules GitHub enforces on main.

The token is the guard's alone, held in the operator process. Proposed heads must already be in the repository
(the agent pushes them as branches standard/proposals/*, which a ruleset must keep apart from main): an installation
requirement checked by tools/qualify.py, not a property of this code.
"""
from __future__ import annotations

import base64
import json
import re
import subprocess
import urllib.request

SHA = re.compile(r"[0-9a-f]{40}")
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
