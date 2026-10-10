"""T07/T08 on GitHub (§8.6, D05).

- remediate: the GraphQL `updateRefs` mutation moves refs/heads/main from `beforeOid` (the judged base) to `afterOid`
  (the judged head), `force: false`. GitHub documents beforeOid as a precondition and the update as atomic: if main
  is not exactly the base, nothing moves. A response with errors is a definitive refusal; a lost response is unknown.
- applied (T08 readback): the compare API says whether main contains the head. Absence is never `not_applied`.
- protections (instrument of the `branch` target): the rules GitHub enforces on main.

The token is the guard's alone, held in the operator process. Proposed heads must already be in the repository
(the agent pushes them to refs/standard/proposals/*, which a ruleset must keep apart from main): an installation
requirement checked by tools/qualify.py, not a property of this code.
"""
from __future__ import annotations

import json
import re
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
    def __init__(self, repository: str, token: str, *, api: str = "https://api.github.com", transport=http):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ValueError("owner/name")
        self.repository, self.token, self.api, self.http = repository, token, api.rstrip("/"), transport
        self._node = None

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
        try:
            node = self._node_id()
        except Exception:
            return "failed"                                 # before the send: nothing left
        status, body = self.http("POST", f"{self.api}/graphql", self.token,
                                 {"query": MUTATION, "variables": {"id": node, "before": base, "after": head}})
        if status == 200 and "data" in body and not body.get("errors"):
            return "ok"
        if status in (200, 400, 401, 403, 404, 409, 422):
            return "failed"                                 # GitHub answered and refused: atomic, nothing moved
        return "unknown"                                    # a server error may follow an applied update

    def applied(self, head: str) -> bool:
        status, body = self.http("GET", f"{self.api}/repos/{self.repository}/compare/{head}...main", self.token)
        return status == 200 and body.get("status") in ("identical", "ahead")

    def protections(self) -> set:
        status, body = self.http("GET", f"{self.api}/repos/{self.repository}/rules/branches/main", self.token)
        if status != 200 or not isinstance(body, list):
            raise RuntimeError(f"rules lookup: {status}")
        return {rule.get("type") for rule in body}
