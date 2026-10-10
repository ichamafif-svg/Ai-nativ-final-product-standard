"""U04 — the maintenance agent: turn one repair task into one proposed commit, then a signed intent (§11.1, §11.4).

What a model writes is hostile data: it never reaches a working tree, a git process's configuration or a shell. The
commit is built with git plumbing in the agent's own proposals store, from a map {path: bytes} whose paths must lie in
the target's write scope. The agent holds only its own key; it never writes to the maintained repository. Whether the
commit may land is decided by the law, from facts independent instruments observe about this exact transition:
a recipe's output can become autonomous (`reproduced`); a model's judgment needs a signed human review.

Sending repository context to a model is itself an effect of data egress (§7.4): files where a secret is detected
never leave, and the secrets target is never sent to a model at all.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import urllib.request
import uuid
from pathlib import Path

from trusted.instruments import SECRETS, Snapshot
from trusted.recipes import RECIPES
from trusted.signing import Signer, envelope

API = "https://api.anthropic.com/v1/messages"
MODEL = os.environ.get("STANDARD_AGENT_MODEL", "claude-sonnet-5-5")
SEGMENT = r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}"
SOURCE = rf"(?!tests/)(?!\.github/)({SEGMENT}/){{0,8}}{SEGMENT}\.(py|md)"
DEPENDENCIES = r"requirements[A-Za-z0-9_.-]*\.txt|sbom\.json"
WRITE_SCOPE = {
    "vulns": DEPENDENCIES, "licenses": DEPENDENCIES, "sbom": r"sbom\.json", "deps-age": rf"{DEPENDENCIES}|{SOURCE}",
    "sast": SOURCE, "ci": SOURCE, "actions": rf"\.github/workflows/{SEGMENT}\.ya?ml",
}
TASKS = {
    "vulns": "Upgrade the vulnerable pinned dependencies in requirements.txt to the lowest fixed versions; keep exact pins.",
    "deps-age": "Upgrade the pinned dependencies that are a major version behind, adapting the code if needed.",
    "licenses": "Replace dependencies whose license is not permissive.",
    "sast": "Fix the high-severity issues reported by bandit without changing behaviour.",
    "ci": "Make the failing test suite pass by fixing the code, never by weakening tests.",
    "actions": "Pin every GitHub Action to a full commit SHA, with the version in a comment.",
}
NEVER_TO_A_MODEL = {"secrets"}


class AgentError(ValueError):
    pass


def in_scope(target: str, path) -> bool:
    return target in WRITE_SCOPE and isinstance(path, str) and re.fullmatch(WRITE_SCOPE[target], path) is not None


def _git(repo, *args, input: bytes | None = None, env=None) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args], input=input, capture_output=True, timeout=120,
                       env={**os.environ, **(env or {})})
    if r.returncode != 0:
        raise AgentError(f"git {args[0]}: {r.stderr.decode(errors='replace')[:200]}")
    return r.stdout.decode().strip()


def commit_files(store, base: str, files: dict, message: str) -> str:
    """A direct child of base whose tree is base's plus exactly these regular files. No working tree is touched."""
    index = Path(tempfile.mkdtemp()) / "index"
    env = {"GIT_INDEX_FILE": str(index), "GIT_AUTHOR_NAME": "standard-agent", "GIT_AUTHOR_EMAIL": "agent@standard",
           "GIT_COMMITTER_NAME": "standard-agent", "GIT_COMMITTER_EMAIL": "agent@standard",
           "GIT_AUTHOR_DATE": "1970-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "1970-01-01T00:00:00Z"}
    _git(store, "read-tree", base, env=env)
    for path, content in sorted(files.items()):
        blob = _git(store, "hash-object", "-w", "--stdin", input=content)
        _git(store, "update-index", "--add", "--cacheinfo", f"100644,{blob},{path}", env=env)
    tree = _git(store, "write-tree", env=env)
    head = _git(store, "commit-tree", tree, "-p", base, "-m", message, env=env)
    _git(store, "update-ref", f"refs/standard/proposals/{head}", head)
    return head


def model_context(tree, limit: int = 120_000) -> str:
    parts, size = [], 0
    for path in sorted(tree.paths()):
        if not path.endswith((".py", ".md", ".txt", ".toml", ".yml", ".yaml", ".json")):
            continue
        raw = tree.read(path)
        if b"\x00" in raw or any(rx.search(raw) for rx in SECRETS):
            continue                                       # a detected secret never leaves
        try:
            text = raw.decode()
        except UnicodeDecodeError:
            continue
        if size + len(text) > limit:
            break
        parts.append(f"=== {path} ===\n{text}")
        size += len(text)
    return "\n".join(parts)


def claude(prompt: str, key: str) -> dict:
    body = {"model": MODEL, "max_tokens": 16000, "messages": [{"role": "user", "content": prompt}],
            "system": "You are a careful maintenance engineer. Answer with one JSON object and nothing else."}
    req = urllib.request.Request(API, data=json.dumps(body).encode(), method="POST", headers={
        "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        text = "".join(b.get("text", "") for b in json.loads(r.read())["content"])
    return json.loads(text[text.find("{"):text.rfind("}") + 1])


class Agent:
    def __init__(self, signer: Signer, capability: str, store, *, api_key: str | None = None, ask=claude):
        self.signer, self.capability, self.store = signer, capability, Path(store)
        self.api_key, self.ask = api_key, ask

    def craft(self, target_id: str, base: str, law_text: str = "") -> tuple[str, str]:
        """(head, route): "recipe" when an instrument can reproduce it, "review" when a human must."""
        tree = Snapshot(self.store, base)
        recipe = RECIPES.get(target_id)
        if recipe is not None:
            files = recipe(tree)
            if files and any(p not in tree.paths() or tree.read(p) != c for p, c in files.items()):
                return commit_files(self.store, base, files, f"Standard: remediate {target_id}"), "recipe"
            raise AgentError(f"the {target_id} recipe changes nothing")
        if target_id in NEVER_TO_A_MODEL or target_id not in TASKS or not self.api_key:
            raise AgentError(f"{target_id}: no recipe and no model route")
        reply = self.ask(f"Repository files follow. Maintenance target `{target_id}`.\nTask: {TASKS[target_id]}\n"
                         f"{law_text}\nReturn JSON {{\"title\": str, \"files\": {{path: full new content}}}}, "
                         f"changing as few files as possible.\n\n{model_context(tree)}", self.api_key)
        files = reply.get("files") if isinstance(reply, dict) else None
        if not isinstance(files, dict) or not files or not all(in_scope(target_id, p) and isinstance(t, str)
                                                                for p, t in files.items()):
            raise AgentError(f"the repair of {target_id} leaves its write scope")
        title = str(reply.get("title", ""))[:200] or f"remediate {target_id}"
        return commit_files(self.store, base, {p: t.encode() for p, t in files.items()}, f"Standard: {title}"), "review"

    def intent(self, domain: str, at: int, area: str, item: str, base: str, head: str) -> dict:
        body = {"id": f"intent-{uuid.uuid4().hex}", "at": at, "author": self.signer.identity, "under": self.capability,
                "op": "remediate", "args": {"area": area, "item": item, "base": base, "head": head}}
        return envelope(domain, "intent", body, [self.signer])
