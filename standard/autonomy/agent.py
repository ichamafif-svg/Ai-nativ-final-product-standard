"""U04 — the maintenance agent: turn one repair task into one proposed commit, then a signed intent (§11.1, §11.4).

What a model writes is hostile data: it never reaches a working tree, a git process's configuration or a shell. The
commit is built with git plumbing in the agent's own proposals store, from a map {path: bytes} whose paths must lie in
the target's write scope. The agent holds only its own key; it never writes to the maintained repository. Whether the
commit may land is decided by the law, from facts independent instruments observe about this exact transition:
a recipe's output can become autonomous (`reproduced`); a model's judgment needs a signed human review.

Sending repository context to a model is itself an effect of data egress (§7.4, R15): a detected secret never leaves.
For the secrets target the model sees the files with every detected value replaced by a redaction mark, and a reply
that still contains the mark is refused.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import uuid
from fnmatch import fnmatchcase
from pathlib import Path

from instruments.probes import SECRETS
from instruments.tree import Snapshot
from instruments.data import EMPTY
from instruments.recipes import recipes_for
from bt.signing import Signer, envelope
from .research import Research, ResearchError, relative_path

MODEL = os.environ.get("STANDARD_AGENT_MODEL", "claude-sonnet-5-5")
SEGMENT = r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}"
SOURCE = rf"(?!tests/)(?!\.github/)(?!standard/)({SEGMENT}/){{0,8}}{SEGMENT}\.(py|md)"
DEPENDENCIES = r"requirements[A-Za-z0-9_.-]*\.txt|sbom\.json"
WRITE_SCOPE = {
    "vulns": DEPENDENCIES, "licenses": DEPENDENCIES, "sbom": r"sbom\.json", "deps-age": rf"{DEPENDENCIES}|{SOURCE}",
    "sast": SOURCE, "ci": SOURCE, "secrets": SOURCE, "actions": rf"\.github/workflows/{SEGMENT}\.ya?ml",
}
TASKS = {
    "vulns": "Upgrade the vulnerable pinned dependencies in requirements.txt to the lowest fixed versions; keep exact pins.",
    "deps-age": "Upgrade the pinned dependencies that are a major version behind, adapting the code if needed.",
    "licenses": "Replace dependencies whose license is not permissive.",
    "sast": "Fix the high-severity issues reported by bandit without changing behaviour.",
    "ci": "Make the failing test suite pass by fixing the code, never by weakening tests.",
    "actions": "Pin every GitHub Action to a full commit SHA, with the version in a comment.",
    "secrets": "Remove every hard-coded secret marked <REDACTED>: read it from an environment variable instead.",
}
REDACTED = b"<REDACTED>"


class AgentError(ValueError):
    pass


def in_scope(target: str, path, scopes=None) -> bool:
    if not relative_path(path):
        return False
    if target in WRITE_SCOPE:
        return re.fullmatch(WRITE_SCOPE[target], path) is not None
    if path.split("/")[0] in ("tests", ".github", "standard"):
        return False
    return any(fnmatchcase(path, scope) for scope in (scopes or {}).get(target, []))


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


def model_context(tree, limit: int = 120_000, *, redact: bool = False) -> str:
    parts, size = [], 0
    for path in sorted(tree.paths()):
        if not path.endswith((".py", ".md", ".txt", ".toml", ".yml", ".yaml", ".json")):
            continue
        raw = tree.read(path)
        if b"\x00" in raw:
            continue
        if any(rx.search(raw) for rx in SECRETS):
            if not redact:
                continue                                   # a detected secret never leaves
            for rx in SECRETS:
                raw = rx.sub(REDACTED, raw)
        try:
            text = raw.decode()
        except UnicodeDecodeError:
            continue
        if size + len(text) > limit:
            break
        parts.append(f"=== {path} ===\n{text}")
        size += len(text)
    return "\n".join(parts)


FRONTIER = ("sast", "ci", "deps-age")                  # judgment-heavy: the frontier tier; the rest: small


def dossier(target: dict, status: str, details: list, files: list, check: dict, title: str, risks: str = "") -> str:
    """The commit message a reviewer reads first: why, what, what was already checked, what may go wrong."""
    where = "\n".join(f"  - {d.splitlines()[0][:200]}" for d in details[:10]) or "  - (no location published)"
    return (f"Standard: {title}\n\n"
            f"Why: {target['resource']} must have {target['property']} = {target['expect']}; "
            f"the instrument reports {status}.\n{where}\n\n"
            f"What: {', '.join(files)}\n\n"
            f"Checked by the agent ({check.get('isolation', '?')}): main's tests {check.get('tests', '?')} on this "
            f"commit; no other floor target regressed; no new ruff or mypy error in the changed files.\n"
            f"Target fixed by the agent's measurement: {check.get('fixed', 'unknown')}. "
            f"These are the agent's own checks: the independent instruments measure this commit again.\n"
            + (f"\nRisks: {risks[:1500]}\n" if risks else "")
            + f"\nStandard-Target: {target['id']}\n")


class Agent:
    def __init__(self, signer: Signer, capability, store, *, data=EMPTY, api_key: str | None = None, ask=None,
                 publish=None, llm=None, sandbox=None, iterations: int = 2, scopes=None, research_sources=None):
        """capability: one grant id, or {"recipe": id, "review": id} when the two routes are granted apart.
        data: the same pinned snapshot the instruments use, so that recipes reproduce.
        llm: the egress gate (standard.autonomy.llm.Gate); `api_key` and `ask(prompt, key) -> dict` build one for tests."""
        from .llm import Gate, Provider
        from .sandbox import Sandbox
        self.capabilities = capability if isinstance(capability, dict) else {"recipe": capability, "review": capability}
        self.signer, self.store = signer, Path(store)
        self.data, self.iterations = data, iterations
        self.publish = publish or (lambda head: None)   # e.g. push the branch standard/proposals/<head> on GitHub
        if llm is None and api_key:
            transport = (lambda p, prompt: json.dumps(ask(prompt, api_key))) if ask else None
            llm = Gate({"frontier": Provider("anthropic", "anthropic", MODEL, api_key)},
                       self.store.parent / "egress.log", transport=transport)
        self.llm, self.sandbox = llm, sandbox or Sandbox()
        self.scopes = dict(scopes or {})
        if any(not isinstance(patterns, list) or not patterns or any(not relative_path(p) for p in patterns)
               for patterns in self.scopes.values()):
            raise AgentError("custom repair scopes must be configured lists of relative path patterns")
        self.research = Research(self.llm, self.store.parent / "research.jsonl", sources=research_sources)

    def investigate(self, view, task, base, findings=None):
        from .context import render_context, task_context
        tree = Snapshot(self.store, base)
        prompt = ("Find a way to serve this missing need. Inspect, research, reuse or experiment with a tool. "
                  "Return a summary and proposed tool files if useful, the required independent verification and any "
                  "operator action. Do not claim the requirement is closed or register a new trusted instrument.\n"
                  + render_context(task_context(view, task, findings)))
        try:
            return self.research.dialogue(prompt, tree, key=task["id"])
        except ResearchError as exc:
            raise AgentError(str(exc)) from exc

    def _commit(self, base: str, files: dict, message: str) -> str:
        return commit_files(self.store, base, files, message)

    def craft(self, target_id: str, base: str, *, targets: dict | None = None, finding: dict | None = None,
              lessons: str = "", law_text: str = "") -> tuple[str, str]:
        """(head, route): "recipe" when an instrument can reproduce it, "review" when a human must sign a review.
        Nothing is proposed that the agent's own precheck rejects: it fixes the target, regresses no other one,
        keeps main's tests green and adds no lint or type error."""
        from .precheck import precheck
        from .repomap import RepoMap
        targets = targets or {}
        target = targets.get(target_id, {"id": target_id, "resource": target_id, "property": "?", "expect": "?"})
        finding = finding or {"status": "?", "details": []}
        tree = Snapshot(self.store, base)
        recipe = recipes_for(self.data).get(target_id)
        files = recipe(tree) if recipe is not None else None
        if files and any(p not in tree.paths() or tree.read(p) != c for p, c in files.items()):
            head = self._commit(base, files, f"Standard: remediate {target_id}\n\nStandard-Target: {target_id}\n")
            check = precheck(self.store, base, head, target_id, targets, self.data, self.sandbox, self.store.parent / "venvs") if targets else {}
            if check and not check["ok"]:
                raise AgentError(f"the recipe for {target_id} does not pass the agent's precheck: {check['problems']}")
            self.publish(head)
            return head, "recipe"
        if (target_id not in TASKS and target_id not in self.scopes) or self.llm is None:
            raise AgentError(f"{target_id}: no applicable recipe and no model route")
        feedback, upgrades = "", ""
        if target_id in ("vulns", "deps-age", "licenses"):
            upgrades = json.dumps({n: {k: v for k, v in p.items() if k in ("latest", "changelog", "releases", "license")}
                                   for n, p in self.data.packages.items()}, indent=1)[:6000]
        where = "\n".join(d[:400] for d in finding["details"][:20]) or "(none published)"
        for _ in range(self.iterations):
            instruction = TASKS.get(target_id, "Serve the client requirement using the configured write scope; human review is required.")
            prompt = (f"Repository maintenance. Target `{target_id}`.\nTask: {instruction}\n"
                      f"Requirement: {target['resource']} must have {target['property']} = {target['expect']}; "
                      f"the independent instrument reports {finding['status']}.\nWhere:\n{where}\n{law_text}\n"
                      + (f"Earlier attempts that did not pass:\n{lessons}\n" if lessons else "")
                      + (f"Your previous candidate was rejected by your own checks:\n{feedback}\n" if feedback else "")
                      + (f"Release data of the pinned dependencies:\n{upgrades}\n" if upgrades else "")
                      + f"Repository map:\n{RepoMap(tree).render(focus=[d.split(':')[0] for d in finding['details']])}\n"
                      f"Return JSON {{\"title\": str, \"files\": {{path: full new content}}, \"risks\": str}}, "
                      f"changing as few files as possible.\n\n"
                      f"{model_context(tree, redact=target_id == 'secrets')}")
            try:
                reply = self.research.dialogue(prompt, tree, tier="frontier" if target_id in FRONTIER else "small",
                                               key=f"repair:{target_id}")
            except ResearchError as exc:
                raise AgentError(str(exc)) from exc
            files = reply.get("files")
            if not isinstance(files, dict) or not files or not all(in_scope(target_id, p, self.scopes) and isinstance(c, str)
                                                                    for p, c in files.items()):
                raise AgentError(f"the repair of {target_id} leaves its write scope")
            if any(REDACTED.decode() in c for c in files.values()):
                raise AgentError("the reply still carries a redaction mark")
            title = str(reply.get("title", ""))[:200] or f"remediate {target_id}"
            head = self._commit(base, {p: c.encode() for p, c in files.items()},
                                f"Standard: {title}\n\nStandard-Target: {target_id}\n")
            check = precheck(self.store, base, head, target_id, targets, self.data, self.sandbox, self.store.parent / "venvs") if targets else {
                "ok": True, "isolation": self.sandbox.isolation, "tests": "?"}
            if check["ok"]:
                message = dossier(target, finding["status"], finding["details"], sorted(files), check, title,
                                  str(reply.get("risks", "")))
                head = self._commit(base, {p: c.encode() for p, c in files.items()}, message)
                self.publish(head)
                return head, "review"
            feedback = "\n".join(check["problems"])[:4000]
        raise AgentError(f"no candidate for {target_id} passed the agent's precheck: {feedback[:1500]}")

    def intent(self, domain: str, at: int, area: str, item: str, base: str, head: str, route: str = "recipe") -> dict:
        body = {"id": f"intent-{uuid.uuid4().hex}", "at": at, "author": self.signer.identity,
                "under": self.capabilities[route],
                "op": "remediate", "args": {"area": area, "item": item, "base": base, "head": head}}
        return envelope(domain, "intent", body, [self.signer])
