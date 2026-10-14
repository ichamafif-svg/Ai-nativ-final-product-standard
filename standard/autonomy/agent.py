"""U04 — the repair crafter: turn one repair task into one candidate commit (§11.1, §11.4).

What a model writes is hostile data: it never reaches a working tree, a git process's configuration or a shell. The
commit is built with git plumbing in the agent's own proposals store, from a map {path: bytes} whose paths must lie in
the target's write scope (instruments/scope.py, the same definition the scanner judges `scoped` with). The agent never
writes to the maintained repository. Whether the commit lands is the rules' call, from facts the scanner measures on
this exact transition: a recipe's output is `reproduced`; a model's change lands alone when main's tests pass, nothing
regresses and it stays in scope, unless the rules keep that route for the human.

Sending repository context to a model is itself an effect of data egress (§7.4, R15): a detected secret never leaves.
For the secrets target the model sees the files with every detected value replaced by a redaction mark, and a reply
that still contains the mark is refused.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from instruments.probes import SECRETS
from instruments.tree import Snapshot
from instruments.data import EMPTY
from instruments.recipes import recipes_for
from instruments.scope import relative, repair as in_scope
from .funnel import Funnel
from .research import Research, ResearchError

MODEL = os.environ.get("STANDARD_AGENT_MODEL", "claude-sonnet-5-5")
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


def _git(repo, *args, input: bytes | None = None, env=None) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args], input=input, capture_output=True, timeout=120,
                       env={**os.environ, **(env or {})})
    if r.returncode != 0:
        raise AgentError(f"git {args[0]}: {r.stderr.decode(errors='replace')[:200]}")
    return r.stdout.decode().strip()


def commit_files(store, base: str, files: dict, message: str) -> str:
    """A direct child of base with regular-file edits and explicit null deletions; no working tree is touched."""
    if any(not relative(p) or c is not None and not isinstance(c, bytes) for p, c in files.items()):
        raise AgentError("invalid candidate path or content")
    scratch = Path(tempfile.mkdtemp())
    index = scratch / "index"
    env = {"GIT_INDEX_FILE": str(index), "GIT_AUTHOR_NAME": "standard-agent", "GIT_AUTHOR_EMAIL": "agent@standard",
           "GIT_COMMITTER_NAME": "standard-agent", "GIT_COMMITTER_EMAIL": "agent@standard",
           "GIT_AUTHOR_DATE": "1970-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "1970-01-01T00:00:00Z"}
    try:
        _git(store, "read-tree", base, env=env)
        for path, content in sorted(files.items()):
            if content is None:
                listed = _git(store, "ls-tree", base, "--", path).split()
                if len(listed) < 3 or listed[1] != "blob":
                    raise AgentError("cannot delete a missing file")
                # index-info works in bare stores; NUL termination keeps every path one record.
                _git(store, "update-index", "-z", "--index-info",
                     input=f"0 {listed[2]}\t{path}\0".encode(), env=env)
                continue
            blob = _git(store, "hash-object", "-w", "--stdin", input=content)
            listed = _git(store, "ls-tree", base, "--", path).split()
            mode = "100755" if listed[:1] == ["100755"] else "100644"   # an edited script stays executable
            _git(store, "update-index", "--add", "--cacheinfo", f"{mode},{blob},{path}", env=env)
        tree = _git(store, "write-tree", env=env)
        head = _git(store, "commit-tree", tree, "-p", base, "-m", message, env=env)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    _git(store, "update-ref", f"refs/standard/proposals/{head}", head)
    return head


def model_context(tree, limit: int = 120_000, *, redact: bool = False) -> str:
    from instruments.surfaces import JS, PY, TEMPLATES
    parts, size, omitted = [], 0, []
    for path in sorted(tree.paths()):
        if not path.endswith(PY + JS + TEMPLATES + (".css", ".md", ".txt", ".toml", ".yml", ".yaml", ".json")):
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
            omitted.append(path)
            continue
        parts.append(f"=== {path} ===\n{text}")
        size += len(text)
    return "\n".join(parts) + ("\nContext bound reached; read/search omitted files: " + ", ".join(omitted[:30]) if omitted else "")


FRONTIER = ("sast", "ci", "deps-age")                  # judgment-heavy: the frontier tier; the rest: small
RULES_TASK = ("Bring the failing rules of this category back (each finding names the rule and the check that failed): "
              "use the building block the rule names (standard_blocks.<block>), never the API it bans; declare what a "
              "probe needs (an access id per route, Access(...).bind(app), Oidc(...).bind(app), runtime.install(app)). "
              "Do not weaken or remove a check.")


def task_of(target_id: str) -> str | None:
    """The instruction for a target: a technical measure, or a category of the rule catalog."""
    return TASKS.get(target_id) or (RULES_TASK if target_id.startswith("rules-") else None)


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
    def __init__(self, store, *, data=EMPTY, api_key: str | None = None, ask=None, publish=None, llm=None,
                 sandbox=None, iterations: int = 2, scopes=None, research_sources=None, funnel: bool = True,
                 review=None, research_steps: int = 8):
        """data: the same pinned snapshot the instruments use, so that recipes reproduce. scopes: the write scopes
        the rules give the client's own targets. llm: the egress gate (standard.autonomy.llm.Gate); `api_key` and
        `ask(prompt, key) -> dict` build one for tests."""
        from .llm import Gate, Provider
        from .sandbox import Sandbox
        self.store = Path(store)
        self.data, self.iterations = data, iterations
        self.publish = publish or (lambda head: None)   # e.g. push the branch standard/proposals/<head> on GitHub
        if llm is None and api_key:
            transport = (lambda p, prompt: json.dumps(ask(prompt, api_key))) if ask else None
            llm = Gate({"frontier": Provider("anthropic", "anthropic", MODEL, api_key)},
                       self.store.parent / "egress.log", transport=transport)
        self.llm, self.sandbox = llm, sandbox or Sandbox(cache_roots=(self.store.parent / "venvs",))
        self.scopes = dict(scopes or {})
        if any(not isinstance(patterns, list) or not patterns or any(not relative(p) for p in patterns)
               for patterns in self.scopes.values()):
            raise AgentError("custom repair scopes must be configured lists of relative path patterns")
        self.research = Research(self.llm, self.store.parent / "research.jsonl", sources=research_sources, steps=research_steps)
        self.funnel, self.last_funnel = (Funnel(**(review or {})) if funnel else None), None

    @staticmethod
    def _values(values) -> dict:
        from standard.catalog import effective, load
        return values if values is not None else effective(load(), None)

    def investigate(self, view, task, base, findings=None, *, model=None):
        from .context import model_packet, task_context
        tree = Snapshot(self.store, base)
        prompt = ("Find a way to serve this missing need. Inspect, research, reuse or experiment with a tool. "
                  "Return a summary and proposed tool files if useful, the required independent verification and any "
                  "operator action. Do not claim the requirement is closed or register a new trusted instrument.\n"
                  + model_packet(task_context(view, task, findings, model=model)))
        try:
            return self.research.dialogue(prompt, tree, key=task["id"])
        except ResearchError as exc:
            raise AgentError(str(exc)) from exc

    def _commit(self, base: str, files: dict, message: str) -> str:
        return commit_files(self.store, base, files, message)

    def craft(self, target_id: str, base: str, *, targets: dict | None = None, finding: dict | None = None,
              lessons: str = "", law_text: str = "", values: dict | None = None) -> tuple[str, str]:
        """(head, way): "recipe" when the scanner can reproduce it, "model" when a model wrote it.
        Nothing is proposed that the agent's own precheck rejects: it fixes the target, regresses no other one,
        keeps main's tests green and adds no lint or type error."""
        from .precheck import precheck
        from .repomap import RepoMap
        self.last_funnel = None
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
        if (task_of(target_id) is None and target_id not in self.scopes) or self.llm is None:
            raise AgentError(f"{target_id}: no applicable recipe and no model route")
        feedback, upgrades = "", ""
        if target_id in ("vulns", "deps-age", "licenses"):
            upgrades = json.dumps({n: {k: v for k, v in p.items() if k in ("latest", "changelog", "releases", "license")}
                                   for n, p in self.data.packages.items()}, indent=1)[:6000]
        where = "\n".join(d[:400] for d in finding["details"][:20]) or "(none published)"
        for _ in range(self.iterations):
            instruction = task_of(target_id) or "Serve the client requirement within the write scope the rules give it."
            prompt = (f"Repository maintenance. Target `{target_id}`.\nTask: {instruction}\n"
                      f"Requirement: {target['resource']} must have {target['property']} = {target['expect']}; "
                      f"the independent instrument reports {finding['status']}.\nWhere:\n{where}\n{law_text}\n"
                      + (f"Earlier attempts that did not pass:\n{lessons}\n" if lessons else "")
                      + (f"Your previous candidate was rejected by your own checks:\n{feedback}\n" if feedback else "")
                      + (f"Release data of the pinned dependencies:\n{upgrades}\n" if upgrades else "")
                      + f"Repository map:\n{RepoMap(tree).render(focus=[d.split(':')[0] for d in finding['details']])}\n"
                      f"Return JSON {{\"title\": str, \"files\": {{path: full new content or null to delete}}, \"risks\": str}}, "
                      f"changing as few files as possible.\n\n"
                      f"{model_context(tree, redact=target_id == 'secrets')}")
            tier = "frontier" if target_id in FRONTIER or target_id.startswith("rules-") else "small"
            try:
                if self.funnel is None:
                    reply = self.research.dialogue(prompt, tree, tier=tier, key=f"repair:{target_id}")
                else:                                       # one writer, parallel read-only reviews of the same draft
                    reply, stats = self.funnel.run(
                        lambda text, role, **kw: self.research.worker(text, role, key=f"repair:{target_id}", tier=tier, **kw),
                        tree, prompt, values=self._values(values), focus=[d.split(":")[0] for d in finding["details"]],
                        scope_ok=lambda path: in_scope(target_id, path, self.scopes))
                    self.last_funnel = stats
                    if stats["remaining"]:
                        feedback = "Candidate checks remain incomplete:\n" + "\n".join(stats["remaining"])
                        continue
            except ResearchError as exc:
                self.last_funnel = self.funnel.last_stats if self.funnel else None
                raise AgentError(str(exc)) from exc
            except ValueError as exc:
                self.last_funnel = self.funnel.last_stats if self.funnel else None
                raise AgentError(f"the repair of {target_id}: {exc}") from exc
            files = reply.get("files")
            if not isinstance(files, dict) or not files or not all(in_scope(target_id, p, self.scopes) and (c is None or isinstance(c, str))
                                                                    for p, c in files.items()):
                raise AgentError(f"the repair of {target_id} leaves its write scope")
            if any(c is not None and REDACTED.decode() in c for c in files.values()):
                raise AgentError("the reply still carries a redaction mark")
            title = str(reply.get("title", ""))[:200] or f"remediate {target_id}"
            encoded = {p: c.encode() if c is not None else None for p, c in files.items()}
            head = self._commit(base, encoded,
                                f"Standard: {title}\n\nStandard-Target: {target_id}\n")
            check = precheck(self.store, base, head, target_id, targets, self.data, self.sandbox, self.store.parent / "venvs") if targets else {
                "ok": True, "isolation": self.sandbox.isolation, "tests": "?"}
            if check["ok"]:
                message = dossier(target, finding["status"], finding["details"], sorted(files), check, title,
                                  str(reply.get("risks", "")))
                head = self._commit(base, encoded, message)
                self.publish(head)
                return head, "model"
            feedback = "\n".join(check["problems"])[:4000]
        raise AgentError(f"no candidate for {target_id} passed the agent's precheck: {feedback[:1500]}")
