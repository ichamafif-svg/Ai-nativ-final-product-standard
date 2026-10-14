"""U — selected rule context, one writer and two parallel read-only reviewers.

Catalog wide/medium/fine are context selectors, not mandatory generation passes. Reviews share an immutable draft
and get separate research histories. Only the writer edits; bounded corrections must be reviewed again. Reviews,
including an empty report or a reasoned disagreement, are advisory, never scanner facts or admission authority.
"""
from __future__ import annotations

import json
import re
import hashlib
import time
from concurrent.futures import ThreadPoolExecutor
from types import MappingProxyType

from instruments import surfaces
from instruments.bans import blocks_fact
from instruments.scope import relative
from standard.catalog import load, render, select

JUDGED = ("How you will be judged: not by you, by Standard's scanner on the exact commit. It measures main's tests "
          "(green), every floor target and rule category (no regression), your write scope (every path inside it) "
          "and the building blocks (no banned API added). A rule the scanner cannot check is still a rule.")
FORMAT = ('Return JSON {"title": str, "files": {path: full new content or null to delete}, "risks": str}. ')
SIMPLICITY = ("Use the smallest design sufficient for the current requirement. Reuse existing mechanisms. "
              "Justify each new layer, dependency or state by a current need; remove obsolete code instead of "
              "wrapping it. Preserve required behaviour and guarantees. Fewer lines alone are not the goal.")
REVIEWERS = {
    "correctness": "Find behavioural defects, regressions, missing cases and lost security guarantees.",
    "simplicity": "Challenge unnecessary layers, states, dependencies, duplication and premature generalisation. "
                  "Propose a concrete simpler design preserving the requirement and guarantees.",
}
REVIEW_FORMAT = ('Return JSON {"findings": [{"path": str, "issue": str, "effect": str, "suggestion": str}]}. '
                 'Return {"findings": []} when nothing concrete needs changing. Never return files or approval. ')


class Overlay:
    """A tree with some files replaced: the draft on top of its base."""

    def __init__(self, base, files: dict):
        self.base = base
        self.files = MappingProxyType({p: c.encode() if isinstance(c, str) else c for p, c in files.items()})
        changes = [(p, None if c is None else hashlib.sha256(c).hexdigest()) for p, c in sorted(self.files.items())]
        self.commit = "draft:" + hashlib.sha256(json.dumps([getattr(base, "commit", "base"), changes]).encode()).hexdigest()
        entries = dict(getattr(base, "entries", {p: ("100644", "blob", "") for p in base.paths()}))
        for path, content in self.files.items():
            if content is None:
                entries.pop(path, None)
            else:
                mode = "100755" if entries.get(path, (None,))[0] == "100755" else "100644"
                entries[path] = (mode, "blob", hashlib.sha256(content).hexdigest())
        self.entries = MappingProxyType(entries)

    def paths(self):
        return (set(self.base.paths()) | set(self.files)) - {p for p, c in self.files.items() if c is None}

    def read(self, path):
        if path not in self.paths():
            raise FileNotFoundError(path)
        return self.files[path] if path in self.files else self.base.read(path)


def bans_of(cat: dict) -> dict:
    return {name: b["bans"] for name, b in cat["blocks"].items() if b["bans"]}


def house_example(tree, block: str, limit: int = 2, stack: str = "fastapi") -> list:
    """Where this repository already uses the block: the code the agent should look like (deterministic: sorted)."""
    impl = load()["blocks"].get(block, {}).get("stacks", {}).get(stack) or {}
    module = impl.get("module", f"standard_blocks.{block}")
    suffix = surfaces.PY if stack == "fastapi" else surfaces.JS
    out = []
    for path in sorted(p for p in tree.paths() if p.endswith(suffix) and not surfaces.SKIP.search(p)):
        text = tree.read(path).decode("utf-8", "replace")
        if module not in text:
            continue
        names = _names(text, module)
        for n, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith(("from ", "import ")):
                continue
            if module in line or any(re.search(rf"(?<![\w$]){re.escape(name)}\s*\(", line) for name in names):
                out.append(f"{path}:{n}: {line.strip()[:120]}")
                break
        if len(out) >= limit:
            break
    return out


def _names(text: str, module: str) -> list:
    """Names imported from the block: `from m import a, b` or `from m import (a,\n b)`; `x as y` gives y."""
    m = re.search(rf"from {re.escape(module)} import (?:\(([^)]*)\)|([^\n]+))", text)
    if m:
        return [part.split(" as ")[-1].strip() for part in (m.group(1) or m.group(2)).split(",") if part.strip()]
    m = re.search(rf"""import\s*\{{([^}}]*)\}}\s*from\s*['"]{re.escape(module)}['"]""", text)      # JS
    return [part.split(" as ")[-1].strip() for part in m.group(1).split(",") if part.strip()] if m else []


def product_stacks(tree) -> list:
    """The product's stacks (fastapi, nextjs), read from its paths and JS imports only: cheap enough for every pass."""
    files = {p: {"imports": surfaces.describe(p, tree.read(p))["imports"] if p.endswith(surfaces.JS) else []}
             for p in tree.paths() if not surfaces.SKIP.search(p)}
    return surfaces.stacks(files)


def uses(cat: dict, block: str, stacks) -> list:
    """`use` lines of a block for these stacks; a stack without the block says the bans still hold."""
    b = cat["blocks"][block]
    out = []
    for stack in stacks or ["fastapi"]:
        impl = b["stacks"].get(stack) or b["stacks"].get("any") or b["stacks"].get("js")
        out.append(f"use    ({stack}) {impl['use']}" if impl and impl.get("use") else
                   f"use    ({stack}) no block on this stack yet: do not use the banned APIs, ask for a human decision")
    return out


def brief(rules: list, values: dict, tree, cat: dict | None = None) -> str:
    """The rules of one pass: full text for what a block does not absorb fully, one line for the rest, then each
    block's use on the product's stack, then where this repository already uses each block."""
    if not rules:
        return ""
    cat = cat or load()
    stacks = product_stacks(tree)
    lines = [render(r, values, full=r["absorb"] != "full") for r in rules]
    blocks = sorted({r["block"] for r in rules if r["block"] in cat["blocks"]})
    code = [b for b in blocks if any(s in cat["blocks"][b]["stacks"] for s in ("fastapi", "nextjs"))]
    use = [f"block {b}\n" + "\n".join(uses(cat, b, stacks)) for b in code]
    house = [f"  {b}: {e}" for b in code for s in stacks for e in house_example(tree, b, stack=s)]
    return "\n\n".join(lines) + ("\n\nBlocks for this product:\n" + "\n".join(use) if use else "") + \
        ("\n\nThis repository already does it this way:\n" + "\n".join(house) if house else "")


def explain(details, values: dict | None = None, cat: dict | None = None) -> str:
    """The rules behind a refusal, in the text the agent saw before coding: `path:line:pattern` (blocks) names the
    block that bans the pattern; `RULE-ID:` (a rule category) names the rule."""
    cat = cat or load()
    values = values or {}
    by_id = {r["id"]: r for r in cat["rules"]}
    shown, out = set(), []
    for d in details or []:
        d = str(d)
        for rid in re.findall(r"\b([A-Z][A-Z0-9]+(?:-[A-Z0-9]+)*):", d):
            if rid in by_id and rid not in shown:
                shown.add(rid)
                out.append(render(by_id[rid], values))
        m = re.search(r":\d+:((?:import|call|call-kw|call-dyn|builtin|attr-set|js-call|js-import|js-word):\S+)$", d)
        if m:
            block = next((n for n, b in cat["blocks"].items() if m.group(1) in b["bans"]), None)
            if block and f"block:{block}" not in shown:
                shown.add(f"block:{block}")
                b = cat["blocks"][block]
                stacks = [s for s in ("fastapi", "nextjs") if s in b["stacks"]] or ["any"]
                out.append(f"block {block}: {b['does']}\n" + "\n".join(uses(cat, block, stacks)) +
                           f"\nbans   {', '.join(b['bans'])}")
    return "\n\n".join(out)


def relevant(cat, base, draft, touched):
    """Union of context levels, including features the candidate introduces."""
    features = sorted(set(surfaces.scan(base)["features"]) | set(surfaces.scan(draft)["features"]))
    chosen = {r["id"]: r for level in ("wide", "medium", "fine") for r in select(cat, features, touched, level)}
    return [chosen[k] for k in sorted(chosen)]


def review_findings(reply, role, paths):
    if isinstance(reply, dict) and reply.get("action") in ("finish", "propose"):
        reply = {k: v for k, v in reply.items() if k != "action"}
    if not isinstance(reply, dict) or set(reply) != {"findings"} or not isinstance(reply["findings"], list):
        raise ValueError(f"REVIEW_UNAVAILABLE:{role}: expected findings, not files or authority")
    if len(reply["findings"]) > 20:
        raise ValueError(f"REVIEW_UNAVAILABLE:{role}: too many findings")
    out = []
    for i, finding in enumerate(reply["findings"]):
        if (not isinstance(finding, dict) or set(finding) != {"path", "issue", "effect", "suggestion"}
                or any(not isinstance(v, str) or not v.strip() or len(v) > 2000 for v in finding.values())
                or finding["path"] not in paths):
            raise ValueError(f"REVIEW_UNAVAILABLE:{role}: invalid or unlocated finding")
        out.append({"id": f"{role}:{i}", **finding})
    return out


class Funnel:
    """Candidate workflow; the retained name refers to rule selection, not three generation passes."""
    def __init__(self, cat: dict | None = None, *, rounds: int = 2, timeout_s: int = 180):
        if type(rounds) is not int or not 1 <= rounds <= 3 or type(timeout_s) is not int or not 1 <= timeout_s <= 600:
            raise ValueError("review rounds must be 1..3, timeout_s 1..600")
        self.cat, self.rounds, self.timeout_s = cat or load(), rounds, timeout_s
        self.last_stats = None

    def run(self, ask, base, head: str, *, values: dict, scope_ok, focus=(), wide_touched=(), fixed_files=None) -> tuple[dict, dict]:
        """ask(prompt, role, tree=snapshot, read_only=bool) -> dict; only build/correct may return edits.
        The callback must give each role its own history and confine read-only roles to read/search."""
        stats = self.last_stats = {"rounds": [], "remaining": [], "authority": "proposal_only"}
        fixed_files = dict(fixed_files or {})               # human-accepted contract, readable but never editable
        guess = set(wide_touched)
        for path in focus:
            if path in base.paths():
                d = surfaces.describe(path, base.read(path))
                guess |= {f"surface:{s}" for s in d["surfaces"]} | {f"construct:{c}" for c in d["constructs"]}
        rules = relevant(self.cat, base, base, guess)
        design = ""
        if "surface:dependency" in guess or re.search(r"new dependenc|new architecture|nouvelle dépendance|réorganis", head, re.I):
            reply = ask(f"ROLE design: assess the smallest design before implementation. {SIMPLICITY} "
                        f"{REVIEW_FORMAT}\nTask:\n{head}\nRules:\n{brief(rules, values, base, self.cat)}",
                        "design", tree=base, read_only=True)
            design = json.dumps(review_findings(reply, "design", set(base.paths()) | {"."}))
            stats["design"] = design
        files = {}

        def take(reply):
            got = reply.get("files") if isinstance(reply, dict) else None
            if (not isinstance(got, dict) or len(got) > 128
                    or any(not relative(p) or p in fixed_files or not scope_ok(p) or c is not None and not isinstance(c, str)
                           for p, c in got.items())
                    or sum(len(c.encode()) for c in got.values() if c is not None) > 2_000_000):
                raise ValueError("candidate edits are malformed, too large or outside the write scope")
            for path, content in got.items():
                if content is None and path not in base.paths() and path not in files:
                    raise ValueError("cannot delete a path absent from the candidate")
                files[path] = content
                if content is None and path not in base.paths():
                    del files[path]
                elif content is not None and path in base.paths() and base.read(path) == content.encode():
                    del files[path]
            return {k: v for k, v in reply.items() if k != "files"}

        result = take(ask(f"ROLE build: implement the task. {SIMPLICITY}\n{JUDGED}\nTask:\n{head}\n"
                          f"Design observations (advisory): {design or 'none'}\n"
                          f"Relevant rules:\n{brief(rules, values, base, self.cat)}\n{FORMAT}",
                          "build", tree=base, read_only=False))
        for round_no in range(self.rounds):
            if not files:
                raise ValueError("candidate makes no effective change")
            draft = Overlay(base, {**fixed_files, **files})
            touched = set(surfaces.touched(base, draft)) | guess
            rules = relevant(self.cat, base, draft, touched)
            _, left = blocks_fact(base, draft, sorted(files), bans_of(self.cat))
            stats["remaining"] = left
            # Both reviewers receive the exact same snapshot and task, never the writer's rationale.
            material = json.dumps(files, sort_keys=True)
            context = (f"Task and original context:\n{head}\nBase: {getattr(base, 'commit', 'base')}\n"
                       f"Candidate: {draft.commit}\nEdits (null deletes):\n{material}\n"
                       f"Rules:\n{brief(rules, values, draft, self.cat)}\n"
                       f"Deterministic findings:\n{explain(left, values, self.cat)}\n{JUDGED}")
            pool = ThreadPoolExecutor(max_workers=2)
            deadline = time.monotonic() + self.timeout_s
            futures = {role: pool.submit(ask, f"ROLE {role}: {mission} {SIMPLICITY} {REVIEW_FORMAT}\n{context}",
                                         role, tree=draft, read_only=True, deadline=deadline) for role, mission in REVIEWERS.items()}
            try:
                findings = [f for role, future in futures.items() for f in review_findings(
                    future.result(timeout=max(0, deadline - time.monotonic())), role, set(base.paths()) | draft.paths())]
            except Exception as exc:
                stats["error"] = f"REVIEW_UNAVAILABLE:{type(exc).__name__}: {str(exc)[:160]}"
                raise ValueError(stats["error"]) from exc
            finally:
                pool.shutdown(wait=False, cancel_futures=True)
            row = {"candidate": draft.commit, "rules": [r["id"] for r in rules], "findings": findings}
            stats["rounds"].append(row)
            if not findings and not left:
                return {**result, "files": dict(files)}, stats
            reply = ask(f"ROLE correct: you are the sole writer. {SIMPLICITY}\n{context}\n"
                        f"Reviewer observations: {json.dumps(findings)}\n"
                        "Address each observation or decline it with a concrete reason. Do not add unrelated work. "
                        'Include review_responses: [{"id": str, "decision": "fixed" or "declined", "reason": str}]. '
                        f"{FORMAT}Return only edits to this draft; an empty files object retains it.",
                        "correct", tree=draft, read_only=False)
            responses = reply.get("review_responses") if isinstance(reply, dict) else None
            if (not isinstance(responses, list) or len(responses) != len(findings)
                    or any(not isinstance(r, dict) or not isinstance(r.get("id"), str) for r in responses)
                    or {r.get("id") for r in responses if isinstance(r, dict)} != {f["id"] for f in findings}
                    or any(not isinstance(r, dict) or r.get("decision") not in ("fixed", "declined")
                           or not isinstance(r.get("reason"), str) or not 0 < len(r["reason"]) <= 2000 for r in responses)):
                raise ValueError("every review finding needs an explicit disposition")
            row["responses"] = responses
            result.update(take(reply))
            revised = Overlay(base, {**fixed_files, **files})
            if revised.commit == draft.commit:
                if left or any(r["decision"] == "fixed" for r in responses):
                    raise ValueError("claimed correction made no change")
                return {**result, "files": dict(files)}, stats
            # Any edit invalidates the reviews; the next round must inspect the new snapshot.
        stats["error"] = "REVIEW_BUDGET_EXHAUSTED"
        raise ValueError("review budget exhausted; the revised draft has not completed review")


def record(stats: dict) -> str:
    """Compact advisory trace in the existing work/memory records; never an approval."""
    from .llm import redact
    text = json.dumps({"rounds": [{"candidate": r["candidate"], "rules": r["rules"],
                                    "findings": len(r["findings"]), "responses": r.get("responses", [])}
                                   for r in stats.get("rounds", [])],
                       "remaining": len(stats.get("remaining", [])), "error": stats.get("error"),
                       "authority": "proposal_only"}, sort_keys=True)
    return redact(text)[0][:2000]
