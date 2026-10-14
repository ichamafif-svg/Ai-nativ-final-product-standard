"""U — the funnel: the agent writes a change in three passes, each showing only the rules it can act on.

    wide    shape the change: which surfaces it adds, which building blocks it uses, which values it needs; the
            design rules of the areas it touches (catalog pass `wide`)
    medium  write and wire: the rules of the surfaces the draft actually touches, and what each asks the code to
            bring (an access row, a probe declaration, telemetry)
    fine    tighten: the rules of the constructs in the draft, and every banned API the draft still uses

Each pass is a separate prompt; passes 2 and 3 only retouch the draft; a pass with nothing selected is skipped. After
the last pass the deterministic checks of all passes run again (bans): what remains goes back as feedback. Rule choice
is the catalog's select() on what instruments/surfaces.py reads: deterministic. The text of a rule is the same before
coding and in a refusal (catalog.render).

Nothing here is a fact: the scanner judges the exact commit afterwards. The funnel only makes the first candidate
better and records what it showed, so its effect can be measured.
"""
from __future__ import annotations

import json
import re

from instruments import surfaces
from instruments.bans import blocks_fact
from standard.catalog import load, render, select

JUDGED = ("How you will be judged: not by you, by Standard's scanner on the exact commit. It measures main's tests "
          "(green), every floor target and rule category (no regression), your write scope (every path inside it) "
          "and the building blocks (no banned API added). A rule the scanner cannot check is still a rule.")
FORMAT = ('Return JSON {"title": str, "files": {path: full new content}, "risks": str}. ')


class Overlay:
    """A tree with some files replaced: the draft on top of its base."""

    def __init__(self, base, files: dict):
        self.base, self.files = base, {p: c.encode() if isinstance(c, str) else c for p, c in files.items()}

    def paths(self):
        return set(self.base.paths()) | set(self.files)

    def read(self, path):
        return self.files[path] if path in self.files else self.base.read(path)


def bans_of(cat: dict) -> dict:
    return {name: b["bans"] for name, b in cat["blocks"].items() if b["bans"]}


def house_example(tree, block: str, limit: int = 2) -> list:
    """Where this repository already uses the block: the code the agent should look like (deterministic: sorted)."""
    module = f"standard_blocks.{block}"
    out = []
    for path in sorted(p for p in tree.paths() if p.endswith(".py") and not surfaces.SKIP.search(p)):
        text = tree.read(path).decode("utf-8", "replace")
        if module not in text:
            continue
        names = _names(text, module)
        for n, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith(("from ", "import ")):
                continue
            if module in line or any(re.search(rf"\b{re.escape(name)}\s*\(", line) for name in names):
                out.append(f"{path}:{n}: {line.strip()[:120]}")
                break
        if len(out) >= limit:
            break
    return out


def _names(text: str, module: str) -> list:
    """Names imported from the block: `from m import a, b` or `from m import (a,\n b)`; `x as y` gives y."""
    m = re.search(rf"from {re.escape(module)} import (?:\(([^)]*)\)|([^\n]+))", text)
    if not m:
        return []
    return [part.split(" as ")[-1].strip() for part in (m.group(1) or m.group(2)).split(",") if part.strip()]


def brief(rules: list, values: dict, tree) -> str:
    """The rules of one pass: full text for what a block does not absorb fully, one line for the rest, then where
    this repository already uses each block."""
    if not rules:
        return ""
    lines = [render(r, values, full=r["absorb"] != "full") for r in rules]
    blocks = sorted({r["block"] for r in rules if r["block"] and r["block"] in _PY_BLOCKS})
    house = [f"  {b}: {e}" for b in blocks for e in house_example(tree, b)]
    return "\n\n".join(lines) + ("\n\nThis repository already does it this way:\n" + "\n".join(house) if house else "")


_PY_BLOCKS = ("web", "session", "access", "crypto", "files", "parse", "process", "outbound", "input", "render", "log",
              "runtime", "data")


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
        m = re.search(r":\d+:((?:import|call|call-kw|call-dyn|builtin|attr-set|js-call|js-import):\S+)$", d)
        if m:
            block = next((n for n, b in cat["blocks"].items() if m.group(1) in b["bans"]), None)
            if block and f"block:{block}" not in shown:
                shown.add(f"block:{block}")
                b = cat["blocks"][block]
                out.append(f"block {block}: {b['does']}\nuse    {b['use']}\nbans   {', '.join(b['bans'])}")
    return "\n\n".join(out)


class Funnel:
    def __init__(self, cat: dict | None = None):
        self.cat = cat or load()

    def run(self, ask, base, head: str, *, values: dict, scope_ok, focus=(), wide_touched=()) -> tuple[dict, dict]:
        """(files, stats). `ask(prompt, pass_name) -> reply dict`; `head`: the task's own text (what to do, where,
        lessons); `scope_ok(path) -> bool`; `focus`: paths the task names; `wide_touched`: terms known before coding
        (a request's surfaces)."""
        features = surfaces.scan(base)["features"]
        stats = {"passes": [], "features": features}
        guess = set(wide_touched)
        for p in focus:
            if p in base.paths():
                d = surfaces.describe(p, base.read(p))
                guess |= {f"surface:{s}" for s in d["surfaces"]} | {f"construct:{c}" for c in d["constructs"]}
        files: dict = {}

        def take(reply, name):
            got = reply.get("files")
            if not isinstance(got, dict) or not all(isinstance(c, str) for c in got.values()):
                raise ValueError(f"the {name} pass returned no files")
            if any(not scope_ok(p) for p in got):
                raise ValueError(f"the {name} pass leaves its write scope")
            files.update(got)
            return reply

        wide = select(self.cat, features, guess, "wide")
        reply = take(ask(f"{head}\n\n{JUDGED}\n\nPass 1 of 3 (shape). Rules for the areas this touches:\n\n"
                         f"{brief(wide, values, base) or '(none selected)'}\n\n{FORMAT}Change as few files as "
                         f"possible.", "wide"), "wide")
        stats["passes"].append({"pass": "wide", "rules": [r["id"] for r in wide], "files": sorted(files)})
        result = dict(reply)
        for name in ("medium", "fine"):
            draft = Overlay(base, files)
            touched = surfaces.touched(base, draft)
            rules = select(self.cat, features, touched, name)
            violations = []
            if name == "fine":
                status, violations = blocks_fact(base, draft, sorted(files), bans_of(self.cat))
            wire = sorted({w for r in rules for w in r.get("wire", [])})
            if not rules and not violations:
                stats["passes"].append({"pass": name, "skipped": True, "touched": touched})
                continue
            ask_text = (f"{head}\n\n{JUDGED}\n\nPass {2 if name == 'medium' else 3} of 3 "
                        f"({'write and wire' if name == 'medium' else 'tighten'}). Your draft, file by file:\n"
                        + "\n".join(f"--- {p}\n{c}" for p, c in sorted(files.items()))
                        + f"\n\nRules this draft triggers:\n\n{brief(rules, values, base) or '(none)'}\n"
                        + (f"\nWhat the code must bring with it: {', '.join(wire)}.\n" if wire else "")
                        + ("\nBanned APIs your draft still uses (fix every one):\n" + "\n".join(violations)
                           + "\n\n" + explain(violations, values, self.cat) + "\n" if violations else "")
                        + f"\nChange only what these rules ask. {FORMAT}List only the files you change "
                          f"(an empty object when nothing needs changing).")
            reply = take(ask(ask_text, name), name)
            result = {**result, **{k: v for k, v in reply.items() if k != "files"}}
            stats["passes"].append({"pass": name, "rules": [r["id"] for r in rules], "touched": touched,
                                    "violations": len(violations), "changed": sorted(reply.get("files") or {})})
        final = Overlay(base, files)
        status, left = blocks_fact(base, final, sorted(files), bans_of(self.cat))
        stats["remaining"] = left
        result["files"] = files
        return result, stats


def record(stats: dict) -> str:
    """A compact line for the agent's own record (memory, work engine): what each pass showed and found."""
    return json.dumps({"passes": [{k: v for k, v in p.items() if k in ("pass", "rules", "violations", "skipped")}
                                  for p in stats.get("passes", [])], "remaining": len(stats.get("remaining", []))},
                      sort_keys=True)[:2000]
