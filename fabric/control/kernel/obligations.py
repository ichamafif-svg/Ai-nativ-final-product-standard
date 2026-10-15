"""OBL: one engine of law-declared obligations, for every level, inside and outside admission (§4.3, §7.5).

A declaration names the entries that open it, close it, or need it open (gates), a key taken from the entry, a deadline
and a level:

    refuse    applied by the kernel: a failed gate or close refuses the entry
    escalate  applied by accountability: a failure opens a violation already due
    measure   applied by accountability: a failure is counted and published, never escalated

The same declaration moves between levels without being rewritten. An instance is named "<type>:<key>". Opening an
open key keeps it, replaces it or refuses, as declared. Nothing changes because time passes: at its deadline an
instance lapses (stops gating, may be reopened) or escalates. Every instance pins the contract of its declaration
(§4.6): a new rule never settles an old instance.

Pure: it reads open instances and one admitted record and returns what to open and close.
"""
from __future__ import annotations

import re

from .canon import digest
from .floor0 import CONSTRAINABLE
from .types import PATH, get_path

LEVELS = ("refuse", "escalate", "measure")
RESERVED = ("pending", "unredeemed", "reconcile", "proof", "target", "clock", "violation")
NAME = re.compile(r"[a-z][a-z0-9-]{0,63}")
MAX_DECLARATIONS = 64
MAX_RULES = 16
YEAR_MS = 365 * 86_400_000


class DeclarationError(ValueError):
    pass


def _rule(raw, where: str, kinds: dict) -> dict:
    if not isinstance(raw, dict) or not {"kind", "key"} <= set(raw) or set(raw) - {"kind", "key", "where", "op"}:
        raise DeclarationError(f"{where}: a rule is {{kind, key, where?, op?}}")
    if raw["kind"] not in kinds or not isinstance(raw["key"], str) or not PATH.fullmatch(raw["key"]):
        raise DeclarationError(f"{where}: unknown kind or bad key path")
    cond = raw.get("where", {})
    if not isinstance(cond, dict) or len(cond) > 8 or not all(
            isinstance(k, str) and PATH.fullmatch(k) and (isinstance(v, str) or type(v) is int) for k, v in cond.items()):
        raise DeclarationError(f"{where}: where maps field paths to strings or integers only")
    if "op" in raw and (raw["kind"] != "intent" or not isinstance(raw["op"], str)):
        raise DeclarationError(f"{where}: op filters intents only")
    return {"kind": raw["kind"], "key": raw["key"], "where": dict(cond), "op": raw.get("op")}


def validate(raw, kinds: dict, compile_condition) -> dict:
    """kinds: every entry kind of the law with its polarity. A refuse-level rule constrains only kinds that act, attest
    or attenuate: no law can block a restriction, a witness or the widening protocol that would repair it (F0-3)."""
    if raw is None:
        return {}
    if not isinstance(raw, list) or len(raw) > MAX_DECLARATIONS:
        raise DeclarationError(f"obligations is a list of at most {MAX_DECLARATIONS} declarations")
    decls = {}
    allowed = {"id", "level", "due_ms", "on_due", "open", "close", "gate", "reopen", "when"}
    for d in raw:
        if not isinstance(d, dict) or not {"id", "level", "due_ms", "on_due", "open"} <= set(d) or set(d) - allowed:
            raise DeclarationError("a declaration is {id, level, due_ms, on_due, open, close?, gate?, reopen?, when?}")
        ident = d["id"]
        if not isinstance(ident, str) or not NAME.fullmatch(ident) or ident in RESERVED or ident in decls:
            raise DeclarationError(f"{ident}: a new lowercase name")
        if d["level"] not in LEVELS or d["on_due"] not in ("lapse", "escalate"):
            raise DeclarationError(f"{ident}: level in {LEVELS}, on_due lapse or escalate")
        if type(d["due_ms"]) is not int or not 0 < d["due_ms"] <= YEAR_MS:
            raise DeclarationError(f"{ident}: due_ms is a positive bounded duration")
        if d.get("reopen", "keep") not in ("keep", "replace", "refuse"):
            raise DeclarationError(f"{ident}: reopen is keep, replace or refuse")
        rules = {}
        for part in ("open", "close", "gate"):
            items = d.get(part, [])
            if not isinstance(items, list) or len(items) > MAX_RULES or (part == "open" and not items):
                raise DeclarationError(f"{ident}: {part} is a bounded list (open is not empty)")
            rules[part] = [_rule(r, f"{ident}.{part}", kinds) for r in items]
            if d["level"] == "refuse" and any(kinds[r["kind"]] not in CONSTRAINABLE for r in rules[part]):
                raise DeclarationError(f"{ident}.{part}: a refuse-level rule constrains only {CONSTRAINABLE} kinds")
        decls[ident] = {"contract": digest(d), "id": ident, "level": d["level"], "due_ms": d["due_ms"],
                        "on_due": d["on_due"], "reopen": d.get("reopen", "keep"), **rules,
                        "when": compile_condition(d["when"]) if "when" in d else None}
    return decls


def key_of(rule: dict, record: dict):
    """The instance key this record designates under this rule, or None if the rule does not apply."""
    body = record["body"]
    if record["kind"] != rule["kind"] or (rule["op"] is not None and body.get("op") != rule["op"]):
        return None
    if any(get_path(body, k) != v for k, v in rule["where"].items()):
        return None
    return get_path(body, rule["key"])


def live(instance: dict, at: int) -> bool:
    return not (instance.get("on_due") == "lapse" and at > instance["due"])


def step(decls: dict, levels, open_: dict, record: dict, holds, admits=lambda instance: True):
    """(opens [(name, instance)], closes [(name, "closed" | "replaced")], failures [(decl, code, detail)]).

    holds(decl): the declaration's `when` for this record (True when there is none).
    admits(instance): whether an open instance may satisfy a gate for this record; the kernel admits only instances
    opened by a chain independent of the record's (F0-8)."""
    at, opens, closes, failures = record["at"], [], {}, []
    for d in (d for d in decls.values() if d["level"] in levels):
        for rule in d["gate"]:
            key = key_of(rule, record)
            if key is not None:
                inst = open_.get(f"{d['id']}:{key}")
                if inst is None or not live(inst, at) or inst["contract"] != d["contract"] or not admits(inst):
                    failures.append((d, "OBL.GATE", f"{record['kind']} needs {d['id']}:{key} open"))
        for rule in d["close"]:
            key = key_of(rule, record)
            if key is not None:
                name = f"{d['id']}:{key}"
                if name in open_ and open_[name]["contract"] != d["contract"]:
                    failures.append((d, "OBL.CONTRACT", f"{name} belongs to another declaration"))
                elif name in open_ and live(open_[name], at) and name not in closes:
                    closes[name] = "closed"
                else:
                    failures.append((d, "OBL.NOT_OPEN", f"{name} is not open"))
        for rule in d["open"]:
            key = key_of(rule, record)
            if key is None or not holds(d):
                continue
            name = f"{d['id']}:{key}"
            current = open_.get(name)
            if current is not None and live(current, at) and name not in closes:
                if d["reopen"] == "keep":
                    continue
                if d["reopen"] == "refuse":
                    failures.append((d, "OBL.ALREADY_OPEN", f"{name} is already open"))
                    continue
                closes[name] = "replaced"
            elif current is not None and name not in closes:
                closes[name] = "replaced"                # a lapsed instance gives way to the new one
            opens.append((name, {"stage": d["id"], "type": "law", "level": d["level"], "key": key, "opened": at,
                                 "due": at + d["due_ms"], "on_due": d["on_due"], "owner": record["author"],
                                 "contract": d["contract"]}))
    return opens, list(closes.items()), failures
