"""The rules of the game as the human edits them: one document, signed once, in force at once (D51).

The client's rules live in the journal (a `law` entry the human signs), never in a file of the product's repository.
They hold three kinds of choice, all inside the socle (standard/floors.py):

    routes     for each op, the autonomous routes kept on; turning one off leaves the move to the human
    settings   numbers the routes compare with (never looser than the socle's: the kernel refuses), and what the
               scanner measures and the console shows: objective, latency, deployment window, components, SLOs,
               probes, silences, the write scopes of the client's own targets
    team       the options for more people: threshold (in the root), delays, witness quorum

Here: the schema of each setting for the editor (a malformed value is refused before anyone signs it), the changed
document a signature puts in force, and the effective values as the console shows them. Nothing here is a
permission: the kernel and the independent checker judge the signed rules.
"""
from __future__ import annotations

import copy
import re
from zoneinfo import ZoneInfo

from instruments.production import PROBE, SELECTOR, component_id, measures

DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
# key -> (type, bounds or choices). The kernel adds its own floor for the settings a route compares with.
SCHEMA = {
    "objective": ("num", (50.0, 99.999)), "failing": ("num", (0.1, 50.0)), "p99_ms": ("num", (1.0, 60_000.0)),
    "window_s": ("int", (60, 3600)), "late_periods": ("int", (1, 10)),
    "burn_fast": ("num", (1.0, 100.0)), "burn_slow": ("num", (1.0, 100.0)),
    "rollback_horizon_min": ("int", (1, 240)), "rollback_migrations": ("int", (0, 1000)),
    "restarts_per_hour": ("int", (0, 11)), "freeze_below": ("num", (0.0, 100.0)),
    "deploy_days": ("days", None), "deploy_hours": ("hours", None), "deploy_tz": ("tz", None),
    "canary_percent": ("int", (1, 50)), "canary_bake_min": ("int", (1, 240)),
    "canary_max_error_delta": ("num", (0.0, 10.0)), "canary_min_requests": ("int", (10, 100_000)),
    "base_url": ("url", None),
}
SECTIONS = {"components": {"objective", "p99_ms", "counted"}, "probes": {"spec"},
            "slos": {"name", "sli", "threshold_ms", "target", "window_d", "selector", "state"},
            "silences": {"target_of", "until", "reason"}}
FIELD = {"counted": ("toggle", None), "spec": ("spec", None), "name": ("text", None),
         "sli": ("choice", ("availability", "latency")), "threshold_ms": ("num", (1.0, 60_000.0)),
         "target": ("num", (50.0, 99.999)), "window_d": ("int", (1, 90)), "selector": ("selector", None),
         "state": ("toggle", None), "target_of": ("text", None), "until": ("int", (0, 10 ** 14)),
         "reason": ("text", None), "objective": ("num", (50.0, 99.999)), "p99_ms": ("num", (1.0, 60_000.0))}
SCOPE_ID = {"components": r"c-[0-9a-f]{12}", "probes": r"p-[a-z0-9]{1,16}", "slos": r"s-[a-z0-9]{1,16}",
            "silences": r"m-[a-z0-9]{1,16}"}


class RulesError(ValueError):
    pass


def _hours(value: str) -> tuple[int, int]:
    m = re.fullmatch(r"([01]?[0-9]|2[0-3])-([01]?[0-9]|2[0-4])", value)
    if not m or int(m[1]) >= int(m[2]):
        raise RulesError("hours are HH-HH, start before end")
    return int(m[1]), int(m[2])


def parse(kind: str, spec, key: str, value):
    """The canonical value of one setting (a decimal is a string, as the kernel compares it), or RulesError."""
    value = str(value)
    if kind == "spec":
        if value != "off" and not PROBE.fullmatch(value):
            raise RulesError("a probe is METHOD /path STATUS")
        return value
    if kind == "url":
        if value and not re.fullmatch(r"https?://[A-Za-z0-9.:-]{1,200}", value):
            raise RulesError("a base URL is scheme://host[:port]")
        return value
    if kind == "toggle":
        if value not in ("on", "off"):
            raise RulesError("a toggle is on or off")
        return value
    if kind == "choice":
        if value not in spec:
            raise RulesError(f"{key} is one of {', '.join(spec)}")
        return value
    if kind == "text":
        if not re.fullmatch(r"[\w .,:'()%/-]{0,120}", value):
            raise RulesError("a short text")
        return value
    if kind == "selector":
        if not SELECTOR.fullmatch(value):
            raise RulesError("a selector is counted, all, kind:<kind> or component ids")
        return value
    if kind == "days":
        days = value.split(",")
        if not days or any(d not in DAYS for d in days) or len(set(days)) != len(days):
            raise RulesError("days are mon,tue,…")
        return ",".join(d for d in DAYS if d in days)
    if kind == "hours":
        _hours(value)
        return value
    if kind == "tz":
        try:
            ZoneInfo(value)
        except Exception:
            raise RulesError(f"unknown time zone {value}") from None
        return value
    try:
        number = float(value)
    except ValueError:
        raise RulesError(f"{key} is a number") from None
    low, high = spec
    if not low <= number <= high:
        raise RulesError(f"{key} is between {low} and {high}")
    return int(number) if kind == "int" else (str(int(number)) if number == int(number) else value)


def setting(key: str, value):
    if key not in SCHEMA:
        raise RulesError(f"unknown setting {key}")
    kind, spec = SCHEMA[key]
    return parse(kind, spec, key, value)


def change(client: dict, *, settings=None, routes=None, sections=None, drop=()) -> dict:
    """The client's rules with these changes: settings {key: value}, routes {op: [autonomous routes kept]},
    sections {section: {id: {field: value}}} (components, probes, SLOs, silences), drop [(section, id)]."""
    out = copy.deepcopy(client)
    s = out.setdefault("settings", {})
    for key, value in (settings or {}).items():
        s[key] = setting(key, value)
    for op, kept in (routes or {}).items():
        if not isinstance(kept, list) or not all(isinstance(r, str) and r != "human" for r in kept):
            raise RulesError(f"routes.{op}: the autonomous routes to keep")
        out.setdefault("routes", {})[op] = sorted(set(kept))
    for section, items in (sections or {}).items():
        if section not in SECTIONS:
            raise RulesError(f"unknown section {section}")
        for ident, fields in items.items():
            if not re.fullmatch(SCOPE_ID[section], ident):
                raise RulesError(f"{section}: bad id {ident}")
            entry = s.setdefault(section, {}).setdefault(ident, {})
            for field, value in fields.items():
                if field not in SECTIONS[section]:
                    raise RulesError(f"{section}.{field} is not a field")
                kind, spec = FIELD[field]
                entry[field] = parse(kind, spec, field, value)
    for section, ident in drop:
        s.get(section, {}).pop(ident, None)
    return out


class Rules:
    """The rules in force as the console reads them: settings, routes, silences."""

    def __init__(self, law: dict):
        self.law = law
        self.settings = law.get("settings", {}) if isinstance(law, dict) else {}

    def get(self, key: str, default=None):
        return self.settings.get(key, default)

    def routes(self) -> dict:
        """{op: {"auto": [kept], "human": True}} for every move of the rules."""
        return {op: {"auto": sorted(r for r in spec["routes"] if r != "human"), "human": True}
                for op, spec in self.law.get("ops", {}).items()}

    def limits(self, kind: str, operation: str, name: str) -> dict:
        """The objective, latency limit and counting of one component: its own override, else the global value."""
        cid = component_id(kind, operation, name)
        own = self.settings.get("components", {}).get(cid, {})
        counted = own.get("counted")
        return {"id": cid, "objective": float(own.get("objective") or self.get("objective", 99.9)) / 100,
                "p99_ms": float(own.get("p99_ms") or self.get("p99_ms", 1000)),
                "failing": float(self.get("failing", 5)) / 100,
                "counted": counted == "on" if counted else kind != "dependency"}

    def slos(self) -> dict:
        """Every SLO in force, exactly as the scanner measures them."""
        return measures(self.settings)["slos"]

    def silences(self, now_ms: int) -> dict:
        """Active silences: id -> {"target_of", "until", "reason"}. They mute the console, never a signed fact."""
        return {mid: keys for mid, keys in self.settings.get("silences", {}).items()
                if int(keys.get("until", 0)) > now_ms}
