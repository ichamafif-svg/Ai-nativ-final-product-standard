"""T06 — the engineers' settings for production (D31): objectives, limits, autonomy, probes.

A setting is a statement an engineer signs in the browser and the kernel admits: an observation on
`run:policy/<scope>/<key>` whose status is the value. The journal keeps who set what and when. Only the holders of the
`engineer` grant are read; anything else on these resources is ignored.

A setting that makes Standard stricter (a higher objective, a lower latency limit, less autonomy, one more probe) applies
at once. A setting that loosens it (a lower objective, more autonomy, a probe removed) applies only after the law's
witnessed delay, like any widening, and is shown as pending until then: one tired engineer cannot silently lower the bar.

    scope    global, or c-<12 hex> for one component (sha256 of "kind|operation|name"), or p-<id> for a probe
    global   objective (%), failing (% of errors), p99_ms, window_s, late_periods, auto_deploy, auto_rollback,
             rollback_horizon_min, auto_restart, restarts_per_hour, compatible_migrations, base_url
    c-…      objective, p99_ms, counted (on/off)
    p-…      spec: "GET /health 200" or "off"
"""
from __future__ import annotations

import hashlib
import json
import re

DEFAULTS = {"objective": 99.9, "failing": 5.0, "p99_ms": 1000.0, "window_s": 300, "late_periods": 2,
            "auto_deploy": "on", "auto_rollback": "on", "rollback_horizon_min": 30, "auto_restart": "off",
            "restarts_per_hour": 2, "compatible_migrations": "on", "base_url": ""}
COMPONENT = {"objective", "p99_ms", "counted"}
BOUNDS = {"objective": (50.0, 99.999), "failing": (0.1, 50.0), "p99_ms": (1.0, 60_000.0), "window_s": (60, 3600),
          "late_periods": (1, 10), "rollback_horizon_min": (1, 240), "restarts_per_hour": (0, 12)}
# Which way is stricter: +1 a higher value is stricter, -1 a lower value is, "on"/"off" the stricter toggle.
STRICTER = {"objective": 1, "failing": -1, "p99_ms": -1, "late_periods": -1, "rollback_horizon_min": -1,
            "restarts_per_hour": -1, "auto_deploy": "off", "auto_rollback": "off", "auto_restart": "off",
            "compatible_migrations": "off", "counted": "on", "window_s": 0, "base_url": 0, "spec": 0}
PROBE = re.compile(r"(GET|HEAD|POST) (/[A-Za-z0-9._~/?=&%-]{0,200}) ([1-5][0-9][0-9])")
RESOURCE = re.compile(r"run:policy/(global|c-[0-9a-f]{12}|p-[a-z0-9]{1,16})/([a-z_0-9]{1,32})")


def component_id(kind: str, operation: str, name: str) -> str:
    return "c-" + hashlib.sha256(f"{kind}|{operation or ''}|{name}".encode()).hexdigest()[:12]


def parse(key: str, value: str):
    """The typed value of a setting, or ValueError: a malformed setting is ignored, never half-applied."""
    if key == "spec":
        if value != "off" and not PROBE.fullmatch(value):
            raise ValueError("a probe is METHOD /path STATUS")
        return value
    if key == "base_url":
        if value and not re.fullmatch(r"https?://[A-Za-z0-9.:-]{1,200}", value):
            raise ValueError("a base URL is scheme://host[:port]")
        return value
    if STRICTER.get(key) in ("on", "off"):
        if value not in ("on", "off"):
            raise ValueError("a toggle is on or off")
        return value
    if key not in BOUNDS:
        raise ValueError(f"unknown setting {key}")
    low, high = BOUNDS[key]
    number = float(value)
    if not low <= number <= high:
        raise ValueError(f"{key} is between {low} and {high}")
    return int(number) if isinstance(low, int) else number


def stricter(key: str, old, new) -> bool:
    """Whether moving from old to new tightens (or keeps) what Standard holds the product to."""
    way = STRICTER.get(key, 0)
    if old is None:                                       # a new component override or a new probe
        return key != "counted" or new == "on"
    if way in ("on", "off"):
        return new == old or new == way
    if key == "spec":
        return new != "off"
    if way == 0:
        return new == old
    return (new - old) * way >= 0


class Policy:
    """The effective settings, from the journal's signed statements, with the pending loosenings and the history."""

    def __init__(self, delay_ms: int, state_path=None, defaults=None):
        self.delay_ms, self.path = delay_ms, state_path
        self.defaults = {**DEFAULTS, **(defaults or {})}  # the installation's own starting values (standard.toml)
        saved = json.loads(state_path.read_text()) if state_path is not None and state_path.exists() else {}
        self.effective = saved.get("effective", {})       # "scope/key" -> value
        self.pending = saved.get("pending", {})           # "scope/key" -> {"value", "at", "author", "applies_at"}
        self.seen = saved.get("seen", {})                 # "scope/key" -> id of the last statement read
        self.history = saved.get("history", [])

    def update(self, observations: dict, authors: set, now_ms: int) -> None:
        for o in sorted(observations.values(), key=lambda o: o["at"]):
            m = RESOURCE.fullmatch(o["resource"])
            if not m or o["property"] != "value" or o["author"] not in authors:
                continue
            scope, key = m[1], m[2]
            name = f"{scope}/{key}"
            if self.seen.get(name) == o["id"] or (scope == "global" and key not in self.defaults) or (
                    scope.startswith("c-") and key not in COMPONENT) or (scope.startswith("p-") and key != "spec"):
                continue
            self.seen[name] = o["id"]
            try:
                value = parse(key, o["status"])
            except ValueError as exc:
                self.history.append({"at": o["at"], "author": o["author"], "setting": name, "value": o["status"],
                                     "outcome": f"ignored: {exc}"})
                continue
            old = self.effective.get(name)
            if old is None and key in ("objective", "p99_ms"):  # an override is compared with what it overrides
                old = self.get(key)
            elif old is None and scope == "global":
                old = self.defaults[key]
            if stricter(key, old, value):
                self.effective[name] = value
                self.pending.pop(name, None)
                outcome = "applied"
            else:
                self.pending[name] = {"value": value, "at": o["at"], "author": o["author"],
                                      "applies_at": o["at"] + self.delay_ms}
                outcome = "pending"
            self.history.append({"at": o["at"], "author": o["author"], "setting": name, "value": value,
                                 "outcome": outcome})
        for name, p in list(self.pending.items()):
            if now_ms >= p["applies_at"]:
                self.effective[name] = p["value"]
                del self.pending[name]
        self.history = self.history[-200:]
        if self.path is not None:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"effective": self.effective, "pending": self.pending, "seen": self.seen,
                                       "history": self.history}))
            tmp.replace(self.path)

    def get(self, key: str, scope: str = "global"):
        name = f"{scope}/{key}"
        if name in self.effective:
            return self.effective[name]
        return self.defaults.get(key) if scope == "global" else None

    def limits(self, kind: str, operation: str, name: str) -> dict:
        """The objective, latency limit and counting of one component: its own override, else the global value."""
        cid = component_id(kind, operation, name)
        counted = self.get("counted", cid)
        return {"id": cid, "objective": (self.get("objective", cid) or self.get("objective")) / 100,
                "p99_ms": self.get("p99_ms", cid) or self.get("p99_ms"), "failing": self.get("failing") / 100,
                "counted": counted == "on" if counted else kind != "dependency"}

    def probes(self) -> list:
        """(id, method, path, status) of every active probe."""
        out = []
        for name, value in sorted(self.effective.items()):
            if name.startswith("p-") and name.endswith("/spec") and value != "off":
                method, path, status = value.split(" ")
                out.append((name.split("/")[0], method, path, int(status)))
        return out

    def published(self) -> dict:
        """What the interface shows: every effective value, the pending loosenings, the latest changes."""
        return {"defaults": self.defaults, "bounds": BOUNDS, "effective": self.effective, "pending": self.pending,
                "history": self.history[-50:][::-1], "delay_ms": self.delay_ms}
