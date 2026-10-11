"""U: switch or restart production when the facts and the engineers' settings say so (D30-D32, D36).

The scanner signs what is on each exact switch, and numbers; the law bounds when the agent may act alone; the
engineers' settings (standard/rules.json on main, autonomy/policy.py) are the agent's own restraint inside those
bounds. The agent submits the intent under the capability whose condition it believes holds; the kernel checks it.

    run:service:all/{from}/{to}   previous (+ requested)                       ->  rollback  (agent_rollback_reviewed)
                                  previous, proven, and the new release never   ->  rollback  (agent_rollback_unanswered)
                                  answered, or broke within the horizon after   ->  rollback  (agent_rollback,
                                  its switch: fast burn, or a failing share                    agent_rollback_failing)
    run:canary:abort/{from}/{to}  running, and worse than the live release, or  ->  abort     (agent_abort, _reviewed)
                                  main moved on (or requested)
    run:process:all/{release}/{n} live, a breach not caused by a switch, within ->  restart   (agent_restart, _burn,
                                  the hourly budget (or requested)                           _reviewed)
    run:release:all/{from}/{to}   candidate, a canary that baked and held       ->  deploy    (agent_promote)
                                  candidate, in the window, unfrozen, budget    ->  deploy    (agent_deploy)
                                  candidate + approved                          ->  deploy    (agent_deploy_reviewed)
    run:canary:all/{from}/{to}    candidate, strategy canary, same conditions   ->  canary    (agent_canary)

Stepping back comes first, then taking a canary out, restarting, deploying; one switch per pass. The guard switches
by compare-and-swap, so a stale fact moves nothing. Each switch is submitted once; a refusal is retried after a pause.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

from trusted.signing import Signer, envelope

from .policy import Policy

ARGS = {"rollback": ("from", "to"), "abort": ("from", "to"), "restart": ("release", "n"), "deploy": ("from", "to"),
        "canary": ("from", "to")}


def _num(facts: dict, key: str) -> float:
    try:
        return float(facts.get(key, "0"))
    except ValueError:
        return 0.0


def worse(c: dict, tolerated: float) -> bool:
    """The canary fails more than the live release by more than the tolerated points, beyond the noise of what was
    seen: the difference exceeds the tolerance by two standard errors (two proportions). A product that fails 2 % of
    its requests shows a point of difference on a few hundred requests by chance alone; taking out every canary on
    such noise would stop all delivery."""
    pc, pl = _num(c, "canary_error_pct") / 100, _num(c, "live_error_pct") / 100
    nc, nl = max(_num(c, "canary_requests"), 1), max(_num(c, "live_requests"), 1)
    se = 100 * ((pc * (1 - pc)) / nc + (pl * (1 - pl)) / nl) ** 0.5
    return _num(c, "canary_error_delta") - tolerated > 2 * max(se, 100 / nc)


def decide(transitions: dict, p: Policy, now_ms: int) -> tuple[list, dict]:
    """[(op, resource, grant name)] in order of priority, and why the agent holds back elsewhere."""
    out, why = [], {}
    yes = lambda f, *keys: all(f.get(k) == "yes" for k in keys)
    burning = lambda f: _num(f, "burn_fast") >= p.get("burn_fast")
    failing = lambda f: _num(f, "failing_pct") >= p.get("failing")
    horizon = p.get("rollback_horizon_min")
    for r, f in sorted(transitions.items()):
        if r.startswith("run:service:all/") and yes(f, "previous"):
            if yes(f, "requested"):
                out.append((0, "rollback", r, "agent_rollback_reviewed"))
            elif not (burning(f) or failing(f) or _num(f, "unanswered_s") >= 90):
                continue
            elif not yes(f, "proven"):
                why["rollback"] = "no earlier release is known to have met the objective"
            elif p.get("auto_rollback") != "on":
                why["rollback"] = "automatic rollback is off: an engineer decides"
            elif _num(f, "migrations_crossed") > 0 and p.get("compatible_migrations") != "on":
                why["rollback"] = "stepping back across a compatible migration is turned off"
            elif _num(f, "unanswered_s") >= 90:
                out.append((0, "rollback", r, "agent_rollback_unanswered"))
            elif _num(f, "switched_min") > horizon:
                why["rollback"] = f"live for {int(_num(f, 'switched_min'))} min before the breach: not attributable to the switch"
            else:
                out.append((0, "rollback", r, "agent_rollback" if burning(f) else "agent_rollback_failing"))
        elif r.startswith("run:canary:abort/") and yes(f, "running"):
            live, canary = r.split("/")[1:]
            c = transitions.get(f"run:release:all/{live}/{canary}", {})
            limit = max(_num(c, "live_p99_ms") * 1.5, p.get("p99_ms"))
            if yes(f, "requested"):
                out.append((1, "abort", r, "agent_abort_reviewed"))
            elif not yes(c, "candidate"):
                out.append((1, "abort", r, "agent_abort"))
                why["canary"] = "main moved on: the canary is taken out"
            elif _num(c, "canary_requests") >= 20 and (worse(c, p.get("canary_max_error_delta")) or (
                    _num(c, "canary_requests") >= p.get("canary_min_requests") and _num(c, "canary_p99_ms") > limit)):
                out.append((1, "abort", r, "agent_abort"))
                why["canary"] = f"canary fails {_num(c, 'canary_error_delta'):.2f} points more than the live release " \
                                f"(limit {p.get('canary_max_error_delta')}), p99 {_num(c, 'canary_p99_ms'):.0f} ms"
        elif r.startswith("run:process:all/") and (yes(f, "live") or yes(f, "requested")):
            if yes(f, "requested"):
                out.append((2, "restart", r, "agent_restart_reviewed"))
            elif not (burning(f) or failing(f)):
                continue
            elif _num(f, "switched_min") <= horizon:
                why["restart"] = "the breach follows a switch: restarting the same code would not repair it"
            elif p.get("auto_restart") != "on":
                why["restart"] = "automatic restart is off"
            elif _num(f, "restarts_last_hour") >= p.get("restarts_per_hour"):
                why["restart"] = f"{int(_num(f, 'restarts_last_hour'))} restarts in the last hour: the budget is spent"
            else:
                out.append((2, "restart", r, "agent_restart" if failing(f) else "agent_restart_burn"))
        elif r.startswith("run:release:all/") and yes(f, "candidate"):
            live, main = r.split("/")[1:]
            running = next((k.split("/")[2] for k, v in transitions.items()
                            if k.startswith(f"run:canary:abort/{live}/") and yes(v, "running")), None)
            open_, closed = p.deploy_open(now_ms)
            if yes(f, "approved"):
                out.append((3, "deploy", r, "agent_deploy_reviewed"))
            elif p.get("auto_deploy") != "on":
                why["deploy"] = "automatic deployment is off: an engineer approves"
            elif running == main:
                baked, seen = _num(f, "canary_baked_min"), _num(f, "canary_requests")
                if baked >= p.get("canary_bake_min") and seen >= p.get("canary_min_requests") and \
                        _num(f, "canary_error_delta") <= p.get("canary_max_error_delta"):
                    out.append((3, "deploy", r, "agent_promote"))
                    why["canary"] = f"canary held {int(baked)} min on {int(seen)} requests: promoted"
                else:
                    why["canary"] = f"canary baking: {int(baked)}/{p.get('canary_bake_min')} min, " \
                                    f"{int(seen)}/{p.get('canary_min_requests')} requests"
            elif running is not None:
                continue
            elif not open_:
                why["deploy"] = closed
            elif p.get("freeze_below") > 0 and _num(f, "budget_pct") < p.get("freeze_below"):
                why["deploy"] = f"error budget left {_num(f, 'budget_pct'):.1f} % is under {p.get('freeze_below')} %: frozen"
            elif p.get("strategy") == "canary" and live != "none":
                out.append((4, "canary", f"run:canary:all/{live}/{main}", "agent_canary"))
            else:
                out.append((3, "deploy", r, "agent_deploy"))
    return [x[1:] for x in sorted(out)], why


class Releaser:
    def __init__(self, service, signer: Signer, grants: dict, *, clock, notes, rules=lambda: {}, backoff_ms=60_000):
        """grants: grant name -> grant id, for the capabilities this installation gave the agent. rules: the
        standard/rules.json main carries."""
        self.service, self.signer, self.grants, self.clock = service, signer, grants, clock
        self.notes, self.rules, self.backoff_ms = Path(notes), rules, backoff_ms

    def run(self) -> dict:
        view, now = self.service.view(), self.clock()
        notes = json.loads(self.notes.read_text()) if self.notes.exists() else {}
        wanted, notes["why"] = decide(view.get("transitions", {}), Policy(self.rules()), now)
        report = {}
        for op, resource, grant in wanted:
            state = notes.get(resource, {})
            if grant not in self.grants or state.get("state") == "admitted" or state.get("next_at", 0) > now:
                continue
            prefix = resource.rsplit("/", len(ARGS[op]))[0] + "/"
            body = {"id": f"intent-{uuid.uuid4().hex}", "at": max(now, view["health"]["as_of"] + 1),
                    "author": self.signer.identity, "under": self.grants[grant], "op": op,
                    "args": dict(zip(ARGS[op], resource[len(prefix):].split("/")))}
            try:
                self.service.admit(envelope(view["prefix"]["genesis"], "intent", body, [self.signer]))
                notes[resource] = {"state": "admitted", "op": op}
            except Exception as exc:
                notes[resource] = {"state": getattr(exc, "code", None) or str(exc), "next_at": now + self.backoff_ms}
            report[resource] = notes[resource]["state"]
            if notes[resource]["state"] == "admitted":
                break
        self.notes.write_text(json.dumps(notes, indent=2, sort_keys=True))
        return report
