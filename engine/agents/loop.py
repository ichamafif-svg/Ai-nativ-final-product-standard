"""U — the agent: one loop. Read the game, produce candidates, play the moves the rules allow.

    view ─► producers (repairs, builds, deliveries) write candidate commits in the agent's own store
         ─► the scanner measures them, and production, on exact resources: these are the moves
         ─► the agent plays every move whose status is `ready` (an autonomous route holds) or `decided` (the human
            said yes), production first and one production switch per pass; the kernel judges each one twice

The agent holds one capability and never chooses a route, a threshold or a grant: the rules and the kernel do. What
stays its own is tactics, which can only make it play less: stepping back before going forward, one switch per pass
(the next pass reads facts measured after it), taking a canary out only when it does worse than the live release or
main moved on, and not restarting the code a switch just brought in. Moves only the human can play wait in the
human's queue (moves.queue); the agent never asks twice for the same move.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

from fabric.control.bt.signing import Signer, envelope

from interface.context.moves import ORDER, moves

PRODUCTION = tuple(ORDER)


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


def tactic(view: dict, move: dict) -> str | None:
    """None to play the move now, or why the agent holds back (it never plays more than the rules allow)."""
    settings = view["law"]["effective"].get("settings", {})
    facts = view.get("transitions", {})
    if move["op"] == "abort":
        live, canary = move["args"]["from"], move["args"]["to"]
        c = facts.get(f"run:release:all/{live}/{canary}", {})
        if c.get("candidate") != "yes":
            return None                                     # main moved on: the canary is taken out
        tolerated = float(settings.get("canary_max_error_delta", 0.5))
        if _num(c, "canary_requests") >= 20 and worse(c, tolerated):
            return None
        return "the canary holds"
    if move["op"] == "restart":
        f = facts.get(move["resource"], {})
        if _num(f, "switched_min") <= float(settings.get("rollback_horizon_min", 30)):
            return "the breach follows a switch: restarting the same code would not repair it"
    if move["op"] == "canary" and "direct" in view["law"]["effective"]["ops"]["deploy"]["routes"] \
            and move["status"] == "ready":
        return "the rules deploy directly"
    return None


class Loop:
    def __init__(self, service, signer: Signer, grant: str, *, main, clock, notes, producers=(), advisors=(), backoff_ms=60_000):
        """grant: the agent's one capability. main(): the maintained repository's current main (read-only).
        producers: objects with `name` and `run(view, main) -> report` (repairs, builds). notes: U's own file."""
        self.service, self.signer, self.grant, self.main, self.clock = service, signer, grant, main, clock
        self.notes, self.producers, self.backoff_ms = Path(notes), tuple(producers), backoff_ms
        self.advisors = tuple(advisors)

    def run(self) -> dict:
        main = self.main()
        report = {p.name: p.run(self.service.view(), main) for p in self.producers}
        report["played"], report["holding"], report["waiting"] = self.play(main)
        for advisor in self.advisors:                         # play normal moves before advisory exploration
            try:
                report[advisor.name] = advisor.run(self.service.view(), main)
            except Exception as exc:
                report[advisor.name] = {"state": "unavailable", "reason": type(exc).__name__}
        return report

    def play(self, main: str) -> tuple[dict, dict, list]:
        view, now = self.service.view(), self.clock()
        notes = json.loads(self.notes.read_text()) if self.notes.exists() else {}
        played, holding, waiting, switched = {}, {}, [], False
        for m in moves(view, main=main, now=now):
            if m["status"] == "yours" and m["wanted"]:
                waiting.append(m["resource"])
            if m["status"] not in ("ready", "decided"):
                continue
            production = m["op"] in PRODUCTION
            if production and switched:
                continue                                    # one switch per pass: the next reads fresh facts
            why = tactic(view, m) if m["status"] == "ready" else None
            if why:
                holding[m["resource"]] = why
                continue
            note = notes.get(m["resource"], {})
            if note.get("next_at", 0) > now or (note.get("state") == "admitted" and m["last"] != "failed"):
                continue
            body = {"id": f"intent-{uuid.uuid4().hex}", "at": max(now, view["health"]["as_of"] + 1),
                    "author": self.signer.identity, "under": self.grant, "op": m["op"], "args": m["args"]}
            try:
                self.service.admit(envelope(view["prefix"]["genesis"], "intent", body, [self.signer]))
                notes[m["resource"]] = {"state": "admitted", "op": m["op"], "route": m["route"], "at": now}
                switched = switched or production
            except Exception as exc:                        # the kernel judged otherwise: information, not failure
                notes[m["resource"]] = {"state": getattr(exc, "code", None) or str(exc)[:200], "op": m["op"],
                                        "next_at": now + self.backoff_ms}
            played[m["resource"]] = notes[m["resource"]]["state"]
        notes["why"] = holding                              # the agent's restraint, for the console
        self.notes.write_text(json.dumps(notes, indent=2, sort_keys=True))
        return played, holding, waiting
