"""U: switch production when the independent instrument says the switch is safe (D30).

The agent decides nothing about production. It reads the facts the scanner signed on exact switches, published in the
view (`transitions`), and submits the matching intent under its own capability:

    run:service:all/{from}/{to}   regressed = yes    ->  rollback from -> to   (first: the service is breaking)
    run:release:all/{from}/{to}   deployable = yes   ->  deploy from -> to

The law refuses anything the facts do not support; the guard switches by compare-and-swap, so a stale fact moves
nothing. Each switch is submitted once; a refusal is retried after a backoff.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

from trusted.signing import Signer, envelope

ROUTES = (("rollback", "run:service:all/", "regressed"), ("deploy", "run:release:all/", "deployable"))


class Releaser:
    def __init__(self, service, signer: Signer, grants: dict, *, clock, notes, backoff_ms=60_000):
        self.service, self.signer, self.grants, self.clock = service, signer, grants, clock
        self.notes, self.backoff_ms = Path(notes), backoff_ms

    def run(self) -> dict:
        view, now = self.service.view(), self.clock()
        notes = json.loads(self.notes.read_text()) if self.notes.exists() else {}
        report = {}
        for op, prefix, prop in ROUTES:
            if op not in self.grants:
                continue
            for resource, facts in sorted(view.get("transitions", {}).items()):
                if not resource.startswith(prefix) or facts.get(prop) != "yes":
                    continue
                frm, to = resource[len(prefix):].split("/")
                state = notes.get(resource, {})
                if state.get("state") == "admitted" or state.get("next_at", 0) > now:
                    continue
                body = {"id": f"intent-{uuid.uuid4().hex}", "at": max(now, view["health"]["as_of"] + 1),
                        "author": self.signer.identity, "under": self.grants[op], "op": op,
                        "args": {"from": frm, "to": to}}
                try:
                    self.service.admit(envelope(view["prefix"]["genesis"], "intent", body, [self.signer]))
                    notes[resource] = {"state": "admitted", "op": op}
                except Exception as exc:
                    notes[resource] = {"state": getattr(exc, "code", None) or str(exc), "next_at": now + self.backoff_ms}
                report[resource] = notes[resource]["state"]
            if any(v == "admitted" for k, v in report.items() if k.startswith(prefix)):
                break                                       # one switch per pass: rollback wins over deploy
        self.notes.write_text(json.dumps(notes, indent=2, sort_keys=True))
        return report
