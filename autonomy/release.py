"""U: switch or restart production when the facts say it may (D30, D31).

The agent decides nothing about production. It reads the facts published in the view (`transitions`) on exact
switches, the scanner's and the engineers', and submits the matching intent under the capability that fits:

    run:service:all/{from}/{to}   regressed = yes                     ->  rollback   (agent_rollback)
                                  previous = yes and requested = yes  ->  rollback   (agent_rollback_reviewed)
    run:process:all/{release}/{n} restartable = yes                   ->  restart    (agent_restart)
                                  requested = yes                     ->  restart    (agent_restart_reviewed)
    run:release:all/{from}/{to}   deployable = yes                    ->  deploy     (agent_deploy)
                                  promotable = yes                    ->  deploy     (agent_promote, D32)
                                  candidate = yes and approved = yes  ->  deploy     (agent_deploy_reviewed)
    run:canary:all/{from}/{to}    canary_ready = yes                  ->  canary     (agent_canary)
    run:canary:abort/{from}/{to}  canary_bad = yes, or requested      ->  abort      (agent_abort, _reviewed)

Stepping back comes first, then taking a canary out, restarting, promoting or deploying, and starting a canary;
one switch per pass. The law refuses anything the facts do
not support; the guard switches by compare-and-swap, so a stale fact moves nothing. Each is submitted once.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

from trusted.signing import Signer, envelope

ROUTES = (  # op, resource prefix, [(facts that must all be yes, grant name)], argument names
    ("rollback", "run:service:all/", [(("regressed",), "agent_rollback"),
                                      (("previous", "requested"), "agent_rollback_reviewed")], ("from", "to")),
    ("abort", "run:canary:abort/", [(("canary_bad",), "agent_abort"),
                                    (("requested",), "agent_abort_reviewed")], ("from", "to")),
    ("restart", "run:process:all/", [(("restartable",), "agent_restart"),
                                     (("requested",), "agent_restart_reviewed")], ("release", "n")),
    ("deploy", "run:release:all/", [(("deployable",), "agent_deploy"), (("promotable",), "agent_promote"),
                                    (("candidate", "approved"), "agent_deploy_reviewed")], ("from", "to")),
    ("canary", "run:canary:all/", [(("canary_ready",), "agent_canary")], ("from", "to")),
)


class Releaser:
    def __init__(self, service, signer: Signer, grants: dict, *, clock, notes, backoff_ms=60_000):
        """grants: grant name -> grant id, for the capabilities this installation gave the agent."""
        self.service, self.signer, self.grants, self.clock = service, signer, grants, clock
        self.notes, self.backoff_ms = Path(notes), backoff_ms

    def run(self) -> dict:
        view, now = self.service.view(), self.clock()
        notes = json.loads(self.notes.read_text()) if self.notes.exists() else {}
        report = {}
        for op, prefix, routes, names in ROUTES:
            for resource, facts in sorted(view.get("transitions", {}).items()):
                if not resource.startswith(prefix):
                    continue
                grant = next((self.grants[g] for need, g in routes
                              if g in self.grants and all(facts.get(f) == "yes" for f in need)), None)
                state = notes.get(resource, {})
                if grant is None or state.get("state") == "admitted" or state.get("next_at", 0) > now:
                    continue
                body = {"id": f"intent-{uuid.uuid4().hex}", "at": max(now, view["health"]["as_of"] + 1),
                        "author": self.signer.identity, "under": grant, "op": op,
                        "args": dict(zip(names, resource[len(prefix):].split("/")))}
                try:
                    self.service.admit(envelope(view["prefix"]["genesis"], "intent", body, [self.signer]))
                    notes[resource] = {"state": "admitted", "op": op}
                except Exception as exc:
                    notes[resource] = {"state": getattr(exc, "code", None) or str(exc), "next_at": now + self.backoff_ms}
                report[resource] = notes[resource]["state"]
            if any(v == "admitted" for k, v in report.items() if k.startswith(prefix)):
                break
        self.notes.write_text(json.dumps(notes, indent=2, sort_keys=True))
        return report
