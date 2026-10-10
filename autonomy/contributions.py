"""U: propose that main integrate a client's contribution (D23).

For every branch of the hosting inbox, the agent submits one `integrate` intent from the current main to the branch's
head, under its own capability. It decides nothing: the law refuses until the independent instrument observed main's
tests green on this exact transition and a human reviewer signed `review = approved` for it. A refusal is retried
after a backoff; a moved main makes a new transition, which needs its own facts.
"""
from __future__ import annotations

import json
import re
import subprocess
import uuid
from pathlib import Path

from trusted.signing import Signer, envelope

BRANCH = re.compile(r"([0-9a-f]{40})\trefs/heads/([a-z0-9][a-z0-9_-]{0,63})/\S+")


def contributions(inbox) -> list[tuple[str, str]]:
    """(author, head) for every branch of the inbox, read from outside."""
    out = subprocess.run(["git", "ls-remote", str(inbox), "refs/heads/*"], capture_output=True, text=True,
                         timeout=120, check=True).stdout
    return sorted({(m[2], m[1]) for m in map(BRANCH.fullmatch, out.splitlines()) if m})


class Integrator:
    def __init__(self, service, signer: Signer, capability: str, inbox, *, main, clock, notes, backoff_ms=60_000):
        self.service, self.signer, self.capability, self.inbox = service, signer, capability, inbox
        self.main, self.clock, self.notes, self.backoff_ms = main, clock, Path(notes), backoff_ms

    def run(self) -> dict:
        view, base, now = self.service.view(), self.main(), self.clock()
        notes = json.loads(self.notes.read_text()) if self.notes.exists() else {}
        report = {}
        for author, head in contributions(self.inbox):
            key = f"{author}/{base}/{head}"
            if head == base:
                continue                                    # already main: nothing to integrate
            if notes.get(key, {}).get("state") == "admitted" or notes.get(key, {}).get("next_at", 0) > now:
                continue
            body = {"id": f"intent-{uuid.uuid4().hex}", "at": max(now, view["health"]["as_of"] + 1),
                    "author": self.signer.identity, "under": self.capability, "op": "integrate",
                    "args": {"contributor": author, "base": base, "head": head}}
            try:
                self.service.admit(envelope(view["prefix"]["genesis"], "intent", body, [self.signer]))
                notes[key] = {"state": "admitted"}
            except Exception as exc:                        # usually CAP.CONDITION: no tests or no review yet
                notes[key] = {"state": getattr(exc, "code", None) or str(exc), "next_at": now + self.backoff_ms}
            report[key] = notes[key]["state"]
        self.notes.write_text(json.dumps(notes, indent=2, sort_keys=True))
        return report
