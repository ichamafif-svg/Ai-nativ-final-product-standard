"""U: commit the rules file an engineer signed from the interface (D35).

An engineer edits the rules in the interface; the browser stores the new standard/rules.json by digest and the
engineer signs that digest for the current main (`rules` on repo:config:rules/<main>). The agent commits exactly those
bytes as standard/rules.json on main, with the trailer `Standard-Rules: <digest>`, and asks the law to `configure`:
refused until the scanner checked the commit changes that file alone, to the signed bytes, and that main's tests and
the floors still hold. Engineers who prefer git change the same file by a reviewed contribution.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

from instruments.suite import load
from bt.signing import Signer, envelope

from .agent import AgentError, commit_files

RULES = "standard/rules.json"


class Configurer:
    def __init__(self, service, signer: Signer, grant: str, store, requests, *, main, clock, notes, backoff_ms=60_000):
        self.service, self.signer, self.grant, self.store = service, signer, grant, Path(store)
        self.requests, self.main, self.clock, self.notes = Path(requests), main, clock, Path(notes)
        self.backoff_ms = backoff_ms

    def run(self) -> dict:
        view, now, base = self.service.view(), self.clock(), self.main()
        notes = json.loads(self.notes.read_text()) if self.notes.exists() else {}
        signed = sorted((f for f in view.get("facts", []) if f["resource"] == f"repo:config:rules/{base}"
                         and f["property"] == "rules"), key=lambda f: f["at"])
        report = {}
        if signed:
            digest = signed[-1]["status"]
            key = f"{base}/{digest}"
            note = notes.setdefault(key, {})
            if note.get("state") != "admitted" and note.get("next_at", 0) <= now:
                try:
                    data = load(self.requests, digest)
                    if data is None:
                        raise AgentError("the signed rules are not in the store")
                    head = note.get("head") or commit_files(self.store, base, {RULES: data},
                                                             f"Standard: rules changed by {signed[-1]['author']}\n\n"
                                                             f"Standard-Rules: {digest}\n")
                    note["head"] = head
                    body = {"id": f"intent-{uuid.uuid4().hex}", "at": max(now, view["health"]["as_of"] + 1),
                            "author": self.signer.identity, "under": self.grant, "op": "configure",
                            "args": {"base": base, "head": head}}
                    self.service.admit(envelope(view["prefix"]["genesis"], "intent", body, [self.signer]))
                    note["state"] = "admitted"
                except Exception as exc:
                    note.update(state=getattr(exc, "code", None) or str(exc)[:200], next_at=now + self.backoff_ms)
            report[digest] = note.get("state")
        self.notes.write_text(json.dumps(notes, indent=2, sort_keys=True))
        return report
