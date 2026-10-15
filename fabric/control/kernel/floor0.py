"""FLOOR-0: what guards the law itself (ARCHITECTURE.md §4.2).

The kernel applies it; a sealed law only declares its digest. One digest covers the text, the polarity table, who may
restrict alone, the constants and the effect line.
"""
from __future__ import annotations

from .canon import digest

FLOOR0 = (
    ("F0-1", "One human and one agent. The agent holds no authority of its own. Every widening is stated and signed by "
             "the root's one human; time is stated by a witness of the root."),
    ("F0-2", "For every critical property, name its controls, common dependencies and covered failures. A safety "
             "disagreement blocks the effect; an integrity mismatch blocks the affected boundary. A local stop is not "
             "an unsigned ledger mutation."),
    ("F0-3", "Code and floors are genesis-bound. The client law changes only by widening, never weakening the release "
             "floors; capability chains only narrow. A law constrains only kinds that act, attest or attenuate: never a "
             "restriction, a witness or the widening protocol."),
    ("F0-4", "Every canonical state transition is caused by exactly one signed entry. Admission depends only on the "
             "admitted prefix and the pinned law and code."),
    ("F0-5", "Every kind has one polarity. Genesis establishes the initial externally pinned root. A widening takes "
             "effect with its own entry. Other polarities only restrict, attenuate, act under capability, attest or "
             "witness."),
    ("F0-6", "Time only expires or lapses authority; it never grants it. Only a witness advances the attested "
             "anchor; ordinary entry timestamps are monotone and bounded ahead of that anchor. A restriction may share "
             "the last instant, so no timestamp can starve it."),
    ("F0-7", "Lifting a restriction is a widening: only the human lifts a freeze."),
    ("F0-8", "A fact permits an action only while freshly attested by a chain sharing no holder with the actor. Every "
             "permitting fact carries its provenance label: observations, closures, open instances and gates. Absence "
             "of a fact never permits it."),
    ("F0-9", "Every effect is typed, its resource derives from its arguments, and its reservation is durable and "
             "single-use. Rejudging and provider dispatch are ordered against admission. Only the judged canonical "
             "request is passed to the trusted adapter, with a genesis-bound reservation key. The effect line follows "
             "one table; a reservation leaves within DISPATCH_MS or never, and only then may it be reconciled."),
    ("F0-10", "History is append-only and genesis-bound. An independent monotone pin is retained for every write before "
              "acknowledgment. History below or diverging from it is blocked; repair restores its exact tail."),
    ("F0-11", "Outside admission, each declared target lacking fresh independent proof has a stable obligation and "
              "deadline; overdue gaps record escalation to the human. Accountability never authorizes. Recording "
              "escalation does not prove that the human saw it, nor repair."),
    ("F0-12", "Every op declares its routes: autonomous routes read measured facts only, and the human route needs a "
              "human's decision on the exact resource. An effect proceeds only while one route in force holds, from "
              "intent to departure. A law may turn autonomous routes off, never the human route."),
)

HUMANS = 1                        # exactly one human in the root (with up to eight keys: devices)
MAX_AHEAD_MS = 300_000            # no statement runs more than five minutes ahead of the last witnessed time
DISPATCH_MS = 300_000             # a reservation leaves within five minutes, or never
DECISION = ("observed", ("decision", "approve", "real", "human"))   # the one atom a human route must carry (F0-12)

KINDS = ("human", "agent", "service", "oracle", "guard", "witness")

POLARITY = {
    "genesis": "widen", "rotate": "widen", "grant": "widen", "unfreeze": "widen", "law": "widen",
    "delegate": "attenuate",
    "revoke": "restrict", "freeze": "restrict", "invalidate": "restrict",
    "checkpoint": "witness",
    "intent": "act", "token": "act", "reservation": "act", "execution": "act", "resource": "act", "transition": "act",
    "reconciliation": "attest", "observation": "attest", "measurement": "attest",
}
CONSTRAINABLE = ("act", "attest", "attenuate")   # the only polarities a law may block (F0-3)

# Who may restrict alone. "revoke" is also open to any holder along the revoked chain.
RESTRICT_BY = {"revoke": ("human",), "freeze": ("human",), "invalidate": ("human", "oracle")}

# The effect line (§8.1): (kind, result) -> (states it may leave, state it enters). "expired" is a reservation past
# DISPATCH_MS: no guard may send it any more, so only then may a reconciler settle it.
LINE = {
    ("intent", None): ((None,), "intended"),
    ("token", None): (("intended",), "tokened"),
    ("reservation", None): (("tokened",), "reserved"),
    ("execution", "ok"): (("reserved", "expired"), "proving"),
    ("execution", "failed"): (("reserved", "expired"), "failed"),
    ("execution", "unknown"): (("reserved", "expired"), "uncertain"),
    ("reconciliation", "applied"): (("uncertain", "expired"), "proving"),
    ("reconciliation", "not_applied"): (("uncertain", "expired"), "failed"),
}
LAPSE = ("pending", "unredeemed")   # stages before any effect: time lapses them. After a reservation nothing lapses.


def line_state(line: dict, intent: str, at: int):
    """The state of an intent's effect line at `at` (None before the intent exists)."""
    cur = line.get(intent)
    if cur is None:
        return None
    return "expired" if cur["state"] == "reserved" and at > cur["at"] + DISPATCH_MS else cur["state"]


def floor0_digest() -> str:
    return digest({
        "text": [list(rule) for rule in FLOOR0],
        "polarity": POLARITY,
        "restrict_by": {k: list(v) for k, v in RESTRICT_BY.items()},
        "constants": {"HUMANS": HUMANS, "MAX_AHEAD_MS": MAX_AHEAD_MS, "DISPATCH_MS": DISPATCH_MS, "LAPSE": list(LAPSE),
                      "KINDS": list(KINDS), "CONSTRAINABLE": list(CONSTRAINABLE),
                      "DECISION": [DECISION[0], list(DECISION[1])]},
        "line": [[k, r, list(f), t] for (k, r), (f, t) in LINE.items()],
    })
