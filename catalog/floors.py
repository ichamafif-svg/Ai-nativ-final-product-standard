"""The socle of this release (ARCHITECTURE.md §12): the rules of the game every client plays under.

Declarative, in the same language as the client's rules. The socle names the moves (the ops), the routes by which each
move may be played, the least proof each route needs and the floor value of every setting; the client's rules choose
inside it. Only the Standard team changes this file, through a release.

Two players. The agent proposes moves and never holds authority. The human writes the rules and has the last word in
the situations that matter, by three gestures only: change the rules, say yes (`decision = approve`, signed by a
human, on the exact resource of a move) and say no (freeze the resource or a scope). Every op has a human route; the
autonomous routes read only facts that pinned instruments measured. The rules turn autonomous routes off and set the
settings no looser than here; the kernel and the independent checker read the same numbers as the agent.

Where the human keeps the last word: the rules themselves (power), code the agent did not write (`integrate`), what
the product must do (a request's contract), what no machine repairs (provider settings), and every move whose
autonomous routes the rules turned off. Everything else the agent plays alone, inside the rules.

Technical measures are observed by the scanner and repaired by `remediate`: main moves fast-forward from one exact
commit (base) to one exact child (head), so the object of the effect is the commit that was judged. A repair lands
alone when a recipe reproduces it, or when main's tests pass, nothing regresses and the change stays in the target's
write scope (`scoped`) and adds no use of an API a building block covers (`blocks`, catalog/blocks.toml).
Production (D30, D36) is measured by the same scanner from the product's own metrics.
"""
import hashlib
from pathlib import Path

from kernel import FORMAT, Release, floor0_digest
from catalog import load as catalog, policy_values, targets

ROLES = ("owner", "inventory_source", "scanner")
DAY = 86_400_000
MINUTE = 60_000

# D33: the facts that open a right are measurements of a pinned instrument. The kernel admits them only from the
# scanner, with this method and coverage, fresh; anyone else (a reviewer, an engineer) cannot sign them, so a person
# cannot replace a measure by an opinion. People sign their own facts: review, approved, requested, ack.
# D37: the instruments are the programs package (instruments/), pinned by its digest and replayable.
# D38: every exchange with the outside world is a boundary transaction under a contract. An observation contract
# names the jobs that compute it, what they may say (properties, resource prefixes) and how it is justified:
#   reproducible  a pinned program on inputs identified by digest: anyone can compute it again
#   attested      a source's word, signed or relayed, within stated limits (a provider's settings, a data snapshot)
#   composite     a reproducible computation over attested material: as good as the weakest source it names
# The method of a pinned property is `programs@<digest>/<contract>`: the kernel admits `tests` only from the suite
# contract, so a compromised production program cannot sign it. An effect contract names the physical profile of
# each operation: `cas` (a compare-and-swap on the very state: applied or not, decided by reading it back),
# `observable` (a request whose effect a later observation establishes; never established absent by silence).


def _programs() -> str:
    h = hashlib.sha256()
    for path in sorted((Path(__file__).resolve().parents[1] / "instruments").glob("*.py")):
        h.update(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
    return "programs@sha256:" + h.hexdigest()


PROGRAMS = _programs()
RUN = ("candidate", "previous", "proven", "live", "running", "good",       # D36: what is, on an exact switch
       "window", "burn_fast", "failing_pct", "switched_min", "unanswered_s", "restarts_last_hour", "migrations_crossed",
       "budget_pct", "canary_error_delta", "canary_requests", "canary_baked_min", "canary_p99_ms", "live_p99_ms",
       "canary_error_pct", "live_error_pct", "live_requests")
CONTRACTS = {
    "observe": {
        "floors": {"form": "composite", "jobs": ["floors"], "resources": ["repo:"],
                   "properties": ["coverage", *sorted({t["property"] for t in targets()
                                                       if t["resource"].startswith("repo:") and not t["id"].startswith("rules-")
                                                       and t["id"] not in ("inventory", "run-platform")})],
                   "attested": ["the pinned third-party data snapshot (D17)", "the provider's settings of main"]},
        "suite": {"form": "reproducible", "jobs": ["remediation", "feature", "contribution"],
                  "resources": ["repo:"],
                  "properties": ["tests", "regressions", "reproduced", "acceptance", "scoped", "blocks"], "attested": []},
        "request": {"form": "reproducible", "jobs": ["request"], "resources": ["build:request/"],
                    "properties": ["contract", "accepted"], "attested": []},
        "production": {"form": "composite", "jobs": ["production"], "resources": ["run:", "repo:code:platform"],
                       "properties": ["coverage", "slo", "lag", "refusals", *RUN],
                       "attested": ["the product's own metrics", "the runner's per-release measures",
                                    "the platform's records of what it corrected or refused (D68)",
                                    "the probes' answers, as the host received them"]},
        "capture": {"form": "attested", "jobs": [], "resources": [], "properties": [],
                    "attested": ["the bytes each declared source returned to the host, at that time"]},
    },
    "effect": {"remediate": "cas", "integrate": "cas", "implement": "cas",
               "deploy": "cas", "rollback": "cas", "canary": "cas", "abort": "cas", "restart": "observable"},
}
INSTRUMENTS = {   # property -> (method, coverage, fresh)
    **{p: (f"{PROGRAMS}/suite", "repo:inventory:all", DAY) for p in CONTRACTS["observe"]["suite"]["properties"]},
    **{p: (f"{PROGRAMS}/request", "repo:inventory:all", DAY) for p in CONTRACTS["observe"]["request"]["properties"]},
    **{p: (f"{PROGRAMS}/production", "run:sources:all", 2 * MINUTE if p == "window" else 15 * MINUTE)
       for p in RUN},
}


DECISION = {"observed": ["decision", "approve", "real", "human"]}        # the human's yes, on the exact resource


def _m(prop, status):
    return {"observed": [prop, status, "real"]}


def _c(prop, way, bound):
    return {"compare": [prop, way, bound, "real"]}


def _auto(*atoms):
    return {"all": list(atoms)}


def _human(*atoms):
    """The human route: the facts that make the move possible at all, and the human's decision on it."""
    return {"all": [*atoms, DECISION]}


_back = (_m("previous", "yes"), _m("proven", "yes"), _c("migrations_crossed", "le", "@rollback_migrations"))

FLOORS = {
    "format": FORMAT,
    "floor0": floor0_digest(),
    "levels": ["unknown", "real"],
    "ttl": {"pending": DAY, "unredeemed": DAY, "reconcile": DAY, "proof": DAY, "observation": DAY},
    # The floor value of every setting a route compares with: the loosest the rules may set (F0-12, D36).
    "settings": policy_values("floor"),
    # Closure on independent proof: every effect leaves a proof obligation only independent evidence closes.
    "evidence": {"evidence": {"fields": {"under": "id", "resource": "resource", "subject": "id", "level": "str"}}},
    "discharges": {"evidence": [{"obligation": "proof", "key": "subject", "min_level": "real"}]},
    "ops": {
        "inventory-refresh": {"args": {"scope": "segment"}, "resource": "repo:inventory:{scope}",
                              "routes": {"auto": _auto({"prefix": ["resource", "repo:inventory:"]}),
                                         "human": _human()}},
        # Fast-forward main from `base` to its child `head`, repairing repo:{area}:{item}. The facts are observed on
        # this very resource, so they bind both commits of the transition.
        "remediate": {"args": {"area": "segment", "item": "segment", "base": "segment", "head": "segment"},
                      "resource": "repo:{area}:{item}/{base}/{head}",
                      "routes": {"reproduced": _auto(_m("tests", "green"), _m("reproduced", "yes")),
                                 "scoped": _auto(_m("tests", "green"), _m("regressions", "none"), _m("scoped", "yes"),
                                                 _m("blocks", "clean")),
                                 "human": _human(_m("tests", "green"), _m("regressions", "none"))}},
        # Fast-forward main from `base` to `head`, a contribution from the hosting inbox (D23): code the agent did not
        # write lands only on the human's word, after main's tests and no regression.
        "integrate": {"args": {"contributor": "segment", "base": "segment", "head": "segment"},
                      "resource": "repo:contrib:{contributor}/{base}/{head}",
                      "routes": {"human": _human(_m("tests", "green"), _m("regressions", "none"))}},
        # Fast-forward main from `base` to `head`, the agent's implementation of a contracted request (D34). The
        # human said what the product must do by signing the contract; its acceptance tests decide.
        "implement": {"args": {"request": "segment", "base": "segment", "head": "segment"},
                      "resource": "repo:feature:{request}/{base}/{head}",
                      "routes": {"accepted": _auto(_m("acceptance", "green"), _m("tests", "green"),
                                                   _m("regressions", "none"), _m("scoped", "yes"),
                                                   _m("blocks", "clean")),
                                 "human": _human(_m("acceptance", "green"), _m("tests", "green"),
                                                 _m("regressions", "none"))}},
        # Switch production from release `from` (a commit of main, or none) to main's head `to` (D30): directly in
        # the deployment window with error budget left, or by promoting a canary that held.
        "deploy": {"args": {"from": "segment", "to": "segment"}, "resource": "run:release:all/{from}/{to}",
                   "routes": {"direct": _auto(_m("candidate", "yes"), _m("window", "open"),
                                              _c("budget_pct", "ge", "@freeze_below")),
                              "promote": _auto(_m("candidate", "yes"),
                                               _c("canary_error_delta", "le", "@canary_max_error_delta"),
                                               _c("canary_requests", "ge", "@canary_min_requests"),
                                               _c("canary_baked_min", "ge", "@canary_bake_min")),
                              "human": _human(_m("candidate", "yes"))}},
        # Start `to` on a share of traffic beside the live `from` (D32); promoting it is `deploy`.
        "canary": {"args": {"from": "segment", "to": "segment"}, "resource": "run:canary:all/{from}/{to}",
                   "routes": {"auto": _auto(_m("candidate", "yes"), _m("window", "open"),
                                            _c("budget_pct", "ge", "@freeze_below")),
                              "human": _human(_m("candidate", "yes"))}},
        # Switch production back from `from` to `to`, the release it replaced, repairing run:service:all: the live
        # release broke soon after its switch (or never answered), and the one it replaced was proven good.
        "rollback": {"args": {"from": "segment", "to": "segment"}, "resource": "run:service:all/{from}/{to}",
                     "routes": {"burn": _auto(*_back, _c("switched_min", "le", "@rollback_horizon_min"),
                                              _c("burn_fast", "ge", "@burn_fast")),
                                "failing": _auto(*_back, _c("switched_min", "le", "@rollback_horizon_min"),
                                                 _c("failing_pct", "ge", "@failing")),
                                "unanswered": _auto(*_back, _c("unanswered_s", "ge", 90)),
                                "human": _human(_m("previous", "yes"))}},
        # Start the live release again (D31): the n-th restart of this release, so each one is judged once.
        "restart": {"args": {"release": "segment", "n": "segment"}, "resource": "run:process:all/{release}/{n}",
                    "routes": {"failing": _auto(_m("live", "yes"),
                                                _c("restarts_last_hour", "le", "@restarts_per_hour"),
                                                _c("failing_pct", "ge", "@failing")),
                               "burn": _auto(_m("live", "yes"), _c("restarts_last_hour", "le", "@restarts_per_hour"),
                                             _c("burn_fast", "ge", "@burn_fast")),
                               "human": _human()}},
        # Take the canary `to` out; it is never offered again. Taking a canary out is always safe.
        "abort": {"args": {"from": "segment", "to": "segment"}, "resource": "run:canary:abort/{from}/{to}",
                  "routes": {"auto": _auto(_m("running", "yes")), "human": _human()}},
    },
    "conditions": {},
    # Coverage: each declared universe must be observed complete by an independent source, or it is a gap.
    "targets": targets(),
    "obligations": [],
    # D34: what the product must do, as a request whose contract is a file of acceptance tests a person signs.
    # The contract is signed only once the scanner saw every one of its tests fail on main (a test already passing
    # promises nothing); the request is delivered only once main passes them, with the contract unchanged.
    "resources": {"request": {
        "fields": {"title": "str", "spec": "digest", "contract": "digest"},
        "states": ["proposed", "contracted", "delivered", "withdrawn"], "initial": "proposed",
        "transitions": {
            "contract": {"from": ["proposed"], "to": "contracted", "writes": [],
                         "requires": {"all": [{"observed": ["contract", "red", "real"]}]}},
            "deliver": {"from": ["contracted"], "to": "delivered", "writes": [],
                        "requires": {"all": [{"observed": ["accepted", "yes", "real"]}]}},
            "withdraw": {"from": ["proposed", "contracted"], "to": "withdrawn", "writes": [],
                         "requires": {"all": [{"prefix": ["resource", "build:request/"]}]}}}}},
    "instruments": {p: {"method": m, "coverage": c, "sources": ["@scanner"], "min_level": "real", "fresh_ms": f}
                    for p, (m, c, f) in INSTRUMENTS.items()},
}

RELEASE = Release(FLOORS, ROLES)

# The rules a new installation starts with: the ceremony writes them, the human changes them in the interface. Each
# key here is a choice inside the socle; the kernel refuses a rule looser than the floors above.
RECOMMENDED = {
    "routes": {"restart": []},                  # restarting stays the human's call until the rules say otherwise
    "settings": {**policy_values("recommended"), **{name: {} for name in catalog()["policy"]["section"]}},
}


def rules(bindings: dict, **changes) -> dict:
    """A client's rules for this release: the recommended ones, the role bindings, and the given sections."""
    import copy
    out = {"format": "standard-client/1", "floors": RELEASE.digest, "bindings": dict(bindings),
           **copy.deepcopy(RECOMMENDED)}
    for section, value in changes.items():
        if section == "settings":
            out["settings"] = {**out["settings"], **copy.deepcopy(value)}
        else:
            out[section] = copy.deepcopy(value)
    return out
