"""The floors of this release (ARCHITECTURE.md §12): what Standard imposes on every client.

Declarative, in the same language as a client law, so every requirement produces a measurable gap: autonomy is the
distance between what the floors and the client require and what the repository has. Only the Standard team changes
this file, through a release. A client binds the roles below to its identities, adds its own declarations and may
only tighten.

Technical measures are observed by the independent scanner and repaired by `remediate`: main moves fast-forward from
one exact commit (base) to one exact child (head), so the object of the effect is the commit that was judged.
Autonomy is reproducibility (§11.4): without a human, a repair needs `tests = green` and `reproduced = yes` from an
independent instrument; otherwise a signed review of this exact transition. Organisational measures are attested by
the compliance officer and have no automatic repair: their gap goes to people.

Production (D30) is measured by the same scanner from the product's own metrics: every declared source answers, the
service meets its objective, and production runs main's head. The switches (deploy, rollback, restart, canary, abort)
move the live release by a compare-and-swap. D36: the scanner signs what is (this switch exists, this release was
proven good) and numbers (burn rate, failing share, minutes since the switch, canary deltas); the bounds below decide
when the agent may act alone. The engineers' finer settings are the agent's own restraint inside these bounds.
"""
from kernel import FORMAT, Release, floor0_digest
from kernel.floor0 import MIN_DELAY_MS

ROLES = ("owner", "inventory_source", "scanner", "compliance_officer")
DAY = 86_400_000
MINUTE = 60_000

# (id, resource, property, expect, fresh days, due days) observed by @scanner, repaired by `remediate`.
TECHNICAL = (
    ("vulns", "repo:deps:vulns", "high", "none", 1, 7),
    ("deps-age", "repo:deps:age", "major_behind", "none", 7, 30),
    ("licenses", "repo:deps:licenses", "policy", "compliant", 7, 30),
    ("secrets", "repo:code:secrets", "leaks", "none", 1, 1),
    ("sast", "repo:code:sast", "high", "none", 1, 30),
    ("ci", "repo:ci:main", "status", "green", 1, 2),
    ("actions", "repo:ci:actions", "pinned", "all", 7, 30),
    ("sbom", "repo:supply:sbom", "state", "current", 7, 7),
)
# Observed by @scanner, repaired by people: only the guard moves main; every commit on main is a judged effect.
SETTINGS = (
    ("branch", "repo:settings:main", "protection", "guard-only", 1, 7),
    ("lineage", "repo:main:lineage", "unjudged", "none", 1, 1),
)
# (id, resource, fresh days) attested "current" by @compliance_officer under the statement of applicability.
ORGANISATIONAL = (
    ("isms", "org:isms:policy", 365), ("risk", "org:risk:assessment", 365), ("access", "org:access:review", 90),
    ("training", "org:people:training", 365), ("hr", "org:people:hr", 365), ("suppliers", "org:supply:register", 365),
    ("incident", "org:incident:procedure", 365), ("continuity", "org:continuity:test", 365),
    ("backup", "org:backup:restore", 90), ("legal", "org:legal:register", 365),
    ("audit", "org:audit:independent", 365), ("physical", "org:physical:sites", 365),
    ("crypto", "org:crypto:policy", 365), ("resilience", "org:resilience:testing", 365),
    ("assets", "org:assets:register", 365), ("infra", "org:infra:baseline", 180),
    ("monitoring", "org:ops:monitoring", 180), ("threat", "org:threat:intel", 180),
)


# D33: the facts that open a right are measurements of a pinned instrument. The kernel admits them only from the
# scanner, with this method and coverage, fresh; anyone else (a reviewer, an engineer) cannot sign them, so a person
# cannot replace a measure by an opinion. People sign their own facts: review, approved, requested, ack.
# property -> (method, coverage, fresh)
INSTRUMENTS = {
    "tests": ("main-suite", "repo:inventory:all", DAY), "regressions": ("floor-probes", "repo:inventory:all", DAY),
    "reproduced": ("recipe-replay", "repo:inventory:all", DAY),
    "acceptance": ("acceptance-suite", "repo:inventory:all", DAY),
    "contract": ("acceptance-suite", "repo:inventory:all", DAY),
    "configured": ("rules-diff", "repo:inventory:all", DAY), "accepted": ("acceptance-suite", "repo:inventory:all", DAY),
    **{p: ("production", "run:sources:all", 15 * MINUTE) for p in (
        "candidate", "previous", "proven", "live", "running",            # D36: what is, on an exact switch
        "burn_fast", "failing_pct", "switched_min", "unanswered_s", "restarts_last_hour", "migrations_crossed",
        "budget_pct", "canary_error_delta", "canary_requests", "canary_baked_min", "canary_p99_ms", "live_p99_ms")},
}


def _target(ident, resource, prop, expect, fresh, due, coverage, source, **extra):
    return {"id": ident, "kind": "property", "coverage": coverage, "resource": resource, "property": prop,
            "expect": expect, "min_level": "real", "fresh_ms": fresh * DAY, "due_ms": due * DAY, "owner": "@owner",
            "sources": [source], **extra}


FLOORS = {
    "format": FORMAT,
    "floor0": floor0_digest(),
    "levels": ["unknown", "real"],
    "ttl": {"pending": DAY, "unredeemed": DAY, "reconcile": DAY, "proof": DAY, "observation": DAY},
    "delays": {"rotate": MIN_DELAY_MS, "grant": MIN_DELAY_MS, "unfreeze": MIN_DELAY_MS, "law": MIN_DELAY_MS},
    "witnesses": {"quorum": 2},
    "controls": {"heartbeat_ms": 0},
    # Closure on independent proof: every effect leaves a proof obligation only independent evidence closes.
    "evidence": {"evidence": {"fields": {"under": "id", "resource": "resource", "subject": "id", "level": "str"}}},
    "discharges": {"evidence": [{"obligation": "proof", "key": "subject", "min_level": "real"}]},
    "ops": {
        "inventory-refresh": {"args": {"scope": "segment"}, "resource": "repo:inventory:{scope}",
                              "profile": "capability"},
        # Fast-forward main from `base` to its child `head`, repairing repo:{area}:{item}. The facts that authorize
        # it are observed on this very resource, so they bind both commits of the transition.
        "remediate": {"args": {"area": "segment", "item": "segment", "base": "segment", "head": "segment"},
                      "resource": "repo:{area}:{item}/{base}/{head}", "profile": "capability"},
        # Fast-forward main from `base` to its child `head`, a client's contribution from the hosting inbox (D23).
        # One judged transition is one commit: the author rebases and squashes onto the current main.
        "integrate": {"args": {"contributor": "segment", "base": "segment", "head": "segment"},
                      "resource": "repo:contrib:{contributor}/{base}/{head}", "profile": "capability"},
        # Switch production from release `from` (a commit of main, or none) to main's head `to` (D30).
        "deploy": {"args": {"from": "segment", "to": "segment"}, "resource": "run:release:all/{from}/{to}",
                   "profile": "capability"},
        # Switch production back from `from` to `to`, the release it replaced, repairing run:service:all.
        "rollback": {"args": {"from": "segment", "to": "segment"}, "resource": "run:service:all/{from}/{to}",
                     "profile": "capability"},
        # Start the live release again (D31): the n-th restart of this release, so each one is judged once.
        "restart": {"args": {"release": "segment", "n": "segment"}, "resource": "run:process:all/{release}/{n}",
                    "profile": "capability"},
        # Fast-forward main from `base` to `head`, the agent's implementation of a contracted request (D34).
        "implement": {"args": {"request": "segment", "base": "segment", "head": "segment"},
                      "resource": "repo:feature:{request}/{base}/{head}", "profile": "capability"},
        # Fast-forward main from `base` to `head`, a change of standard/rules.json an engineer signed (D35).
        "configure": {"args": {"base": "segment", "head": "segment"}, "resource": "repo:config:rules/{base}/{head}",
                      "profile": "capability"},
        # Start `to` on a share of traffic beside the live `from` (D32); promoting it is `deploy`.
        "canary": {"args": {"from": "segment", "to": "segment"}, "resource": "run:canary:all/{from}/{to}",
                   "profile": "capability"},
        # Take the canary `to` out; it is never offered again.
        "abort": {"args": {"from": "segment", "to": "segment"}, "resource": "run:canary:abort/{from}/{to}",
                  "profile": "capability"},
    },
    "conditions": {
        "remediate-autonomous": {"all": [{"observed": ["tests", "green", "real"]},
                                         {"observed": ["reproduced", "yes", "real"]}]},
        "remediate-reviewed": {"all": [{"observed": ["tests", "green", "real"]},
                                       {"observed": ["review", "approved", "real"]}]},
        # A client's work never lands on its author's word: main's own tests, no new gap on any floor target, and a
        # signed human review, always.
        "integrate-reviewed": {"all": [{"observed": ["tests", "green", "real"]},
                                       {"observed": ["regressions", "none", "real"]},
                                       {"observed": ["review", "approved", "real"]}]},
        # D36: the agent acts alone in production only on what the scanner measured, against these bounds. The
        # engineers' settings may ask for more (a higher burn, a shorter horizon, a canary that bakes longer); never
        # for less: the kernel refuses.
        # Main's head, never rolled back, replaces exactly the live release.
        "deploy-autonomous": {"all": [{"observed": ["candidate", "yes", "real"]}]},
        # The live release breaks soon after its switch, and the one it replaced was proven good: step back.
        "rollback-autonomous": {"all": [{"observed": ["previous", "yes", "real"]}, {"observed": ["proven", "yes", "real"]},
                                        {"compare": ["switched_min", "le", 240, "real"]},
                                        {"compare": ["burn_fast", "ge", "14.4", "real"]}]},
        "rollback-failing": {"all": [{"observed": ["previous", "yes", "real"]}, {"observed": ["proven", "yes", "real"]},
                                     {"compare": ["switched_min", "le", 240, "real"]},
                                     {"compare": ["failing_pct", "ge", 5, "real"]}]},
        "rollback-unanswered": {"all": [{"observed": ["previous", "yes", "real"]}, {"observed": ["proven", "yes", "real"]},
                                        {"compare": ["unanswered_s", "ge", 90, "real"]}]},
        # The same switches when the engineers keep them for themselves (D31): the scanner's fact that the switch is
        # possible, and an engineer's signed decision on that exact switch.
        "deploy-reviewed": {"all": [{"observed": ["candidate", "yes", "real"]},
                                    {"observed": ["approved", "yes", "real"]}]},
        "rollback-reviewed": {"all": [{"observed": ["previous", "yes", "real"]},
                                      {"observed": ["requested", "yes", "real"]}]},
        "restart-autonomous": {"all": [{"observed": ["live", "yes", "real"]},
                                       {"compare": ["restarts_last_hour", "le", 11, "real"]},
                                       {"compare": ["failing_pct", "ge", 5, "real"]}]},
        "restart-burn": {"all": [{"observed": ["live", "yes", "real"]},
                                 {"compare": ["restarts_last_hour", "le", 11, "real"]},
                                 {"compare": ["burn_fast", "ge", "14.4", "real"]}]},
        "restart-reviewed": {"all": [{"observed": ["requested", "yes", "real"]}]},
        "canary-autonomous": {"all": [{"observed": ["candidate", "yes", "real"]}]},
        # D35: the rules file changes from the interface with one signature: the scanner checks the commit changes
        # only that file, to exactly what an engineer signed, and that main's tests and the floors hold.
        "configure-signed": {"all": [{"observed": ["configured", "yes", "real"]},
                                     {"observed": ["tests", "green", "real"]},
                                     {"observed": ["regressions", "none", "real"]}]},
        # D34: a feature lands only if its signed contract's acceptance tests pass on this exact transition, main's
        # own tests still pass, no floor target got worse, and a person reviewed the code.
        "implement-reviewed": {"all": [{"observed": ["acceptance", "green", "real"]},
                                       {"observed": ["tests", "green", "real"]},
                                       {"observed": ["regressions", "none", "real"]},
                                       {"observed": ["review", "approved", "real"]}]},
        "deploy-canary": {"all": [{"observed": ["candidate", "yes", "real"]},
                                  {"compare": ["canary_error_delta", "le", "2", "real"]},
                                  {"compare": ["canary_requests", "ge", 20, "real"]},
                                  {"compare": ["canary_baked_min", "ge", 1, "real"]}]},
        "abort-autonomous": {"all": [{"observed": ["running", "yes", "real"]}]},   # taking a canary out is always safe
        "abort-reviewed": {"all": [{"observed": ["requested", "yes", "real"]}]},
    },
    # Coverage: each declared universe must be observed complete by an independent source, or it is a gap.
    "targets": [
        {"id": "inventory", "kind": "coverage", "resource": "repo:inventory:all", "property": "coverage",
         "expect": "complete", "min_level": "real", "fresh_ms": DAY, "due_ms": DAY, "owner": "@owner",
         "sources": ["@inventory_source"], "repair": "inventory-refresh"},
        {"id": "soa", "kind": "coverage", "resource": "org:controls:soa", "property": "coverage",
         "expect": "complete", "min_level": "real", "fresh_ms": 365 * DAY, "due_ms": 30 * DAY, "owner": "@owner",
         "sources": ["@compliance_officer"], "human": True},
        {"id": "run-sources", "kind": "coverage", "resource": "run:sources:all", "property": "coverage",
         "expect": "complete", "min_level": "real", "fresh_ms": 15 * MINUTE, "due_ms": 60 * MINUTE,
         "owner": "@owner", "sources": ["@scanner"], "human": True},
        {"id": "run-slo", "kind": "property", "coverage": "run-sources", "resource": "run:service:all",
         "property": "slo", "expect": "met", "min_level": "real", "fresh_ms": 15 * MINUTE, "due_ms": 30 * MINUTE,
         "owner": "@owner", "sources": ["@scanner"], "repair": "rollback"},
        {"id": "run-live", "kind": "property", "coverage": "run-sources", "resource": "run:release:all",
         "property": "lag", "expect": "none", "min_level": "real", "fresh_ms": 15 * MINUTE, "due_ms": DAY,
         "owner": "@owner", "sources": ["@scanner"], "repair": "deploy"},
        *(_target(*t, "inventory", "@scanner", repair="remediate") for t in TECHNICAL),
        *(_target(*t, "inventory", "@scanner", human=True) for t in SETTINGS),
        *(_target(i, r, "attested", "current", f, 30, "soa", "@compliance_officer", human=True)
          for i, r, f in ORGANISATIONAL),
    ],
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
