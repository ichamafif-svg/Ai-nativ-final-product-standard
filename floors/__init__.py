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
"""
from kernel import FORMAT, Release, floor0_digest
from kernel.floor0 import MIN_DELAY_MS

ROLES = ("owner", "inventory_source", "scanner", "compliance_officer")
DAY = 86_400_000

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
    },
    "conditions": {
        "remediate-autonomous": {"all": [{"observed": ["tests", "green", "real"]},
                                         {"observed": ["reproduced", "yes", "real"]}]},
        "remediate-reviewed": {"all": [{"observed": ["tests", "green", "real"]},
                                       {"observed": ["review", "approved", "real"]}]},
    },
    # Coverage: each declared universe must be observed complete by an independent source, or it is a gap.
    "targets": [
        {"id": "inventory", "kind": "coverage", "resource": "repo:inventory:all", "property": "coverage",
         "expect": "complete", "min_level": "real", "fresh_ms": DAY, "due_ms": DAY, "owner": "@owner",
         "sources": ["@inventory_source"], "repair": "inventory-refresh"},
        {"id": "soa", "kind": "coverage", "resource": "org:controls:soa", "property": "coverage",
         "expect": "complete", "min_level": "real", "fresh_ms": 365 * DAY, "due_ms": 30 * DAY, "owner": "@owner",
         "sources": ["@compliance_officer"], "human": True},
        *(_target(*t, "inventory", "@scanner", repair="remediate") for t in TECHNICAL),
        *(_target(*t, "inventory", "@scanner", human=True) for t in SETTINGS),
        *(_target(i, r, "attested", "current", f, 30, "soa", "@compliance_officer", human=True)
          for i, r, f in ORGANISATIONAL),
    ],
    "obligations": [],
}

RELEASE = Release(FLOORS, ROLES)
