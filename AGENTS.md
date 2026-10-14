# Agents

Repository layout: `kernel/` judges, `bt/` owns physical trust mechanisms, `instruments/` computes pinned measures.
`standard/` holds Standard's common autonomy, interface, socle and privileged runtime assembly, not a client product.
`tools/` installs, operates and inspects Standard; `examples/` contains demonstrations only. Moving the runtime does not
remove it from the installation's release pin. Run `make layers` for dependency checks; line counts are informational.

## The game

One human, one agent (ARCHITECTURE.md §4.8, D51–D53). The socle (`standard/floors.py`) declares every move (an op on an
exact resource) and its routes. The rules of the game are one client document the human signs, in force at once: which
autonomous routes stay on, the thresholds those routes compare with (never looser than the socle), and what production
is judged against. The human has three gestures: **yes** (`decision = approve` on the exact resource), **no** (a freeze),
**rules** (sign new rules). The agent never signs rules and holds one capability.

A move is `ready` when an autonomous route holds on facts the scanner measured, `decided` when the human said yes,
`yours` when only the human's decision opens it. `python -m standard.surface moves` shows every move and its status,
`python -m standard.surface queue` what waits for the human.

## Reading

From the repository root, `python -m standard.surface tasks` shows the work the law asks for, then
`python -m standard.surface context TASK_ID` one task: its debt, its requirement, its routes and the facts each needs.
`python -m standard.surface law SECTION/ID` shows one declaration of the effective law.
`python -m standard.surface drift [TARGET] --findings findings.json` shows the drift dossier for born gaps;
`python -m standard.surface patrol [FOCUS] --findings findings.json` builds an exploratory patrol context.
`standard/autonomy/read_model.py` is the shared, derived reading graph behind all of these. Neither this graph nor a
diagnostic finding is authority; K and the independent checker never import it. Findings from another main commit or
law digest are stale, not current evidence.

Nothing printed is a permission. You can only submit a statement signed with your own identity; the kernel decides,
and the second judge decides again. If Standard is unreachable or unqualified, nothing is attested or authorized.

## The rules you code to

The rule catalog is `standard/catalog` (156 rules from OWASP ASVS 5.0, CWE Top 25 and run rules). You do not read it
whole: each change goes through three passes (wide, medium, fine) that show only the rules it triggers, and a refusal
comes back with the broken rule's text. `python -m standard.surface rule RULE-ID` prints one rule with the values in
force; `python -m standard.surface coverage` shows each category's state and debt.

Most rules hold by using a building block (`blocks/python/standard_blocks`, `blocks/js/nextjs`, `blocks/js/front.mjs`).
FastAPI: `secure_app` for the web layer, `Oidc(...).bind(app)` for sign-in and sessions, `Access(...).bind(app)` and
`allow("route.id")` on every route, `crypto`, `files`, `parse`, `process`, `outbound`, `input`, `render`, `log`,
`runtime`, `data`. Next.js (`@standard/blocks`): `guard(values, NextResponse)` as the middleware and
`securityHeaders(values)` in next.config, `createOidc(...)` for sign-in, `access.route("id", fn)` on every route
handler and `access.action("id", fn, req)` on every server action, `body(request, Schema)` with a strict Zod schema.
Each pass shows the use for your product's stack; a block your stack does not have yet is not owed, its bans hold. The APIs a block
covers are banned elsewhere (`standard/catalog/blocks.toml`); the scanner signs `blocks = clean` only when a change adds
none. Never copy a block into the product. Values such as `@access`, `@upload_max_bytes` or `@app` are the human's: you
may draft them, never decide them.

## Writing code

A repair lands alone only by the `reproduced` route (a recipe the scanner recomputes) or the `scoped` route (tests
green, no regression, every changed path inside the target's write scope, measured by the scanner from
`instruments/scope.py`, and no banned API added: `blocks = clean`). A request lands alone only when its contract is accepted, inside its own scope. Everything
else waits for the human's yes.

Never write under `tests/` (a request's acceptance tests are its contract, measured byte for byte), `.github/` (except
the `actions` target's `.github/workflows/` scope) or the maintained client's `standard/` directory. That reserved
client path is distinct from this repository's Python package `standard/`. Facts such as `tests`, `regressions`,
`scoped`, `acceptance`, `window` or production numbers are measured by the scanner; nobody else can sign them. Name
what a commit is for with a trailer: `Standard-Target:` for a repair, `Standard-Request: <id>` for a request.

A missing route is visible as `NO_ROUTE`; its `investigate` task keeps the same obligation and deadline. The agent may
read/search its snapshot, fetch only configured research sources, and experiment in the strict bubblewrap jail.
Research outputs are notes, never signed facts or permission to register an instrument.

The architecture, its chosen coverage and its limits are in [ARCHITECTURE.md](ARCHITECTURE.md).
