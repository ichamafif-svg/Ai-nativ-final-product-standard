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

`standard/catalog` is the release's common definition of product requirements. `maintenance.toml` declares the
maintenance targets and repair instructions; `policy.toml` defines signed policy parameters, their editor types,
floors and recommended values; `rules/*.toml` details the technical requirements; `values.toml` and `blocks.toml`
define their parameters and minimum implementation contracts. `standard/floors.py` compiles these declarations into
the existing law language and defines governed moves. The human's signed choices instantiate the effective law.
Model providers, budgets and schedules in `standard.toml` are execution configuration, never product policy.

Selection uses product features and touched surfaces/constructs, including the draft's new features and declared
features. `declared_features()` derives these from signed settings, including `@high_value`; scanner inputs and
model missions use the same projection. `contracts()` supplies the same rule/block/parameter/check reading to construction, review, exploration
and the interface. `python -m standard.surface rule RULE-ID` prints that contract; `coverage` shows measured state.
`absorb` describes the intended division of work: it never proves correct block adoption or complete path coverage.
A rule without a check, a missing parameter or an unknown client mapping stays visible; no opinion becomes proof.

Most rules hold by using a building block (`blocks/python/standard_blocks`, `blocks/js/nextjs`, `blocks/js/front.mjs`).
FastAPI: `secure_app` for the web layer, `Oidc(...).bind(app)` for sign-in and sessions, `Access(...).bind(app)` and
`allow("route.id")` on every route, `crypto`, `files`, `parse`, `process`, `outbound`, `input`, `render`, `log`,
`runtime`, `data`. Next.js (`@standard/blocks`): `guard(values, NextResponse)` as the middleware and
`securityHeaders(values)` in next.config, `createOidc(...)` for sign-in, `access.route("id", fn)` on every route
handler and `access.action("id", fn, req)` on every server action, `body(request, Schema)` with a strict Zod schema.
The selected context shows the use for your product's stack; a block your stack does not have yet is not owed, its bans hold.
Use the blocks' types and helpers rather than plain values: `secret()` gives a `Secret` (`.reveal()` only where the
value is really sent), `for_user(session, user)` for every database session of a request, `arg()` for any user value
passed to a process, `Text[n]`/`Id`/`Email` in input models. To narrow access, add `also=` predicates; to add a guard
check, pass `refuse=`: both can only refuse. What the blocks guarantee beyond the standards is in
`blocks/HARDENING.md`. The APIs a block
covers are banned elsewhere (`standard/catalog/blocks.toml`); the scanner signs `blocks = clean` only when a change adds
none. Never copy a block into the product. Values such as `@access`, `@upload_max_bytes` or `@app` are the human's: you
may draft them, never decide them.

## Candidate workflow and simplicity

One governed agent identity may have several workers in U. One constructor writes; two reviewers (correctness/security
and simplicity) inspect the same immutable draft in parallel, each with its own read/search dialogue. They never get
write tools, a privileged credential or authority to attest. A reviewer may report no findings. Every concrete finding
names its path, issue, effect and proposed correction; the constructor fixes it or records a reasoned disagreement.
Any edit invalidates the reviews. A revised draft must complete review before publication. Review failure is visible,
not an empty success. This is the sole model construction path for BUILD and repair, including in tests; no switch
bypasses review. Dependencies and design use these same readers. Signed values come from the mission context,
not a second parameter channel.

Prefer the smallest sufficient design for the current need. Reuse existing mechanisms; justify a new layer,
dependency or state; remove dead code and obsolete intermediaries. Preserve behaviour and guarantees. Fewer lines or
files alone are not a quality measure. Model edits use `{files: {path: full_content_or_null}}`: null deletes a file,
under the same write scope and reserved-path checks as an edit. Tests and accepted contracts remain protected.

The workflow defaults to two review rounds, a 180-second review deadline and eight research steps per dialogue.
`[agent.review] rounds = 1..3, timeout_s = 1..600`; `[agent] research_steps = 1..32` bounds every dialogue. There are
at most one initial build and three dialogues per review round (two readers, one correction).
Optional `[llm.correctness]`, `[llm.simplicity]` choose reader providers; otherwise readers use frontier.
Provider calls time out after 120 seconds. An already running HTTP call may finish after the review deadline; its late
answer cannot publish the candidate or start another research step. No recursive delegation or reviewer-of-reviewer.

All model missions use `context.assemble`: pinned journal/law/code/catalog basis, task, exact scope, selected
contracts, diagnostics and a bounded repository map. The initial packet is bounded to 28,000 characters. Large entries
are deferred whole, with their references; selection never exempts omitted requirements. `read(ref=..., offset=...)`
reads complete pinned declarations/documents in pages; `search(in=context, query=...)` discovers their references.
BUILD specifications and immutable acceptance contracts are available in full, including beyond the initial preview.
Ordinary file reads are paged too. These are the existing research tools, with the same role restrictions and budget.

One patrol mechanism explores a question and a read scope. `simplicity[:path]` examines design;
`rules:CATEGORY[:path]` examines the AI-readable part of that category. The snapshot wrapper enforces the same file
boundary for reads, searches and the repository map. Applicability is still determined on the whole product.
The interface and running patrol use the same mission definition. Simplicity selects the contracts triggered in its
subsystem, including deterministic block guarantees; a target focus carries that exact target and its measurement.
Without a repository snapshot, a human context leaves applicability unavailable instead of inventing a rule selection.
Automatic rounds rotate questions and repository/subsystem scopes, each category keeping its own scope cursor.
They run after ordinary moves, by default at most once per hour; `[agent] patrol_interval_ms` is
60000..86400000. Schedule state survives failures and restarts. Manual use:
`python -m standard.autonomy patrol standard.toml simplicity:app`; inspect proposals with `patrol-results`.
Results retain main, law digest and scope, become stale when main or law changes, and remain proposals. Serve an
existing debt within its scope, or propose a human-contracted BUILD request for a transversal refactor.

## Measurement limits

SAST and catalog checks share one isolated Bandit runner. Candidate modules and .bandit files cannot replace or
configure it. A failed, malformed or partial report, including omitted requested files, is unmeasured, never clean. `make coverage` inventories dynamic rule
categories as well as fixed probes. A block import is presence only: static coverage also looks for resolved calls
(and application binding for Python access/sessions). This remains syntactic evidence; runtime probes are needed to
verify behaviour, and universal traversal of the block is not proved by static wiring. JavaScript scanning resolves
direct aliases, destructured names and literal member access; computed calls, dynamic execution/imports and template
interpolation are explicitly unmeasured until a pinned parser covers them. Python parse errors and source-size limits
are also unmeasured. Such a candidate cannot obtain `blocks = clean` on an autonomous scoped/accepted route.

## Writing code

A repair lands alone only by the `reproduced` route (a recipe the scanner recomputes) or the `scoped` route (tests
green, no regression, every changed path inside the target's write scope, measured by the scanner from
`instruments/scope.py`, and no banned API added: `blocks = clean`). A request lands alone only when its contract is accepted, inside its own scope. Everything
else waits for the human's yes.

In maintained client repositories, never write under `tests/` (a request's acceptance tests are its contract, measured byte for byte), `.github/` (except
the `actions` target's `.github/workflows/` scope) or the maintained client's `standard/` directory. Those reserved
client paths are distinct from this repository's own implementation and verification suite. When maintaining
Standard itself, update its tests for changed contracts without weakening kernel, BT or admission checks. Facts such as `tests`, `regressions`,
`scoped`, `acceptance`, `window` or production numbers are measured by the scanner; nobody else can sign them. Name
what a commit is for with a trailer: `Standard-Target:` for a repair, `Standard-Request: <id>` for a request.

A missing route is visible as `NO_ROUTE`; its `investigate` task keeps the same obligation and deadline. The agent may
read/search its snapshot, fetch only configured research sources, and experiment in the strict bubblewrap jail.
Research outputs are notes, never signed facts or permission to register an instrument.

The architecture, its chosen coverage and its limits are in [ARCHITECTURE.md](ARCHITECTURE.md).
