# Agents

The repository is Standard. `kernel/` judges; `bt/` owns physical trust mechanisms; `instruments/` computes pinned
measures; `catalog/` defines product requirements and compiles the socle. `context/` derives the shared reading for
humans and agents. `agent/` proposes and schedules work; `surface/` presents it and forwards signed human gestures.
`runtime/` assembles the operator and runs product releases. `tools/` installs and audits; `examples/` is demonstration.
Run `make layers` for dependency checks. Location does not remove code from its release pin or effective trust role.

## The game

One human, one agent (ARCHITECTURE.md §4.8, D51–D53). The socle (`catalog/floors.py`) declares every move (an op on an
exact resource) and its routes. The rules of the game are one client document the human signs, in force at once: which
autonomous routes stay on, the thresholds those routes compare with (never looser than the socle), and what production
is judged against. The human has three gestures: **yes** (`decision = approve` on the exact resource), **no** (a freeze),
**rules** (sign new rules). The agent never signs rules and holds one capability.

A move is `ready` when an autonomous route holds on facts the scanner measured, `decided` when the human said yes,
`yours` when only the human's decision opens it. `python -m surface moves` shows every move and its status,
`python -m surface queue` what waits for the human.

## Reading

From the repository root, `python -m surface tasks` shows the work the law asks for, then
`python -m surface context TASK_ID` one task: its debt, its requirement, its routes and the facts each needs.
`python -m surface law SECTION/ID` shows one declaration of the effective law.
`python -m surface drift [TARGET] --findings findings.json` shows the drift dossier for born gaps;
`python -m surface patrol [FOCUS] --findings findings.json` builds an exploratory patrol context.
`context/model.py` is the shared, derived reading graph behind all of these. Neither this graph nor a
diagnostic finding is authority; K and the independent checker never import it. Findings from another main commit or
law digest are stale, not current evidence.

Nothing printed is a permission. You can only submit a statement signed with your own identity; the kernel decides,
and the second judge decides again. If Standard is unreachable or unqualified, nothing is attested or authorized.

## The rules you code to

`catalog` is the release's common definition of product requirements. `maintenance.toml` declares the
maintenance targets and repair instructions; `policy.toml` defines signed policy parameters, their editor types,
floors and recommended values; `rules/*.toml` details the technical requirements; `values.toml` and `blocks.toml`
define their parameters and minimum implementation contracts. `catalog/floors.py` compiles these declarations into
the existing law language and defines governed moves. The human's signed choices instantiate the effective law.
Model providers, budgets and schedules in `standard.toml` are execution configuration, never product policy.

Selection uses product features and touched surfaces/constructs, including the draft's new features and declared
features. `declared_features()` derives these from signed settings, including `@high_value`; scanner inputs and
model missions use the same projection. `contracts()` supplies the same rule/block/parameter/check reading to construction, review, exploration
and the interface. `python -m surface rule RULE-ID` prints that contract; `coverage` shows measured state.
`absorb` describes the intended division of work: it never proves correct block adoption or complete path coverage.
A rule without a check, a missing parameter or an unknown client mapping stays visible; no opinion becomes proof.

Most rules hold by using a building block (`blocks/python/standard_blocks`, `blocks/js/nextjs`, `blocks/js/front.mjs`).
Python primitives: `crypto`, `parse`, `process`, `outbound`, `input` (Pydantic), `data` (SQLAlchemy), `render`, `log`,
`runtime`. Their catalog definitions use `.python`; FastAPI inherits them from this one definition.
FastAPI integrations: `secure_app` for web, `Oidc(...).bind(app)` for sessions, `Access(...).bind(app)` and
`Depends(access.allow("route.id"))` on every route, `Files` for uploads/downloads. `Pages.render` and `runtime.install(app)` are
explicit optional Starlette/FastAPI helpers, not portable response/lifecycle APIs. A Python suffix never means
FastAPI: the scanner must observe a FastAPI import. Other Python frameworks keep generic primitives and do not
inherit these framework integrations. Install `standard-blocks[web]` for the FastAPI integrations; the base package
does not require FastAPI or PyJWT. Next.js (`@standard/blocks`): `guard(values, NextResponse)` as the middleware and
`securityHeaders(values)` in next.config, `createOidc(...)` for sign-in, `access.route("id", fn)` on every route
handler and `access.action("id", fn, req)` on every server action, `body(request, Schema)` with a strict Zod schema.
The selected context shows the use for your product's stack; a block your stack does not have yet is not owed, its bans hold.
Use the blocks' types and helpers rather than plain values: `secret()` gives a `Secret` (`.reveal()` only where the
value is really sent), `for_user(session, user)` for every database session of a request, `arg()` for any user value
passed to a process, `Text[n]`/`Id`/`Email` in input models. To narrow access, add `also=` predicates; to add a guard
check, pass `refuse=`: both can only refuse. What the blocks guarantee beyond the standards is in
`blocks/HARDENING.md`. The APIs a block
covers are banned elsewhere (`catalog/blocks.toml`); the scanner signs `blocks = clean` only when a change adds
none. Never copy a block into the product. Values such as `@access`, `@upload_max_bytes` or `@app` are the human's: you
may draft them, never decide them.
D68 (ARCHITECTURE.md §4.10) is decided, not yet implemented: transversal properties (ingress, identity, egress,
secrets, keys, data filtering, resources, logs, files) move to the execution platform; only `access` and `render`
stay blocks.
Do not extend the blocks it absorbs.
D69 (§4.11), also decided, not implemented: each mission will carry the capability map of its bac; a refusal
record says what capability is missing and which interface serves the need. Adapt the design, or draft the value
for the human to sign; never work around a wall.

Standard also consumes its own Python blocks directly from `blocks.python.standard_blocks` in this checkout;
products install the same source as `standard_blocks`. No copy, bootstrap alias or alternate implementation.
Model calls, configured research fetches and metadata refresh use `outbound.request`, the synchronous entry to
the existing checked client; named endpoints and limits come from operator configuration (metadata hosts are fixed).
HTTPS is required, including for a local model; private model hosts require an explicit port. Environment proxies
and redirects cannot reroute a call. Provider JSON and model proposals use `parse.strict_json`; model replies are
bounded to 8 MiB/64 levels, research to 1 MB/10 seconds, metadata to 32 MiB/60 seconds.
Provider keys use `runtime.read_secret` and `Secret`, revealed only in the outgoing authentication headers.
The console uses strict parsing on all POST bodies and structured logs; parsing never normalizes signed data.
Block logs go to stderr, keeping CLI result JSON on stdout. The egress audit retains its own content-free format.
This is scoped adoption, not whole-repository block compliance. The console's HTTP server is not ASGI and its
current DOM rendering needs a separate migration before the full web/front contracts can hold. Its existing
headers/host checks remain in place. Repository processes, evidence files and physical cryptography keep their
specific contracts; K and BT may not import either block package name. Product probes already use the installed
blocks to exercise the product; this does not make block presence independent proof of every path.

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

All model missions use `context.missions.assemble`: pinned journal/law/code/catalog basis, task, exact scope, selected
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
`python -m agent patrol standard.toml simplicity:app`; inspect proposals with `patrol-results`.
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

## One work path and one observation source

BUILD/RUN are presentation contexts, not route filters or separate task queues. Routes match a resource, need and
supported targets. WorkEngine keys tasks by their obligation-derived id. Opening an older scheduling store collapses
its partitions transactionally, retaining the earliest deadline, total attempts, longest retry/lease and event history.
A request keeps its accepted contract; a repair keeps its obligation. Both use the common candidate and precheck path;
request checks add acceptance and reject every local regression, while repair retains its existing recipe follow-ups.

The interface never scrapes metrics. BT captures declared sources; `runtime.operator.publish_readings` publishes only
retained metrics chunks and their referenced bytes, with source, capture time and digest. No probe response, runner
capture or privileged key is published. The interface verifies digests and builds a disposable presentation cache;
old independently collected metric rows are discarded when that cache first adopts capture provenance. Missing,
corrupt or stale captures remain unavailable, and unknown capture state cannot resolve an existing incident. This
public projection grants no authority and never becomes an input to independent measurement or kernel admission.
