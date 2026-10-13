# Agents

Repository layout: `kernel/` judges, `bt/` owns physical trust mechanisms, `instruments/` computes pinned measures.
`standard/` holds Standard's common autonomy, interface, floors and privileged runtime assembly, not a client product.
`tools/` installs, operates and inspects Standard; `examples/` contains demonstrations only. Moving the runtime does not remove it
from the installation's release pin. Run `make layers` for dependency checks; line counts are informational.

From the repository root, run `python -m standard.surface tasks` to see the work the law asks for, then
`python -m standard.surface context TASK_ID` for one task: its debt, its requirement, its repair route and the
trusted contracts it needs. `python -m standard.surface law SECTION/ID` shows one declaration of the effective law.
`python -m standard.surface drift [TARGET] --findings findings.json` shows the drift controller's dossier for born
gaps: law target, measured drift, code locations reported by instruments, projected route, autonomy and proof needed.
`python -m standard.surface patrol [FOCUS] --findings findings.json` builds a wide or targeted exploratory law-patrol
context for areas where deterministic instruments may not yet see enough.

Nothing printed is a permission. You can only submit a statement signed with your own identity; the kernel
decides. A repair that a recipe reproduces can land without a human; any other repair waits for a human's
signed review (`python -m standard.surface review`). If Standard is unreachable or unqualified, nothing is attested
or authorized.

What you may change in a generic repair: code, never `tests/` (a request's acceptance tests are its contract,
measured byte for byte), `.github/` or the maintained client's `standard/` directory. The `actions` target has its
own narrow `.github/workflows/` scope; the `configure` operation may change only the engineer-signed
`standard/rules.json` bytes. Neither exception grants a generic model write scope.
That reserved client path is distinct from this repository's Python package `standard/`; it does not make Standard's own
source unmodifiable during an authorized release refactor. Facts such as `tests`, `regressions`,
`acceptance` or production numbers are measured by the scanner; nobody else can sign them. Name what a commit is
for with a trailer: `Standard-Target:` for a repair, `Standard-Request: <id>` for a request.

The architecture, its chosen coverage and its limits are in [ARCHITECTURE.md](ARCHITECTURE.md).

A missing route is visible as `NO_ROUTE`; its `investigate` task keeps the same obligation and deadline. The agent may
read/search its snapshot, fetch only configured research sources, and experiment in the strict bubblewrap jail. Research
outputs are notes, never signed facts or permission to register an instrument. Generic repairs require an operator-configured
write scope and human review; the kernel still decides and only the law's accepted source can close the gap.
`standard/autonomy/drift_map.py` projects already-open constitutional debts and optional scanner findings into dossiers.
`standard/autonomy/read_model.py` is the shared, derived reading graph behind the agent context, drift, patrol, target
surface, web state, CLI and source inventory. It includes every effective-law section and labels each relation by origin
and certainty. `python -m standard.surface read-model --repo PATH` shows it locally, with a Python AST code index when a
repository is supplied. Neither this graph nor a diagnostic finding is authority; K and the independent checker never
import it. Findings from another main commit or law digest are stale, not current evidence.
`standard/autonomy/patrol.py` builds a wide or targeted context for searching blind spots. The model pass in
`advisory_llm.py` is run by the agent process with `python -m standard.autonomy patrol standard.toml [FOCUS]`; it may
read/search a snapshot and propose suspicions, never measure, certify, close, authorize or change law. The web's
"Contexte de patrouille" button only shows the context; it does not launch the model. `drift.py` is a compatibility
import facade. `standard/autonomy/law_surface.py` derives a target-only map from law, measurement registries, diagnostic
locations and visible facts through the read model. It has no persisted human validation or code binding yet.
ISO/DORA/NIS2 labels are coarse projections, not certification; OWASP agentic references are present but unmapped.
`make coverage` is an auxiliary source inventory using the same measurement registry, not runtime qualification.
The differences and remaining work are explicit in ARCHITECTURE.md §20.5.
