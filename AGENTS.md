# Agents

Repository layout: `kernel/` judges, `bt/` owns physical trust mechanisms, `instruments/` computes pinned measures.
`standard/` holds Standard's common autonomy, interface, floors and privileged runtime assembly, not a client product.
`tools/` installs, operates and inspects Standard; `examples/` contains demonstrations only. Moving the runtime does not remove it
from the installation's release pin. Run `make layers` for dependency checks; line counts are informational.

From the repository root, run `python -m standard.surface tasks` to see the work the law asks for, then
`python -m standard.surface context TASK_ID` for one task: its debt, its requirement, its repair route and the
trusted contracts it needs. `python -m standard.surface law SECTION/ID` shows one declaration of the effective law.

Nothing printed is a permission. You can only submit a statement signed with your own identity; the kernel
decides. A repair that a recipe reproduces can land without a human; any other repair waits for a human's
signed review (`python -m standard.surface review`). If Standard is unreachable or unqualified, nothing is attested
or authorized.

What you may change: code. Never `tests/` (a request's acceptance tests are its contract, measured byte for byte),
`.github/` or the maintained client's `standard/` directory (the engineers' rules, committed only as signed).
That reserved client path is distinct from this repository's Python package `standard/`; it does not make Standard's own
source unmodifiable during an authorized release refactor. Facts such as `tests`, `regressions`,
`acceptance` or production numbers are measured by the scanner; nobody else can sign them. Name what a commit is
for with a trailer: `Standard-Target:` for a repair, `Standard-Request: <id>` for a request.

The architecture, its chosen coverage and its limits are in [ARCHITECTURE.md](ARCHITECTURE.md).

A missing route is visible as `NO_ROUTE`; its `investigate` task keeps the same obligation and deadline. The agent may
read/search its snapshot, fetch only configured research sources, and experiment in the strict bubblewrap jail. Research
outputs are notes, never signed facts or permission to register an instrument. Generic repairs require an operator-configured
write scope and human review; the kernel still decides and only the law's accepted source can close the gap.
The same effective-law context feeds the CLI, web context endpoint and maintenance model. `make coverage` is auxiliary
source inspection; it is not the law or a runtime qualification. Details and configuration: ARCHITECTURE.md §20.5.
