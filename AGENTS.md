# Agents

Repository layout: `kernel/` judges, `bt/` owns physical trust mechanisms, `instruments/` computes pinned measures.
`product/` holds the current product and its privileged runtime assembly. Moving that runtime does not remove it
from the installation's release pin. Run `make layers` for dependency checks; line counts are informational.

From the repository root, run `python -m product.surface tasks` to see the work the law asks for, then
`python -m product.surface context TASK_ID` for one task: its debt, its requirement, its repair route and the
trusted contracts it needs. `python -m product.surface law SECTION/ID` shows one declaration of the effective law.

Nothing printed is a permission. You can only submit a statement signed with your own identity; the kernel
decides. A repair that a recipe reproduces can land without a human; any other repair waits for a human's
signed review (`python -m product.surface review`). If Standard is unreachable or unqualified, nothing is attested
or authorized.

What you may change: code. Never `tests/` (a request's acceptance tests are its contract, measured byte for byte),
`.github/` or `standard/` (the engineers' rules, committed only as signed). Facts such as `tests`, `regressions`,
`acceptance` or production numbers are measured by the scanner; nobody else can sign them. Name what a commit is
for with a trailer: `Standard-Target:` for a repair, `Standard-Request: <id>` for a request.

The architecture, its chosen coverage and its limits are in [ARCHITECTURE.md](ARCHITECTURE.md).
