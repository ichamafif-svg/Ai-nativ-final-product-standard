# Agents

From the repository root, run `python -m surface tasks` to see the work the law asks for, then
`python -m surface context TASK_ID` for one task: its debt, its requirement, its repair route and the
trusted contracts it needs. `python -m surface law SECTION/ID` shows one declaration of the effective law.

Nothing printed is a permission. You can only submit a statement signed with your own identity; the kernel
decides. A repair that a recipe reproduces can land without a human; any other repair waits for a human's
signed review (`python -m surface review`). If Standard is unreachable or unqualified, nothing is attested
or authorized.

What you may change: code. Never `tests/` (a request's acceptance tests are its contract, measured byte for byte),
`.github/` or `standard/` (the engineers' rules, committed only as signed). Facts such as `tests`, `regressions`,
`acceptance` or production numbers are measured by the scanner; nobody else can sign them. Name what a commit is
for with a trailer: `Standard-Target:` for a repair, `Standard-Request: <id>` for a request.

The architecture, its chosen coverage and its limits are in [ARCHITECTURE.md](ARCHITECTURE.md).
