# Agents

From the repository root, run `python -m surface tasks` to see the work the law asks for, then
`python -m surface context TASK_ID` for one task: its debt, its requirement, its repair route and the
trusted contracts it needs. `python -m surface law SECTION/ID` shows one declaration of the effective law.

Nothing printed is a permission. You can only submit a statement signed with your own identity; the kernel
decides. A repair that a recipe reproduces can land without a human; any other repair waits for a human's
signed review (`python -m surface review`). If Standard is unreachable or unqualified, nothing is attested
or authorized.

The architecture, its chosen coverage and its limits are in [ARCHITECTURE.md](ARCHITECTURE.md).
