# Standard product requirement catalog

The rules the agent codes to and Standard measures, rewritten from the
[OWASP Application Security Verification Standard 5.0](https://github.com/OWASP/ASVS) (levels 1 to 3) with the
[CWE Top 25 (2025)](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html) attached, plus run rules from the
Google SRE launch checklist.

**Licence.** This folder is an adaptation of OWASP ASVS 5.0 by the OWASP Foundation, licensed under
[CC BY-SA 4.0](LICENSE.md). The adaptation (merging, rewording, named values, examples, checks) is released under the
same licence. Standard's code that reads this folder keeps its own licence.

The catalog is the common definition, pinned with the release. The effective law combines its compiled socle
with the human's signed choices. K and BT retain admission and enforcement; a catalog contract is no measurement.
Execution settings such as providers, research budgets and patrol schedules stay in operator configuration.

## Files

- `maintenance.toml`: target declarations compiled into law, plus instructions for their repair. The category
  template expands deterministically from the technical rules; work instructions never enter the kernel language.
- `policy.toml`: signed policy parameter types, editor bounds, floor and recommended values, and editor presentation.
  The law compiler, editor and interface read these same definitions. The two judges enforce route thresholds.
- `rules/*.toml`: technical requirements, applicability, block responsibility, required wiring and verification.
- `values.toml`: named technical parameters and strict defaults. Signed client choices override defaults; a parameter
  without a default remains explicitly missing until supplied. Agent proposals never activate these choices.
- `blocks.toml`: minimum implementation contracts, stack APIs, prohibited bypasses and probes.
- `vocabulary.toml`: product features, changed surfaces and constructs used for selection.
- `asvs.toml`: ASVS requirement ids and levels, including explicit reasons for those set aside.

`targets()` and `policy_values()` compile release law data. `definition()` links an effective target to the release
requirements without inventing a mapping for an unknown client target. `select()` chooses triggered requirements;
`contracts()` joins their exact parameters, blocks and checks, with optional category/verifier attention and the
mission's required rule ids. `render_contracts()` serves humans and model missions. `declared_features()` derives
features from signed settings and `@high_value` identically for scanner inputs and model context.
The scanner receives inert catalog data and evaluates observations independently. Code discovery remains in U;
no catalog function imports an instrument or an agent. Missing implementation or measurement remains visible.

## A rule

```toml
[[rule]]
id = "INJ-SQL"
do = "Pass every value as a bound parameter or through the ORM."      # one behaviour, an order
never = "Build SQL text from values: f-string, +, %, .format, template literal."
applies = []                    # features the product must have for the rule to apply ([] = every product)
when = ["construct:sql-call"]   # what in a change triggers this requirement
who = ["det"]                   # who verifies: det, ai, human (several = a mix)
block = "data"                  # the building block that absorbs it, if any
absorb = "full"                 # full | partial | none
phase = "build"                 # build | run
values = []                     # named values it reads
wire = []                       # what the code must wire (probe, telemetry, access row)
check = ["blocks", "bandit:B608"]
asvs = ["1.2.4"]
cwe = ["89"]
py_ok = '''cur.execute("SELECT * FROM users WHERE id = %s", (uid,))'''
py_no = '''cur.execute(f"SELECT * FROM users WHERE id = {uid}")'''
```

The same block is what the agent reads before coding and what a refusal returns. No rule uses a vague word
(*sensitive*, *critical*, *trusted*…): each is a named value with a strict default.

Selection depends on applicability and touched surfaces, without a pass hierarchy. A repair also receives its
own category's applicable requirements. Selection is repeated on the candidate, including newly introduced features.
One constructor writes; correctness and simplicity readers share the exact immutable candidate with separate
read/search dialogues. Every revision is reviewed again. Their opinions remain proposals.

Block absorption (`full`, `partial`, `none`) is a specification of responsibility, not evidence. Static presence,
resolved wiring, runtime probes and complete execution-path coverage are distinct. A simplification must preserve
the minimum block guarantees and the requirement's residual obligations.
