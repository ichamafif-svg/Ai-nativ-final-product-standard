# Standard rule catalog

The rules the agent codes to and Standard measures, rewritten from the
[OWASP Application Security Verification Standard 5.0](https://github.com/OWASP/ASVS) (levels 1 to 3) with the
[CWE Top 25 (2025)](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html) attached, plus run rules from the
Google SRE launch checklist.

**Licence.** This folder is an adaptation of OWASP ASVS 5.0 by the OWASP Foundation, licensed under
[CC BY-SA 4.0](LICENSE.md). The adaptation (merging, rewording, named values, examples, checks) is released under the
same licence. Standard's code that reads this folder keeps its own licence.

## Files

- `asvs.toml`: every ASVS 5.0 requirement id with its level, and the ones set aside with their reason.
- `vocabulary.toml`: what a rule's `when` and `applies` may name: features, surfaces, constructs. Instruments detect
  each one deterministically.
- `values.toml`: the named values (`@access`, `@upload_max_bytes`…) with their strict default. The human sets them in
  the rules of the game; a missing one falls back to its default, never blocks.
- `blocks.toml`: the building blocks, what each guarantees and the raw APIs it bans.
- `rules/*.toml`: the rules, one file per category.

## A rule

```toml
[[rule]]
id = "INJ-SQL"
do = "Pass every value as a bound parameter or through the ORM."      # one behaviour, an order
never = "Build SQL text from values: f-string, +, %, .format, template literal."
applies = []                    # features the product must have for the rule to apply ([] = every product)
when = ["construct:sql-call"]   # what in a change triggers it in the funnel
who = ["det"]                   # who verifies: det, ai, human (several = a mix)
block = "data"                  # the building block that absorbs it, if any
absorb = "full"                 # full | partial | none
pass = "fine"                   # funnel pass: wide | medium | fine
phase = "build"                 # build | run
values = []                     # named values it reads
wire = []                       # what pass 2 adds with the code (probe, telemetry, access row)
check = ["ban:raw-sql", "bandit:B608"]
asvs = ["1.2.4"]
cwe = ["89"]
py_ok = '''cur.execute("SELECT * FROM users WHERE id = %s", (uid,))'''
py_no = '''cur.execute(f"SELECT * FROM users WHERE id = {uid}")'''
```

The same block is what the agent reads before coding and what a refusal returns. No rule uses a vague word
(*sensitive*, *critical*, *trusted*…): each is a named value with a strict default.
