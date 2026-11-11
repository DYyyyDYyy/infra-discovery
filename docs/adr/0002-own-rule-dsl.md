# 2. A small rule DSL instead of Python plugins

**Status:** accepted

**Context.** Recognising software is mostly "if this output matches, pull these values out", with a
fallback per distro. BMC solves this with TPL patterns written by content teams, not developers.

**Decision.** A Lark grammar with four statements: `kind`, `when ... matches`, `extract ... regex`,
`set`. Rules are validated at load time (unknown source, bad regex, missing group, missing name,
duplicates) with `file:line:col` errors. Python stays for structured parsing (`ps`, `ss`).

**Consequences.** Rules are short, safe to load (no code execution) and testable one by one on fixtures.
The language is deliberately weak: no loops, no cross-rule references. A hypothesis property test
guards the parser (round trip, never crashes on arbitrary input).
