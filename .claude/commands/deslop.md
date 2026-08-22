---
description: Remove AI-generated slop from recent changes — redundant comments, defensive code that does not match the area, casts that dodge the type system. Use after a large generated change or before committing.
argument-hint: [scope, e.g. "the last commit" or a path]
---

# Deslop

$ARGUMENTS — if no scope is given, review the working tree plus the last commit.

Remove what a careful author of *this* codebase would not have written. The
house style here is dense: a short module with a docstring that explains why it
exists, and comments reserved for traps and rationale.

- **Comments that restate the code.** A comment here earns its place by
  explaining *why*, recording a measurement, or naming a trap. `# increment the
  counter` does not. `/* only management frames */` next to a bit mask does.
- **Defensive code that does not match the area.** A `try/except` around a call
  that cannot fail, a null check on something the type system guarantees. The
  boundary is already validated by pydantic — inside, trust the types.
- **Casts and suppressions that dodge the type system**: `# type: ignore`,
  `as any`, `oxlint-disable`. AGENTS.md rule 3 forbids these outright; each one
  is either a real false positive with a written justification, or a bug.
- **Bare strings for categorical values.** Status, event type, node state → a
  `StrEnum` in `models.py` and a literal union in `types.ts`, never a loose
  string.
- **A `dict` crossing a boundary.** Rule 7: every payload on an HTTP body, a WS
  message, agent I/O or oracle I/O is a pydantic model. An ad-hoc dict is slop
  even when it works.
- **Dead code and commented-out blocks.** Git remembers them.
- **Style inconsistent with the file.** Match the surrounding comment density,
  naming and idiom rather than importing a different house style.

Do not remove:

- comments recording a measurement, a defect, a hardware quirk or a deliberate
  trade-off — those are the ones worth keeping,
- the deliberately-wrong first attempt in `agent_stub.py` (it exercises the
  fail → retry → pass path in every demo run),
- tests that look redundant but are negative controls (`test_oracle.py` proves an
  over-broad filter and a non-compiling filter both fail).

Afterwards run `make check` and report in one to three sentences what you removed.
