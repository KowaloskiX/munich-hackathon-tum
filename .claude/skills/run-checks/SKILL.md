---
name: run-checks
description: Run every quality gate the way CI does, across all three toolchains (Python, TypeScript, C). Use before finishing a task, before committing, when the user asks whether everything passes, or to reproduce a CI failure locally.
---

# Run every gate

There is exactly one gate and it is a Makefile target:

```bash
make check
```

It runs, in order: ruff (lint + format check), ty, pytest, the C oracle build,
oxlint, tsc, vitest. CI runs the same target — there is no second list to drift
against. **Do not hand back a red `make check`** (AGENTS.md rule 1).

## While iterating

Run the narrow target, then `make check` once at the end.

| Edited | Command |
|---|---|
| `backend/app/**`, `backend/tests/**` | `make back-lint back-types back-test` |
| `dashboard/src/**` | `make front-lint front-types front-test` |
| `backend/oracle/**` (harness or a filter) | `make oracle-build` |
| a contract (`models.py` / `types.ts`) | `make back-test front-test` — see the `change-contract` skill |

Formatting and trivial lint: `make fix` (ruff format + ruff --fix + oxlint --fix).

## First time on a machine

```bash
make doctor    # tools, .nvmrc pin, ports 8000/5173 — before anything else
make setup     # uv sync + npm install
```

`make check` fails confusingly when `dashboard/node_modules` is missing, so run
`make setup` first on a fresh clone.

## Traps

- **`ty check` covers `app` only.** `make back-types` runs `uv run ty check app` —
  nothing type-checks `backend/tests/`. A broken annotation in a test surfaces as
  a pytest error, not a type error.
- **`make oracle-build` needs clang** and compiles with `-Wall -Werror -std=c11`.
  A *warning* in a filter is a build failure. `make doctor` tells you if clang is
  absent; without it the oracle silently verifies nothing.
- **`npm run test` is `vitest run`**, not watch mode. It exits.
- **`make fix` ends with `|| true`** for the dashboard, so a lint error it cannot
  auto-fix does not stop it. Read the output; do not assume fix means clean.
- **Never weaken a check to make it pass** (AGENTS.md rule 3): no blanket
  `# type: ignore`, no `oxlint-disable`, no deleted assertion, no lowered oracle
  threshold. Fix the cause or stop and ask.
