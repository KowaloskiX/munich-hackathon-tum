---
description: Document how a part of this system works today, with file and line references. Use for "how does X work", "where is Y handled", or before changing an area you have not touched.
argument-hint: [question, e.g. "how does a failed verification retry"]
---

# Research

$ARGUMENTS

Your only job is to **document what exists**. Not to improve it.

- Do NOT suggest changes, refactors or future enhancements unless explicitly asked.
- Do NOT critique the implementation.
- Describe what exists, where it lives, how it works, and how the pieces connect.

## Process

1. Read any file the question names — fully, no offset tricks. Nothing here is
   long: `backend/app/` is under 600 lines total.
2. Follow the loop rather than grepping blindly. The system has one spine:
   `main.py` (HTTP/WS edge) → `orchestrator.py` (the state machine) →
   `agent_stub.py` (filter author) → `oracle.py` → `oracle/harness.c`, with
   `models.py` as the contract leaf and `state.py` holding all mutable state.
   On the dashboard: `useLive.ts` → `reducer.ts` → `App.tsx`.
3. Check ARCHITECTURE.md §3 (the intended sequence) and §4 (the frozen
   contracts) before assuming — the code is meant to match them.
4. Read the tests. `test_orchestrator.py` documents the retry path,
   `test_oracle.py` the pass/fail boundary, `test_layering.py` and
   `test_contract_sync.py` the rules that are mechanically enforced.

## Output

```markdown
# Research: [topic]

**Commit**: [hash]  **Branch**: [name]

## Question
[verbatim]

## Summary
[the answer in a few sentences]

## How it works
- [step, with `path/to/file.py:123`]

## What is enforced vs. described
[which rules are checked by a test or a Makefile target, and which are only prose]

## Open questions
[what remains unclear — say so rather than guessing]
```

Prefer concrete `file:line` references over prose. If something is genuinely
undocumented and unclear from the code, say that instead of inventing an
explanation.
