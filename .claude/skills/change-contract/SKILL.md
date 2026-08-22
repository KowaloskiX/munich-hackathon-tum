---
name: change-contract
description: Change a frozen data contract — a pydantic model, a WS event type, a node state — across the backend, the dashboard and the mock generator. Use when adding or renaming a field, adding an EventType or NodeState, or when the contract-sync test fails.
---

# Change a contract

The 4 contracts plus the WS event live in ARCHITECTURE.md §4 and are mirrored by
hand in two languages. AGENTS.md rule 4: **do not change one side alone.** The
mirror is machine-checked, so a half-change is a red build, not a mystery at demo
time.

## Every place, in order

1. `backend/app/models.py` — the pydantic model. Categorical values are `StrEnum`,
   never bare strings (rule 7: pydantic at every boundary, no bare `dict`).
2. `dashboard/src/types.ts` — the mirror. Field names stay **snake_case** so they
   match the JSON on the wire; the parser compares them literally.
3. `backend/tests/test_contract_sync.py` — a *new* model goes in the `MIRRORED`
   map. Without that entry it is simply unchecked.
4. `backend/app/mockgen.py` — if the field or event has to appear in the demo, the
   mock has to produce it. The mock drives the same orchestrator as real hardware,
   so anything it does not emit is untested end to end.
5. `dashboard/src/reducer.ts` — a new `EventType` needs a `case` in `describe()`
   (a missing one renders the raw enum name in the timeline) and, if it is a
   pipeline step, an entry in `STAGE_BY_TYPE`.

## What the gate checks

`backend/tests/test_contract_sync.py` parses `types.ts` and compares:

- `NodeState` and `EventType` members against the TS string unions,
- the fields of every model in `MIRRORED` against the matching `export interface`,
- that `reducer.ts` handles every `EventType`.

`backend/tests/test_layering.py` additionally keeps `models.py` a leaf: everything
imports the contracts, the contracts import nothing from `app`.

## Traps

- **A field added only to `types.ts`** fails as "extra items in the right set" —
  the TS side is the right-hand side of the comparison.
- **An optional field is still a field.** `foo?: number` on the TS side counts;
  the parser strips `?`. Give the pydantic field a default instead of dropping it.
- **Renaming is two changes.** Nothing aliases; a renamed field is a new field on
  the wire and old ESP firmware keeps sending the old name.
- **`payload` stays `dict[str, Any]` / `Record<string, unknown>`** on purpose:
  `LiveEvent` is a stable envelope and per-event detail rides inside it. Adding a
  typed field to the envelope means touching all five places above — prefer the
  payload unless the dashboard needs to switch on it.

```bash
make back-test front-test    # then make check before finishing
```
