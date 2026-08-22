# Autonomous Anomaly Defense

ESP32 sniffers detect network anomalies → an AI agent reads the raw capture and
**writes a C filter** → an **independent oracle** replay-tests it on held-out
captures → it deploys OTA. No human in the loop.

Full design: [ARCHITECTURE.md](ARCHITECTURE.md). Rules for humans and agents:
[AGENTS.md](AGENTS.md).

## Quickstart

```bash
make doctor    # tools, pins, ports — before anything else
make setup     # uv sync + npm install
make check     # the gate: ruff, ty, pytest, clang oracle, oxlint, tsc, vitest
```

Two processes, no database, no Docker:

```bash
cd backend && uv run uvicorn app.main:app --reload --port 8000
cd dashboard && npm run dev        # http://localhost:5173
```

Mock loops are on by default, so the full loop (real orchestrator, real clang
compile, real oracle replay) runs with **zero hardware**. A tile walks
NORMAL → ALERT → UPDATING → PROTECTED within ~15s of boot. Turn mocks off as
nodes come online: `MOCK=0`, or `MOCK_HEARTBEAT=0` / `MOCK_ANOMALY=0`.

Optional: `cp .env.example .env`, `uvx pre-commit install`.

## Layout

| Path | What |
|---|---|
| `backend/app/models.py` | the 4 frozen contracts + the WS event, as pydantic |
| `backend/app/orchestrator.py` | the state machine: trigger → agent → oracle → retry → OTA |
| `backend/app/oracle.py` | compiles the agent's C with clang, replays the fixtures |
| `backend/oracle/` | `harness.c`, sample `filters/`, held-out `fixtures/` |
| `backend/app/agent_stub.py` | stand-in for the real agent call, same contract |
| `dashboard/src/reducer.ts` | pure WS-event fold, unit-tested without React |

## What is enforced, not just described

- `make check` is the only gate, and CI runs exactly that target.
- `tests/test_contract_sync.py` parses `dashboard/src/types.ts` and fails when a
  contract drifts from `backend/app/models.py`.
- `tests/test_layering.py` fails if the agent side can reach the oracle, the
  orchestrator, or the held-out fixtures — the verification has to stay honest.
- The oracle passes a filter only at `FPR == 0` and `TPR == 1`. No threshold to
  relax (AGENTS.md rule 3).

## Agent workflows

`.claude/skills/` — `run-checks`, `run-dev`, `write-filter`, `change-contract`.
`.claude/commands/` — `/research`, `/deslop`. They encode the traps (the oracle
needs clang, the dashboard hardcodes port 8000, a contract change touches five
files) so nobody rediscovers them at 3am.
