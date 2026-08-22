# AGENTS.md — rules for any agent working in this repo

This is the single source of truth for Claude Code, Devin, Cursor, Codex, and
any other coding agent. `CLAUDE.md` points here.

## The project

Autonomous anomaly-defense system. ESP32 sniffers detect network/signal
anomalies → an AI agent reads the raw capture and **writes a C filter** → an
**independent oracle** replay-tests it on held-out captures → it deploys OTA.
No human in the loop. Full design in [ARCHITECTURE.md](ARCHITECTURE.md).

Layout: `backend/` (FastAPI spine + orchestrator + oracle), `dashboard/`
(React/Vite live view), `backend/oracle/` (C harness + filters + fixtures).

## Local CI — NON-NEGOTIABLE

**Before finishing any task or committing, run `make check` and make it green.
Do not hand back red.** `make check` runs: ruff (lint+format), ty (types),
pytest, the C oracle build, oxlint, tsc, and vitest.

Scoped commands while iterating:
- Backend Python edited → `make back-lint back-types back-test`
- Dashboard edited → `make front-lint front-types front-test`
- A filter or the oracle harness edited → `make oracle-build`
- Auto-fix formatting/lint → `make fix`

First time on a machine → `make setup` (uv sync + npm install).

## Rules

1. **Green before done.** No task is complete while `make check` is red.
2. **New behavior ships with a test** in the same change. A bug fix starts with
   a regression test that fails first.
3. **Never weaken a check to make it pass.** No blanket `# type: ignore`, no
   `oxlint-disable`, no deleting assertions, no loosening the oracle threshold.
   Fix the cause or stop and ask.
4. **Contracts are frozen.** The 4 data contracts + the WS event schema live in
   [ARCHITECTURE.md](ARCHITECTURE.md) §4 and are mirrored in
   `backend/app/models.py` and `dashboard/src/types.ts`. Do not change a
   contract without updating **both sides + the mock generator** in one change.
5. **The oracle is authoritative.** Verification runs on the backend against
   held-out fixtures the agent never sees. Never let a component self-report a
   pass. `backend/app/oracle.py` compiles the filter with `clang` and replays
   `backend/oracle/fixtures/`.
6. **Autonomy is the point.** Never insert a human approval step between the
   agent and OTA deploy. That turns the layer back into a copilot.

## Running it

- Backend: `cd backend && uv run uvicorn app.main:app --reload --port 8000`
  (mock loops on by default; `MOCK=0` for all-real, `MOCK_HEARTBEAT=0` /
  `MOCK_ANOMALY=0` for partial integration).
- Dashboard: `cd dashboard && npm run dev` → http://localhost:5173
