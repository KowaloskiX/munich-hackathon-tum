# Autonomous Anomaly Defense

ESP32 sniffers detect network anomalies, while the backend analyzes and verifies
candidate defenses. A separate Waveshare ESP32-S3 terminal presents the
authoritative aggregate state as `BEZPIECZNIE`, `ATAK` or `BRAK DANYCH`.

Full design: [ARCHITECTURE.md](ARCHITECTURE.md). Rules for humans and agents:
[AGENTS.md](AGENTS.md). ESP-specific validation is documented in
[docs/ESP_ARCHITECTURE_REVIEW.md](docs/ESP_ARCHITECTURE_REVIEW.md).
Gmail + Devin setup is documented in [docs/GMAIL_SETUP.md](docs/GMAIL_SETUP.md).

A controlled lab anomaly generator lives in
[esp-attacker/README.md](esp-attacker/README.md); its hardware demo runbook is
[ESP_DEMO.md](ESP_DEMO.md).

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

## ESP32-S3 display

The supported display target is the Waveshare ESP32-S3-Touch-LCD-1.28 with its
round 240×240 GC9A01A panel and CST816S touch controller. See the
[firmware README](firmware/esp32-display/README.md) for wiring, configuration,
the `/v1/hmi/status` contract and flashing instructions.

To flash the clearly marked standalone demo without a backend:

```bash
pio run -d firmware/esp32-display \
  -e waveshare-s3-touch-lcd-1_28-demo -t upload
```

The demo alternates between `BEZPIECZNIE` and `ATAK` every 8 seconds. It is not
a real security signal.

## Layout

| Path | What |
|---|---|
| `backend/app/models.py` | the frozen backend contracts + the WS event, as pydantic |
| `backend/app/orchestrator.py` | the backend state machine |
| `backend/app/oracle.py` | compiles and replay-tests candidate filters |
| `backend/oracle/` | `harness.c`, sample `filters/`, held-out `fixtures/` |
| `backend/app/agent_stub.py` | stand-in for the real agent call, same contract |
| `dashboard/src/reducer.ts` | pure WS-event fold, unit-tested without React |
| `firmware/esp32-display/` | fail-safe ESP32-S3 status terminal and host tests |
| `esp-attacker/` | bounded synthetic anomaly generator for the live demo |

## What is enforced, not just described

- `make check` is the backend/dashboard gate, and CI runs exactly that target.
- The display has a separate CI workflow for native state tests and both
  Waveshare firmware builds.
- `tests/test_contract_sync.py` parses `dashboard/src/types.ts` and fails when a
  backend contract drifts from `backend/app/models.py`.
- `tests/test_layering.py` fails if the agent side can reach the oracle, the
  orchestrator, or the held-out fixtures — the verification has to stay honest.
- The oracle passes a filter only at `FPR == 0` and `TPR == 1`. No threshold to
  relax (AGENTS.md rule 3).

## Agent workflows

`.claude/skills/` — `run-checks`, `run-dev`, `write-filter`, `change-contract`.
`.claude/commands/` — `/research`, `/deslop`. They encode the traps (the oracle
needs clang, the dashboard hardcodes port 8000, a contract change touches five
files) so nobody rediscovers them at 3am.
