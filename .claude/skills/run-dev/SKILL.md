---
name: run-dev
description: Start the backend and the dashboard locally and verify the live feed is actually flowing. Use when asked to run the app, start the servers, demo the loop, or check that localhost works — including with real ESP hardware instead of the mock loops.
---

# Run the demo

Two processes, no database, no Docker. The whole system is in-memory
(`backend/app/state.py`), so restarting the backend resets the fleet.

## 1. Backend (port 8000)

```bash
cd backend && uv run uvicorn app.main:app --reload --port 8000
```

Mock loops are **on by default** — fake nodes heartbeat every 3s and a synthetic
deauth attack fires every 8–13s, driving the *real* orchestrator (real agent
call, real clang compile, real oracle replay). The demo works with zero hardware.

Turn mocks off per source as hardware arrives:

```bash
MOCK=0            # everything real
MOCK_HEARTBEAT=0  # real ESP heartbeats only, keep mock anomalies
MOCK_ANOMALY=0    # real /ingest anomalies only, keep mock heartbeats
```

## 2. Dashboard (port 5173)

```bash
cd dashboard && npm run dev    # http://localhost:5173
```

## 3. Verify — do not assume

```bash
curl -s localhost:8000/health          # {"status":"ok"}
curl -s localhost:8000/nodes           # nodes[] fills up after ~3s of mock heartbeats
```

For the live feed, the honest check is the browser: the timeline should scroll and
a tile should walk NORMAL → ALERT → UPDATING → PROTECTED within ~15s.

## Traps

- **The dashboard hardcodes `ws://localhost:8000/live`** unless `VITE_WS_URL` is
  set (`dashboard/src/useLive.ts:6`). Running the backend on another port gives a
  page that renders fine and shows nothing — the WS just retries every second.
  `make doctor` warns when 8000 is taken.
- **An empty grid right after boot is normal.** `anomaly_loop` sleeps 5s before
  its first attack so nodes exist on the grid first.
- **A node greys out on its own.** `OFFLINE_AFTER_S = 10.0` and `mockgen`
  randomly silences the last node ~15% of ticks. That is the offline sweeper
  working, not a bug.
- **`/ingest` returns `{"status":"accepted"}` immediately** — it fires the loop as
  a background task. Progress arrives over the WS, so a 200 says nothing about
  whether the filter passed.
- **Restart on schema-ish changes.** `--reload` handles Python edits, but the
  fleet lives in process memory: after a contract change, restart and let the
  heartbeats repopulate rather than debugging phantom nodes.
