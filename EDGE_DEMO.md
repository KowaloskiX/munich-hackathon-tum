# Edge enforcement demo — making "deployed" real without hardware

The backend detects an anomaly, Devin writes a C filter, and the independent
oracle verifies it on held-out captures. But an ESP32 in promiscuous mode is
**receive-only** — it can detect malicious 802.11 frames, it cannot drop frames
flowing between other devices. So the honest place to *enforce* the verified
filter is a standing process **in the traffic path**: the
[`sentinel-edge`](https://github.com/PTQ-22/sentinel-edge) gateway (separate repo).

```
ESP fleet ──frames──▶ sentinel-edge (:8100) ──survivors──▶ backend (:8000)
                            │  ▲
                   drops    │  │ pulls verified filter (OTA): GET /firmware/{node}
                 malicious  │  └ reports real counts:         POST /enforcement
                  frames    └─── forwards survivors:          POST /ingest
```

Frames the compiled filter matches are **dropped at the edge and never reach the
backend**. This is genuine inline enforcement (a bump-in-the-wire / IPS), done in
software where dropping is physically possible.

## Run it (three terminals)

```bash
# 1) backend
cd backend
MOCK=1 MOCK_ANOMALY=0 AGENT=stub uv run uvicorn app.main:app --host 0.0.0.0 --port 8000

# 2) edge gateway (separate repo: sentinel-edge)
cd ../sentinel-edge
BACKEND_URL=http://localhost:8000 make run          # listens on :8100

# 3) dashboard
cd ../dashboard && npm run dev                        # http://localhost:5173
```

## Two-shot demo (the payoff)

```bash
ATTACK='{"node_id":"esp-01","timestamp":0,
  "frame_hex":["c0003a01ffffffffffff001122334455001122334455",
               "a0003a01aabbccddeeff001122334455001122334455",
               "8000000000ffffffffffffaabbccddeeffaabbccddeeffc0006400"],
  "anomaly_stats":{"subtype":12,"count_in_window":400}}'

# Shot 1 — no filter yet: edge forwards all 3 → backend detects → Devin+oracle → DEPLOYED
curl -sX POST localhost:8100/ingest -H 'content-type: application/json' -d "$ATTACK"
#   edge log: "esp-01 v=-: in 3 forwarded 3 dropped 0"
#   then:     "loaded v2 for esp-01 (deauth_flood)"

# Shot 2 — same attack: edge DROPS the 2 mgmt frames and enforces silently
curl -sX POST localhost:8100/ingest -H 'content-type: application/json' -d "$ATTACK"
#   edge log: "esp-01 v=v2: in 3 forwarded 0 dropped 2"
```

The attack is now handled by the deployed filter, so the edge drops it and does
**not** wake the backend (no spurious new incident). Instead it reports the real
drop via `POST /enforcement`, which the backend records against the original
incident and streams as an **edge-sourced** `FRAME_BLOCKED` — the dashboard shows
"blocked 2 frames at edge (filter v2)", and `GET /incidents/{id}/report.md` shows
the enforcement counts under *Enforcement (in-path, sentinel-edge)*.

Enforcement is the edge's job alone: the backend detects + publishes the filter
and never fabricates a blocked count.

## Pointing the real sniffer at the edge

No firmware code change — only the backend URL. In
`esp-sniffer-demo/include/lab_secrets.h`, set `BACKEND_BASE_URL` to the edge's
`host:8100` instead of the backend's `:8000`. The edge filters `/ingest` and
passes `/heartbeat` straight through, so everything the sniffer sends still
works. Start the backend and the edge on the same LAN as the fleet.
