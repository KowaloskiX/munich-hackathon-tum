# Edge enforcement demo — making "deployed" real without hardware

The backend detects an anomaly, Devin writes a C filter, and the independent
oracle verifies it on held-out captures. But an ESP32 in promiscuous mode is
**receive-only** — it can detect malicious 802.11 frames, it cannot drop frames
flowing between other devices. So the honest place to *enforce* the verified
filter is a standing process **in the traffic path**: the edge enforcement
gateway at `backend/app/edge/` (run as `app.edge.gateway`).

```
ESP fleet ──frames──▶ edge gateway (:8100) ──survivors──▶ backend (:8000)
                            │  ▲
                   drops    │  │ pulls verified filter (OTA): GET /firmware/{node}
                 malicious  │  └ reports real counts:         POST /enforcement
                  frames    └─── forwards survivors:          POST /ingest
```

The edge pulls the filter's C source, compiles it to a **native shared object**
(`clang -shared -fPIC -O2 filter.c -o filter.so`), loads it via `ctypes`
(`dlopen`), and runs every frame through the real `block_frame()`. Matched frames
are **dropped at the edge and never reach the backend** — genuine inline
enforcement (a bump-in-the-wire / IPS), where dropping is physically possible.

## Run it (three terminals)

```bash
# 1) backend
cd backend
MOCK=1 MOCK_ANOMALY=0 AGENT=stub uv run uvicorn app.main:app --host 0.0.0.0 --port 8000

# 2) edge gateway (same repo/venv; listens on :8100)
cd backend
EDGE_BACKEND_URL=http://localhost:8000 uv run uvicorn app.edge.gateway:app --host 0.0.0.0 --port 8100

# 3) dashboard
cd dashboard && npm run dev                           # http://localhost:5173
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

## Seeing that the code really runs (native, not "API play")

```bash
# What the edge logged when it deployed the filter:
#   compiled v2 for esp-01: clang -shared -fPIC -O2 filter.c -> filter.so
#   (sha 0e470bf0..., 16792 bytes native); loaded block_frame() via dlopen

curl -s localhost:8100/status | jq        # version, native so sha/bytes, evaluated/blocked/passed, the C

file backend/deployed/esp-01/filter.so    # -> "Mach-O 64-bit ... shared library"  (real machine code)
cat  backend/deployed/esp-01/filter.c     # the exact C Devin wrote, now enforced
cat  backend/deployed/esp-01/manifest.json
```

Each deploy writes a real, inspectable artifact tree under `backend/deployed/`
(gitignored): `filter.c`, the compiled `filter.so`, `v<N>/filter.c`, and a
manifest with the sha256 + byte size. That is the deployed code — compiled to a
native library and executed per frame — not a string in memory.

## Real hardware: two ESP32s + a one-key trigger

The curl above is the hardware-free stand-in. On real boards the same `/ingest`
request comes from the **sniffer bridge**, so the loop runs off actual RF:

```
esp-attacker ──ESP-NOW (marked frames)──▶ esp-sniffer-demo ──POST /ingest──▶ edge (:8100) ──▶ backend
```

- **esp-attacker** broadcasts marked synthetic ESP-NOW frames (never a real
  over-the-air deauth). Press **`T`** in its serial monitor to fire one scenario
  — it self-arms and starts in a single keypress (a second `T` stops early). The
  BOOT-hold + web `START` panel still work; `T` is just the stage shortcut.
- **esp-sniffer-demo** receives those frames, batches a capture window, and
  POSTs the exact `/ingest` JSON shape above to `BACKEND_BASE_URL`. Point that at
  the **edge** `host:8100` (default in `sniffer_config.h` / `lab_secrets.example.h`)
  so frames flow through enforcement. It also sends `/heartbeat`, which the edge
  passes straight through.

Wiring (all boards + the backend/edge host share the same `LAB_*` phone hotspot):

```bash
# flash both boards (copy lab_secrets.example.h -> lab_secrets.h and fill in first)
cd esp-attacker      && pio run -e esp32dev --target upload && pio device monitor
cd esp-sniffer-demo  && pio run -e esp32dev --target upload
```

Two-shot, exactly as the curl version:

- **Press `T` (shot 1)** → attacker floods → bridge POSTs to edge → no filter yet
  → forwarded → backend detects → Devin + oracle → `DEPLOYED`; edge poller loads
  `v2`.
- **Press `T` again (shot 2)** → same frames hit the loaded filter → edge drops
  them, reports the real block via `POST /enforcement`, backend stays quiet. The
  dashboard shows "blocked N frames at edge (filter v2)".

Start the backend and the edge with `--host 0.0.0.0` on the same LAN as the
fleet. For a direct, no-enforcement run, set `BACKEND_BASE_URL` back to `:8000`.
