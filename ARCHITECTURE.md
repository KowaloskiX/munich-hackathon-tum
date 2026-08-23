# Autonomous Anomaly Defense — Architecture

> **One-liner:** Cheap ESP32 sniffers watch an industrial network for anomalies. When something unknown appears, the raw capture goes to an AI agent that identifies the attack and *writes a C filter*. A replay test proves the filter works (catches the attack, blocks nothing legit), and only then is it pushed OTA to the fleet. No human in the loop.

> **The thesis:** *Give the industry an engineer.* The agent isn't a copilot suggesting fixes — it's an autonomous layer that detects → analyzes → writes code → verifies → deploys.

Deauth is just the first example. The system is built to generalize to **any radio/bus anomaly** (deauth, disassoc, beacon flood, auth flood, Modbus injection, rogue BLE…).

---

## 1. Why this wins

Three things judges reward, and this design has all three *naturally* (not bolted on):

| Criterion | How we hit it |
|---|---|
| **Autonomy** (a layer, not a copilot) | Full loop with zero human approval: trigger → agent → verify → OTA |
| **Verification** (a hard oracle) | Replay test: attack pcap (must catch ~100%) + benign pcap (must block 0). Machine-scored in seconds. |
| **Clarity** (if we can't follow it, we can't credit it) | The **dashboard** visualizes the whole loop live. This is the money shot. |

**The oracle is the core.** Attack = data (hex frames). Defense = code (a C predicate over frame bytes). Verification = replay both labeled sets and count TPR/FPR. That's the `write → run → test → fix` loop, applied to network security.

```mermaid
mindmap
  root((Autonomous<br/>Defense))
    Detect
      ESP32 promiscuous sniff
      statistical anomaly
      raw hex to backend
    Analyze
      agent reads hex
      classifies attack
      writes C filter
    Verify
      replay attack pcap
      replay benign pcap
      TPR / FPR oracle
    Deploy
      compile firmware
      OTA to fleet
    Observe
      dashboard live loop
      node map
      blocked counter
```

---

## 2. System architecture (high level)

```mermaid
flowchart LR
    subgraph EDGE["🛰️ Edge — ESP32 fleet"]
        S1["ESP Sniffer #1<br/>promiscuous 2.4GHz"]
        S2["ESP Sniffer #2"]
        S3["ESP Sniffer #N"]
        HMI["ESP + Screen<br/>SOC alarm terminal"]
    end

    subgraph SPINE["🧠 Backend / Orchestrator (Python/FastAPI)"]
        ING["/ingest<br/>anomaly intake"]
        HB["/heartbeat<br/>liveness"]
        ORCH["Orchestrator<br/>state machine"]
        FW["/firmware<br/>OTA server"]
        WS["WebSocket /live<br/>event bus"]
    end

    subgraph AI["🤖 AI modules"]
        AGENT["Agent module<br/>hex → attack_class + C filter"]
        VERIFY["Verify module (oracle)<br/>replay test → TPR/FPR"]
    end

    subgraph WEB["📊 Dashboard (React)"]
        MAP["Node map/grid"]
        TL["Live timeline"]
        OPS["Ops counters"]
        PIPE["Loop animation"]
    end

    S1 & S2 & S3 -->|POST anomaly hex| ING
    S1 & S2 & S3 -->|POST every 2-5s| HB
    ING --> ORCH
    HB --> ORCH
    ORCH -->|"1. analyze"| AGENT
    AGENT -->|filter_c_code| ORCH
    ORCH -->|"2. verify"| VERIFY
    VERIFY -->|pass/fail + log| ORCH
    ORCH -->|"3. on FAIL: iterate"| AGENT
    ORCH -->|"4. on PASS: publish"| FW
    FW -.->|OTA update| S1 & S2 & S3
    ORCH -->|events| WS
    WS --> MAP & TL & OPS & PIPE
    ORCH -.->|alerts| HMI

    style SPINE fill:#1e2a3a,stroke:#4a90d9,color:#fff
    style AI fill:#2a1e3a,stroke:#9d4ad9,color:#fff
    style WEB fill:#1e3a2a,stroke:#4ad98a,color:#fff
```

**Your ownership = the SPINE + WEB.** AI team gives you two black-box functions with fixed contracts. Hardware gives you devices that POST to your endpoints and accept OTA. You wire it all together and make it visible.

---

## 3. The autonomous loop (the whole demo)

```mermaid
sequenceDiagram
    autonumber
    participant ESP as ESP Sniffer
    participant BE as Backend/Orchestrator
    participant AG as Agent (Devin/LLM)
    participant OR as Oracle (replay test)
    participant FW as OTA server
    participant DASH as Dashboard

    ESP->>BE: anomaly {node_id, frame_hex[], stats}
    BE->>DASH: event: ANOMALY_DETECTED (node red)
    BE->>AG: analyze(hex, context)
    BE->>DASH: event: AGENT_ANALYZING
    AG-->>BE: {attack_class, confidence, filter_c_code, explanation}
    BE->>DASH: event: FILTER_GENERATED (show class + code)

    loop until PASS or max retries
        BE->>OR: verify(filter_c_code)
        BE->>DASH: event: VERIFYING
        OR-->>BE: {passed, tpr, fpr, tests_passed/total, log}
        alt FAIL
            BE->>DASH: event: VERIFY_FAILED (x/8)
            BE->>AG: refine(filter, failure_log)
            AG-->>BE: new filter_c_code
        else PASS
            BE->>DASH: event: VERIFY_PASSED (8/8 ✓)
        end
    end

    BE->>FW: publish firmware(filter)
    BE->>DASH: event: OTA_DEPLOYING
    FW-->>ESP: OTA update
    ESP-->>BE: heartbeat {state: PROTECTED}
    BE->>DASH: event: DEPLOYED (blocked counter climbs)
```

**Critical:** no human between AG and FW. A human clicking "approve" = you lose on *"copilot, not a layer."*

---

## 4. Data contracts — FREEZE THESE IN HOUR 1

This is the single most important thing. Agree these 4 schemas before anyone writes code. Then everyone builds against mocks and nobody blocks anyone.

```mermaid
flowchart TD
    A["Contract 1<br/>ESP → /ingest<br/>(anomaly)"]
    B["Contract 2<br/>ESP → /heartbeat<br/>(liveness)"]
    C["Contract 3<br/>Backend ↔ Agent"]
    D["Contract 4<br/>Backend ↔ Oracle"]

    A --> BE["Backend<br/>(you)"]
    B --> BE
    BE <--> C
    BE <--> D
    BE --> WSX["WebSocket event schema<br/>(you own, drives dashboard)"]

    style BE fill:#1e2a3a,stroke:#4a90d9,color:#fff
    style WSX fill:#1e3a2a,stroke:#4ad98a,color:#fff
```

### Contract 1 — ESP → `/ingest` (anomaly)
```json
{
  "node_id": "esp-03",
  "timestamp": 1690000000.123,
  "frame_hex": ["c0003a01ffffffff...", "..."],
  "rssi": -52,
  "bssid": "34:fa:9f:5d:24:a9",
  "sender_mac": "02:00:00:00:00:01",
  "anomaly_stats": { "frame_type": "mgmt", "subtype": 12, "channel": 11, "count_in_window": 240, "window_ms": 1000 },
  "guessed_type": null
}
```

### Contract 2 — ESP → `/heartbeat` (every 2–5s)
```json
{ "node_id": "esp-03", "timestamp": 1690000000.0, "state": "NORMAL", "stats": { "frames_seen": 10432, "blocked": 0, "fw_version": "v1" } }
```
`state ∈ { NORMAL, ALERT, PROTECTED, UPDATING, OFFLINE }`

### Contract 3 — Backend ↔ Agent
```json
// in:
{ "frame_hex": ["..."], "anomaly_stats": {}, "prev_filter": null, "failure_log": null }
// out:
{ "attack_class": "deauth_flood", "confidence": 0.94,
  "filter_c_code": "bool block_frame(const uint8_t* f, size_t n){ ... }",
  "explanation": "802.11 mgmt subtype 12 flood ..." }
```

### Contract 4 — Backend ↔ Oracle
```json
// in:
{ "filter_c_code": "bool block_frame(...)" }
// out:
{ "passed": true, "tpr": 1.0, "fpr": 0.0, "tests_total": 8, "tests_passed": 8, "log": "..." }
```

### WebSocket `/live` event (you own this — it drives the dashboard)
```json
{ "type": "VERIFY_PASSED", "node_id": "esp-03", "ts": 1690000000.5,
  "payload": { "tpr": 1.0, "fpr": 0.0, "tests": "8/8", "attack_class": "deauth_flood" } }
```
Event types: `NODE_UP, NODE_DOWN, ANOMALY_DETECTED, AGENT_ANALYZING, FILTER_GENERATED, VERIFYING, VERIFY_FAILED, VERIFY_PASSED, OTA_DEPLOYING, DEPLOYED, FRAME_BLOCKED`.

---

### Contract 5 — Gmail threat review

Email security is isolated from the frozen ESP event stream. Gmail emits mailbox history IDs through
Cloud Pub/Sub; the backend resolves added messages, persists a durable analysis record, and emits a
dedicated `/v1/email/live` event.

```json
{
  "type": "EMAIL_FLAGGED",
  "analysis_id": 42,
  "ts": 1690000000.5,
  "message": "Potential credential phishing requires review"
}
```

Analysis state: `QUEUED → ANALYZING → CLEAR | PENDING_REVIEW | FAILED → REVIEWED`.
Agent verdict: `CLEAR | FLAGGED | INCONCLUSIVE`. `FLAGGED` and `INCONCLUSIVE` require a human
decision; no email is deleted, moved, or reported as Spam automatically.

`GET /v1/email/messages?limit=50&page_token=...` browses Gmail history in 1–50 message pages and
returns `next_page_token`, independently of the automatic monitoring mode. `POST /v1/email/import`
accepts either selected Gmail IDs as
`{ "message_ids": ["abc"], "limit": null }` or a no-preview quick import as
`{ "message_ids": [], "limit": 10 }`. It returns
`{ "scanned": 1, "imported": 1, "duplicates": 0 }`. Imported Gmail message IDs use the same
durable deduplication and analysis queue as push events; quick import skips full Gmail downloads
for IDs already present in the queue.

```mermaid
flowchart LR
    GM["Gmail users.watch"] --> PS["Pub/Sub pull"]
    PS --> HS["history.list + dedupe"]
    HS --> DB["encrypted SQLite queue"]
    DB --> DV["Devin triage / investigation"]
    DV --> ER["evidence report"]
    ER --> UI["human review"]
    UI --> GL["Sentinel Gmail labels"]
```

---

## 5. Backend — build order (so you never block on the team)

```mermaid
flowchart LR
    M1["1. FastAPI skeleton<br/>+ in-memory state<br/>+ MOCK event generator"] --> M2["2. Dashboard on mock<br/>3 panels live"]
    M2 --> M3["3. Loop animation<br/>(if time)"]
    M3 --> M4["4. Swap mock → real<br/>plug real events,<br/>dashboard unchanged"]

    style M1 fill:#3a2a1e,stroke:#d9904a,color:#fff
    style M4 fill:#1e3a2a,stroke:#4ad98a,color:#fff
```

**Key trick:** a fake-event generator emits synthetic loop events every few seconds (`NODE_UP → ANOMALY → ANALYZING → 8/8 → DEPLOYED`). This runs your entire dashboard *before ESP or agent exist*. At the end you swap the source; the dashboard never changes.

### Orchestrator state machine (per anomaly)
```mermaid
stateDiagram-v2
    [*] --> IDLE
    IDLE --> ANALYZING: anomaly received
    ANALYZING --> VERIFYING: filter returned
    VERIFYING --> DEPLOYING: PASS
    VERIFYING --> ANALYZING: FAIL (retry, n<max)
    VERIFYING --> ESCALATED: FAIL (n≥max)
    DEPLOYING --> PROTECTED: OTA ack
    PROTECTED --> [*]
    ESCALATED --> [*]
```

### ESP node liveness (dashboard tile color)
```mermaid
stateDiagram-v2
    [*] --> NORMAL
    NORMAL --> ALERT: anomaly seen
    ALERT --> UPDATING: OTA push
    UPDATING --> PROTECTED: applied
    PROTECTED --> NORMAL: window clear
    NORMAL --> OFFLINE: no heartbeat > 10s
    ALERT --> OFFLINE: no heartbeat > 10s
    OFFLINE --> NORMAL: heartbeat resumes
```

### Endpoints
| Method | Path | Purpose |
|---|---|---|
| POST | `/ingest` | anomaly intake (Contract 1) |
| POST | `/heartbeat` | node liveness (Contract 2) |
| GET | `/firmware/{node_id}` | OTA fetch latest firmware |
| GET | `/nodes` | current fleet snapshot (dashboard bootstrap) |
| WS | `/live` | event stream to dashboard |

---

## 6. Dashboard — the money shot

Three panels + one animation. Built on mock data from hour 1.

```mermaid
flowchart TB
    subgraph DASH["Dashboard layout"]
        direction TB
        subgraph TOP["Top — Ops counters"]
            C1["Active nodes"]
            C2["Threats detected"]
            C3["Filters deployed"]
            C4["Frames blocked ▲"]
        end
        subgraph MID["Middle"]
            GRID["Node map/grid<br/>tiles: green/red/gray<br/>label · last seen · state"]
            PIPE["Loop pipeline animation<br/>trigger→agent→verify→OTA<br/>lights up step by step"]
        end
        subgraph BOT["Bottom — Live timeline"]
            FEED["⚠ esp-03 anomaly → agent analyzing →<br/>filter generated (deauth_flood) →<br/>tests 8/8 ✓ → OTA deployed"]
        end
    end

    style PIPE fill:#2a1e3a,stroke:#9d4ad9,color:#fff
    style FEED fill:#1e3a2a,stroke:#4ad98a,color:#fff
    style C4 fill:#3a1e1e,stroke:#d94a4a,color:#fff
```

- **Node grid** — one tile per ESP. Color by heartbeat state. Red when under attack. This proves "fleet."
- **Live timeline** — the loop as a scrolling feed. *This is the visualization of autonomy + verification.*
- **Ops counters** — active nodes, threats, filters deployed, blocked frames (a climbing counter reads as "working right now").
- **Loop animation** — pipeline `trigger → agent → verify → OTA` lighting up in sequence. Highest stage ROI if time allows.

---

## 7. Work split (5 people, ~19h)

```mermaid
flowchart TB
    subgraph YOU["YOU — Spine"]
        Y["Backend + orchestrator<br/>+ dashboard + final integration<br/>+ OWN the data contracts"]
    end
    subgraph HW["Hardware A"]
        HA["Sniffer firmware<br/>promiscuous capture<br/>anomaly stats → /ingest<br/>+ heartbeat"]
    end
    subgraph HW2["Hardware B"]
        HB2["OTA pipeline (fetch/apply)<br/>+ test attacks IN ISOLATION<br/>+ real pcaps for oracle"]
    end
    subgraph AI1["AI A"]
        AA["Agent module<br/>Devin/LLM integration<br/>hex → JSON (Contract 3)"]
    end
    subgraph AI2["AI B"]
        AB["Oracle module<br/>compile C on host<br/>replay pcaps → TPR/FPR<br/>(Contract 4)"]
    end

    Y -.contracts.-> HA & HB2 & AA & AB
    HA -->|real anomaly| Y
    AA -->|real filter| Y
    AB -->|real pass/fail| Y
    HB2 -->|OTA + pcaps| Y

    style YOU fill:#1e2a3a,stroke:#4a90d9,color:#fff
```

Everyone builds a **vertical slice on mocks**; integrate at the end. Your second job (besides code) = enforce the contracts.

---

## 8. Timeline

```mermaid
gantt
    title 19h plan (rough)
    dateFormat HH
    axisFormat %Hh
    section All
    Contracts + stack + repo (NO SKIP)   :done, c1, 00, 1h
    section Parallel (on mocks)
    Backend + dashboard on fake data      :active, b1, 01, 7h
    Sniffer capture (verify FIRST night)  :h1, 01, 7h
    Agent module vs contract              :a1, 01, 7h
    Oracle module standalone              :o1, 01, 7h
    section Integrate
    ESP→backend (heartbeat visible)       :i1, 08, 2h
    + agent                               :i2, 10, 1h
    + oracle                              :i3, 11, 1h
    + OTA                                 :i4, 12, 1h
    section Demo-harden
    Full loop end-to-end once             :d1, 13, 2h
    2nd unknown attack live               :d2, 15, 1h
    Dashboard polish                      :d3, 16, 1h
    section Pitch
    Dry run + buffer                      :p1, 17, 2h
```

---

## 9. Scope discipline — cut lines

```mermaid
flowchart TD
    MUST["MUST-HAVE = whole demo<br/>1 full loop on 1 board, visible on dashboard<br/>+ 2nd unknown attack live"]
    STRETCH["STRETCH<br/>fleet of N · pretty UI · more attack types · ESP-NOW"]

    MUST -->|if time| STRETCH

    CUT["IF TIME RUNS OUT — cut these"]
    C_OTA["OTA → 1 board only (not fleet)"]
    C_TYPES["Attack types → 2"]
    NEVER["NEVER CUT<br/>❌ verification loop<br/>❌ autonomy (no human approve)"]

    CUT --> C_OTA & C_TYPES
    CUT -.-> NEVER

    style MUST fill:#1e3a2a,stroke:#4ad98a,color:#fff
    style NEVER fill:#3a1e1e,stroke:#d94a4a,color:#fff
```

The **generalization proof** kills the "wired to one prepared example" objection: train/demo on deauth, then fire a *different* attack (beacon flood / disassoc) live and show the agent handles the unknown.

---

## 10. Safety / legality (say this to judges — it shows maturity)

- **Detection is 100% passive and legal.** Building the detector is fully fine.
- **Generating attacks is a real attack** → keep it isolated:
  - Prefer replaying from **pcap files** or crafting frames programmatically — no live over-the-air attack.
  - If live is required: one dedicated ESP attacks *only your own victim ESP*, low power, your channel, your hardware.
  - **Never** deauth the venue/hackathon WiFi — breaks other teams, likely against venue rules, possibly illegal.
- Keep the **oracle's test sets independent** — the humans prepare the attack/benign pcaps so the agent can't game them.

---

## 11. Generalization — same skeleton, other domains

> Pattern: *ESP sniffs a signal it doesn't fully understand → agent reconstructs structure & builds a detector as code → replay-verify on labeled captures → OTA → next unknown, loop repeats.*

```mermaid
flowchart LR
    CORE["Reusable skeleton<br/>sniff → agent-codes-detector<br/>→ replay-verify → OTA"]
    CORE --> D1["Modbus/RS485 injection<br/>(safer OT version)"]
    CORE --> D2["Rogue BLE beacons"]
    CORE --> D3["NILM appliance ID<br/>(current sensor)"]
    CORE --> D4["Acoustic/vibration<br/>predictive maintenance"]
    CORE --> D5["RF anti-jamming<br/>classifier"]

    style CORE fill:#2a1e3a,stroke:#9d4ad9,color:#fff
```

**Modbus/RS485** is the safest same-narrative fallback if RF sniffing proves flaky: passive tap, canonical OT protocol, bad frames replayed on your own bus, identical loop.

---

## 12. Biggest risks

```mermaid
flowchart TD
    R1["RF capture flaky on ESP32"] --> M1["Verify promiscuous capture<br/>FIRST NIGHT before building on it"]
    R2["Human sneaks into loop"] --> M2["Enforce zero-approval trigger→OTA"]
    R3["Agent games the oracle"] --> M3["Humans own test pcaps, kept separate"]
    R4["OTA flakes on stage"] --> M4["Demo OTA on 1 board; 'fleet' in words"]
    R5["Team collides at h15"] --> M5["Contracts frozen h1, everyone on mocks"]

    style M1 fill:#3a1e1e,stroke:#d94a4a,color:#fff
```

---

### TL;DR
You own the spine (FastAPI backend + orchestrator + WebSocket) and the dashboard. Freeze 4 data contracts in hour 1, build everything on a mock event generator, swap to real sources at integration. The dashboard visualizing the autonomous loop is the pitch. Never cut verification or autonomy.

---

## 13. Controlled Red ESP (safe synthetic radio demo)

The hardware demo uses a dedicated ESP32 as a bounded synthetic anomaly
generator. It does not change any frozen backend contract and never transmits
the embedded management frame as a real 802.11 deauthentication frame.

```mermaid
flowchart LR
    HOTSPOT[Phone hotspot 2.4 GHz] --- RED[Red ESP32]
    HOTSPOT --- SNIFFERS[3 demo sniffer ESPs]
    HOTSPOT --- OLED[OLED status ESP]
    LAPTOP[Laptop / red-esp.local] -->|web control| RED
    BUTTON[Physical arm + emergency stop] --> RED
    RED -->|marked ESP-NOW broadcast TUMD| SNIFFERS & OLED
    SNIFFERS -->|Contract 1| INGEST[/ingest/]
```

The `TUMD` envelope contains a simulation flag, run/sequence metadata, a logical
frame count, an embedded frame sample, and a checksum. For
`synthetic_deauth_flood`, the sample starts with the real deauth frame-control
bytes (`0xC0 0x00`), so the existing agent and C oracle operate on representative
input after a sniffer unwraps it. Over the air it remains a vendor-specific
ESP-NOW action frame and cannot disconnect Wi-Fi clients.

Selectable profiles are `synthetic_deauth_flood`, `traffic_spike`,
`sequence_replay`, `sequence_jump`, `identity_churn`, and `malformed_payload`.
No ESP IP/MAC allowlist is needed. Selection happens in a local web UI and
execution additionally requires a 1.5-second physical button hold. Runs stop
after at most 10 seconds and 500 physical packets. The default deauth profile
uses 10 physical packets/s × 80 logical frames, producing an 800 frames/s
anomaly without a real flood. See [ESP_DEMO.md](ESP_DEMO.md) for the complete
five-board runbook and [esp-attacker/README.md](esp-attacker/README.md) for the
transmitter.
