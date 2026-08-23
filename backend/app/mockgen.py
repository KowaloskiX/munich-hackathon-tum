"""Mock event generator — brings the whole dashboard alive with no hardware.

Drives the SAME orchestrator path the real system uses, so the demo exercises
real code (including a real oracle compile+replay) end to end. Swap off at
integration by setting MOCK_HEARTBEAT=0 / MOCK_ANOMALY=0 (see main.py).
"""

from __future__ import annotations

import asyncio
import random
import time

from .models import (
    AnomalyIn,
    AnomalyStats,
    EmailEventType,
    EmailLiveEvent,
    EventType,
    Heartbeat,
    HeartbeatStats,
    LinkScanIn,
    LiveEvent,
)
from .orchestrator import handle_anomaly, handle_link_scan
from .state import AppState

FAKE_NODES = ["esp-01", "esp-02"]

DEAUTH_FRAMES = [
    "c0003a01ffffffffffff00112233445500112233445500700700",
    "c0003a01aabbccddeeff00112233445500112233445500800700",
    "a0003a01ffffffffffff00112233445500112233445500900800",
]


def sample_email_event() -> EmailLiveEvent:
    """Typed mock for the dedicated email dashboard contract."""
    return EmailLiveEvent(
        type=EmailEventType.FLAGGED,
        analysis_id=1,
        ts=time.time(),
        message="Potential phishing email requires review",
    )


async def heartbeat_loop(state: AppState, *, period: float = 3.0) -> None:
    """Each fake node beats every `period`s; one node randomly goes quiet."""
    while True:
        silent = FAKE_NODES[-1] if random.random() < 0.15 else None
        for node_id in FAKE_NODES:
            if node_id == silent:
                continue  # skip -> the offline sweeper will grey it out
            node = state.nodes.get(node_id)
            hb = Heartbeat(
                node_id=node_id,
                timestamp=time.time(),
                stats=HeartbeatStats(
                    frames_seen=random.randint(5000, 20000),
                    blocked=node.blocked if node else 0,
                ),
            )
            is_new = state.apply_heartbeat(hb)
            if is_new:
                state.emit(LiveEvent(type=EventType.NODE_UP, node_id=node_id, ts=time.time()))
        await asyncio.sleep(period)


async def anomaly_loop(state: AppState, *, min_gap: float = 8.0, max_gap: float = 13.0) -> None:
    """Every few seconds fire a synthetic attack at a random node."""
    # Let a few heartbeats land first so nodes exist on the grid.
    await asyncio.sleep(5.0)
    while True:
        node_id = random.choice(FAKE_NODES)
        anomaly = AnomalyIn(
            node_id=node_id,
            timestamp=time.time(),
            frame_hex=list(DEAUTH_FRAMES),
            rssi=random.randint(-70, -40),
            bssid="02:00:00:00:00:01",
            sender_mac="02:00:00:00:00:02",
            anomaly_stats=AnomalyStats(
                frame_type="mgmt",
                subtype=12,
                channel=6,
                count_in_window=random.randint(120, 400),
            ),
            guessed_type="deauth_flood",
        )
        await handle_anomaly(state, anomaly)
        await asyncio.sleep(random.uniform(min_gap, max_gap))


MOCK_LINKS = [
    LinkScanIn(url="https://www.ledger.com/", source="mock"),
    LinkScanIn(url="https://ledger-livedsktpp.pages.dev/", source="mock"),
    LinkScanIn(url="https://www.kraken.com/", source="mock"),
    LinkScanIn(url="http://kraknkrakenlogn.webflow.io/", source="mock"),
]


async def link_scan_loop(state: AppState, *, min_gap: float = 10.0, max_gap: float = 16.0) -> None:
    """Periodically scan a mock URL (alternating legit/phishing) through the same
    web-domain orchestrator the real /scan endpoint uses."""
    await asyncio.sleep(7.0)
    i = 0
    while True:
        await handle_link_scan(state, MOCK_LINKS[i % len(MOCK_LINKS)])
        i += 1
        await asyncio.sleep(random.uniform(min_gap, max_gap))
