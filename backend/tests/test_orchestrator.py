"""Full autonomous loop: fail -> retry -> pass -> deploy, with real oracle."""

import asyncio

from app.agent_stub import call_agent
from app.models import AnomalyIn, AnomalyStats, EventType
from app.orchestrator import handle_anomaly
from app.state import AppState

DEAUTH = ["c0003a01ffffffffffff001122334455001122334455"]


async def _nosleep(_: float) -> None:
    return None


def _run_loop() -> tuple[bool, AppState]:
    state = AppState()
    anomaly = AnomalyIn(
        node_id="esp-01",
        timestamp=1.0,
        frame_hex=DEAUTH,
        anomaly_stats=AnomalyStats(subtype=12, count_in_window=200),
    )
    deployed = asyncio.run(
        handle_anomaly(
            state,
            anomaly,
            agent_call=call_agent,
            step_delay=0.0,
            sleep=_nosleep,
        )
    )
    return deployed, state


def test_loop_deploys_after_one_retry():
    deployed, state = _run_loop()
    assert deployed is True
    types = [e.type for e in state.events]
    # Stub over-blocks first (fail), narrows on retry (pass), then deploys.
    assert EventType.VERIFY_FAILED in types
    assert types.index(EventType.VERIFY_PASSED) > types.index(EventType.VERIFY_FAILED)
    assert types[-1] is EventType.FRAME_BLOCKED
    assert EventType.DEPLOYED in types


def test_counters_advance():
    _, state = _run_loop()
    assert state.counters.threats_detected == 1
    assert state.counters.filters_deployed == 1
    assert state.counters.frames_blocked > 0
