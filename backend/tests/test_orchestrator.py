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
        guessed_type="deauth_flood",
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

    detected = next(event for event in state.events if event.type is EventType.ANOMALY_DETECTED)
    assert detected.payload["attack_class"] == "deauth_flood"


def test_counters_advance():
    _, state = _run_loop()
    assert state.counters.threats_detected == 1
    assert state.counters.filters_deployed == 1
    assert state.counters.frames_blocked > 0


def test_unknown_node_is_auto_registered():
    state = AppState()
    assert "esp-new" not in state.nodes
    anomaly = AnomalyIn(
        node_id="esp-new",
        timestamp=1.0,
        frame_hex=DEAUTH,
        anomaly_stats=AnomalyStats(subtype=12, count_in_window=5),
    )
    asyncio.run(
        handle_anomaly(state, anomaly, agent_call=call_agent, step_delay=0.0, sleep=_nosleep)
    )
    assert "esp-new" in state.nodes  # appeared in the fleet
    assert any(e.type is EventType.NODE_UP and e.node_id == "esp-new" for e in state.events)


def test_agent_failure_is_graceful():
    """A dead agent (e.g. Devin unreachable) must not crash the loop."""

    def boom(_payload, on_step=None):
        raise ConnectionError("nodename nor servname provided")

    state = AppState()
    anomaly = AnomalyIn(
        node_id="esp-07",
        timestamp=1.0,
        frame_hex=DEAUTH,
        anomaly_stats=AnomalyStats(subtype=12, count_in_window=5),
    )
    deployed = asyncio.run(
        handle_anomaly(state, anomaly, agent_call=boom, step_delay=0.0, sleep=_nosleep)
    )
    assert deployed is False
    types = [e.type for e in state.events]
    assert EventType.AGENT_STEP in types
    assert any("unavailable" in str(e.payload.get("text", "")) for e in state.events)
    assert state.counters.filters_deployed == 0


def test_agent_steps_and_iterations_surface():
    _, state = _run_loop()
    types = [e.type for e in state.events]
    # The stub narrates its sandbox work -> AGENT_STEP events reach the stream.
    assert EventType.AGENT_STEP in types
    # FILTER_GENERATED carries the sandbox iteration count for the dashboard badge.
    fg = next(e for e in state.events if e.type is EventType.FILTER_GENERATED)
    assert "iterations" in fg.payload


def test_default_agent_resolves_from_config():
    # agent_call=None -> get_agent() -> stub (conftest forces settings.agent=stub).
    state = AppState()
    anomaly = AnomalyIn(
        node_id="esp-09",
        timestamp=1.0,
        frame_hex=DEAUTH,
        anomaly_stats=AnomalyStats(subtype=12, count_in_window=200),
    )
    deployed = asyncio.run(handle_anomaly(state, anomaly, step_delay=0.0, sleep=_nosleep))
    assert deployed is True
