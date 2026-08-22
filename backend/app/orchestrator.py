"""Per-anomaly orchestration: trigger -> agent -> oracle -> (retry) -> OTA.

Zero human in the loop. Emits a LiveEvent at every transition so the dashboard
mirrors the sequence in ARCHITECTURE.md §3. The oracle is authoritative: nothing
deploys until it passes on the backend's own held-out fixtures.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from functools import partial

from .agents import get_agent
from .models import (
    AgentIn,
    AgentOut,
    AnomalyIn,
    EventType,
    Heartbeat,
    LiveEvent,
    NodeState,
    OracleOut,
)
from .oracle import run_oracle
from .state import AppState

MAX_RETRIES = 2

AgentFn = Callable[..., AgentOut]  # (AgentIn, on_step=None) -> AgentOut
OracleFn = Callable[[str], OracleOut]


async def handle_anomaly(
    state: AppState,
    anomaly: AnomalyIn,
    *,
    agent_call: AgentFn | None = None,
    oracle_call: OracleFn = run_oracle,
    step_delay: float = 0.6,
    max_retries: int = MAX_RETRIES,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> bool:
    """Run one full autonomous loop for an anomaly. Returns True if deployed.

    `agent_call` and `oracle_call` are injected so tests can run them
    synchronously; when `agent_call` is None the configured agent (stub or
    devin, per settings.agent) is resolved via `get_agent()`.
    """
    if agent_call is None:
        agent_call = get_agent()
    node_id = anomaly.node_id

    def emit(etype: EventType, **payload: object) -> None:
        state.emit(LiveEvent(type=etype, node_id=node_id, ts=time.time(), payload=payload))

    # The agent runs in a worker thread (to_thread); marshal its narration back
    # onto the loop thread before touching the (non-thread-safe) event queue.
    loop = asyncio.get_running_loop()

    def on_step(msg: str) -> None:
        loop.call_soon_threadsafe(lambda: emit(EventType.AGENT_STEP, text=msg))

    # Auto-register an unknown node so a fresh sniffer (or a manual /ingest)
    # shows up in the fleet instead of an anomaly against a node nobody sees.
    if node_id not in state.nodes:
        state.apply_heartbeat(Heartbeat(node_id=node_id, timestamp=anomaly.timestamp))
        emit(EventType.NODE_UP)

    state.set_node_state(node_id, NodeState.ALERT)
    emit(
        EventType.ANOMALY_DETECTED,
        frames=len(anomaly.frame_hex),
        subtype=anomaly.anomaly_stats.subtype,
        count=anomaly.anomaly_stats.count_in_window,
    )

    agent_in = AgentIn(frame_hex=anomaly.frame_hex, anomaly_stats=anomaly.anomaly_stats)
    verdict: OracleOut | None = None
    agent_out: AgentOut | None = None

    for attempt in range(max_retries + 1):
        await sleep(step_delay)
        emit(EventType.AGENT_ANALYZING, attempt=attempt + 1)
        try:
            agent_out = await asyncio.to_thread(partial(agent_call, agent_in, on_step=on_step))
        except Exception as exc:
            emit(EventType.AGENT_STEP, text=f"agent unavailable: {exc}")
            state.set_node_state(node_id, NodeState.ALERT)
            return False
        emit(
            EventType.FILTER_GENERATED,
            attack_class=agent_out.attack_class,
            confidence=agent_out.confidence,
            iterations=agent_out.iterations,
            self_tpr=agent_out.self_tpr,
            self_fpr=agent_out.self_fpr,
            compiled=agent_out.compiled,
        )

        await sleep(step_delay)
        emit(EventType.VERIFYING, attempt=attempt + 1)
        verdict = await asyncio.to_thread(oracle_call, agent_out.filter_c_code)
        result_payload = {
            "tpr": verdict.tpr,
            "fpr": verdict.fpr,
            "tests": f"{verdict.tests_passed}/{verdict.tests_total}",
            "attack_class": agent_out.attack_class,
        }
        if verdict.passed:
            emit(EventType.VERIFY_PASSED, **result_payload)
            break
        emit(EventType.VERIFY_FAILED, attempt=attempt + 1, **result_payload)
        # Feed the failure back so the agent narrows its next attempt.
        agent_in = AgentIn(
            frame_hex=anomaly.frame_hex,
            anomaly_stats=anomaly.anomaly_stats,
            prev_filter=agent_out.filter_c_code,
            failure_log=verdict.log,
        )

    if verdict is None or not verdict.passed:
        # Exhausted retries — leave node in ALERT for a human. No deploy.
        state.set_node_state(node_id, NodeState.ALERT)
        return False

    assert agent_out is not None
    await sleep(step_delay)
    state.set_node_state(node_id, NodeState.UPDATING)
    emit(EventType.OTA_DEPLOYING, attack_class=agent_out.attack_class)

    await sleep(step_delay)
    state.set_node_state(node_id, NodeState.PROTECTED)
    emit(EventType.DEPLOYED, attack_class=agent_out.attack_class)

    # The now-protected node starts dropping the attack traffic.
    emit(EventType.FRAME_BLOCKED, count=anomaly.anomaly_stats.count_in_window or 42)
    return True
