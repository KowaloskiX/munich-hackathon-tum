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
from .link_agents import get_link_scout
from .models import (
    AgentIn,
    AgentOut,
    AnomalyIn,
    EventType,
    Heartbeat,
    IncidentSeverity,
    IncidentSource,
    LinkScanIn,
    LinkVerdict,
    LiveEvent,
    NodeState,
    OracleOut,
)
from .oracle import run_oracle
from .prompts import SAMPLE_BENIGN
from .state import AppState

LinkScoutFn = Callable[..., LinkVerdict]  # (LinkScanIn, on_step=None) -> LinkVerdict

MAX_RETRIES = 2
AGENT_CONN_RETRIES = 4  # extra tries on a transient network error (e.g. DNS blip)

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
    agent_conn_retries: int = AGENT_CONN_RETRIES,
    conn_backoff: float = 2.0,
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

    # A durable record for this incident: the report endpoint reads it, and the
    # dashboard groups the live stream by its id (stamped into every payload).
    incident = state.create_incident(node_id, anomaly.timestamp)
    incident.frames = len(anomaly.frame_hex)

    def emit(etype: EventType, **payload: object) -> None:
        payload["incident_id"] = incident.id
        event = LiveEvent(type=etype, node_id=node_id, ts=time.time(), payload=payload)
        incident.events.append(event)
        state.emit(event)

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
        attack_class=anomaly.guessed_type or "unknown",
    )
    state.add_feed_item(
        source=IncidentSource.ESP,
        severity=IncidentSeverity.WARNING,
        title=f"{node_id}: {anomaly.anomaly_stats.frame_type} anomaly",
        summary=f"{anomaly.anomaly_stats.count_in_window} frames in window "
        f"(subtype {anomaly.anomaly_stats.subtype})",
        ref=node_id,
        report_id=incident.id,
    )

    agent_in = AgentIn(frame_hex=anomaly.frame_hex, anomaly_stats=anomaly.anomaly_stats)
    verdict: OracleOut | None = None
    agent_out: AgentOut | None = None

    for attempt in range(max_retries + 1):
        await sleep(step_delay)
        emit(EventType.AGENT_ANALYZING, attempt=attempt + 1)
        # Retry transient network errors (DNS blip, dropped connection) before
        # giving up — a single hiccup reaching Devin must not kill the incident.
        agent_out = None
        for conn_try in range(agent_conn_retries + 1):
            try:
                agent_out = await asyncio.to_thread(partial(agent_call, agent_in, on_step=on_step))
                break
            except OSError as exc:
                if conn_try < agent_conn_retries:
                    # ⏳-prefixed: shows as live status, not a loud error yet.
                    emit(
                        EventType.AGENT_STEP,
                        text=f"⏳ agent connection failed ({exc}); "
                        f"retry {conn_try + 1}/{agent_conn_retries}",
                    )
                    await sleep(conn_backoff)
                    continue
                emit(EventType.AGENT_STEP, text=f"agent unavailable: {exc}")
                state.set_node_state(node_id, NodeState.ALERT)
                return False
            except Exception as exc:
                emit(EventType.AGENT_STEP, text=f"agent unavailable: {exc}")
                state.set_node_state(node_id, NodeState.ALERT)
                return False
        assert agent_out is not None
        emit(
            EventType.FILTER_GENERATED,
            attack_class=agent_out.attack_class,
            confidence=agent_out.confidence,
            iterations=agent_out.iterations,
            self_tpr=agent_out.self_tpr,
            self_fpr=agent_out.self_fpr,
            compiled=agent_out.compiled,
        )
        incident.attack_class = agent_out.attack_class
        incident.confidence = agent_out.confidence
        incident.iterations = agent_out.iterations
        incident.self_tpr = agent_out.self_tpr
        incident.self_fpr = agent_out.self_fpr
        incident.filter_c_code = agent_out.filter_c_code
        incident.session_url = agent_out.session_url

        await sleep(step_delay)
        emit(EventType.VERIFYING, attempt=attempt + 1)
        verdict = await asyncio.to_thread(oracle_call, agent_out.filter_c_code)
        result_payload = {
            "tpr": verdict.tpr,
            "fpr": verdict.fpr,
            "tests": f"{verdict.tests_passed}/{verdict.tests_total}",
            "attack_class": agent_out.attack_class,
        }
        incident.oracle = verdict  # keep the verdict (pass or fail) for the report
        if verdict.passed:
            emit(EventType.VERIFY_PASSED, **result_payload)
            break
        # Surface WHY it failed (compile error / unparseable) so the dashboard
        # shows a reason instead of a cryptic 0/0. First non-empty log line.
        reason = next((ln.strip() for ln in verdict.log.splitlines() if ln.strip()), "")
        emit(
            EventType.VERIFY_FAILED,
            attempt=attempt + 1,
            reason=reason[:200],
            **result_payload,
        )
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

    # Publish the real filter for OTA (a node can pull + load it) and bump fw.
    sample_frames = [*anomaly.frame_hex, *SAMPLE_BENIGN]
    state.set_deployed_filter(
        node_id, agent_out.filter_c_code, agent_out.attack_class, sample_frames
    )

    await sleep(step_delay)
    state.set_node_state(node_id, NodeState.PROTECTED)
    incident.deployed = True
    incident.deployed_ts = time.time()
    emit(EventType.DEPLOYED, attack_class=agent_out.attack_class)

    # The backend is the brain: detect -> Devin -> oracle -> publish the filter.
    # It does NOT enforce. Enforcement happens in the traffic path on the
    # sentinel-edge gateway, which pulls this filter over /firmware, drops
    # matching frames, and reports real counts back via POST /enforcement.
    return True


async def handle_link_scan(
    state: AppState,
    scan: LinkScanIn,
    *,
    scout: LinkScoutFn | None = None,
    step_delay: float = 0.5,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> LinkVerdict:
    """Run the web domain's scan loop: submit -> browse -> research -> verdict.

    The web analogue of `handle_anomaly`: no human in the loop, and every phase
    is streamed as a LiveEvent so the dashboard mirrors the two-agent scan. The
    scout stays independent (it never sees the fleet state); this orchestrator
    owns the event stream and the threat counter (via state.emit). When `scout`
    is None the configured scout (stub or devin) is resolved via get_link_scout().
    """
    if scout is None:
        scout = get_link_scout()

    def emit(etype: EventType, **payload: object) -> None:
        state.emit(LiveEvent(type=etype, node_id=None, ts=time.time(), payload=payload))

    emit(EventType.LINK_SUBMITTED, url=scan.url, source=scan.source)
    await sleep(step_delay)
    emit(EventType.LINK_BROWSING, url=scan.url)
    await sleep(step_delay)
    emit(EventType.LINK_RESEARCHING, url=scan.url)

    # Marshal scout narration (from the worker thread) back onto the loop thread
    # before touching the event queue, then stream it as AGENT_STEP lines.
    loop = asyncio.get_running_loop()

    def on_step(msg: str) -> None:
        loop.call_soon_threadsafe(lambda: emit(EventType.AGENT_STEP, text=msg))

    verdict = await asyncio.to_thread(partial(scout, scan, on_step=on_step))

    await sleep(step_delay)
    emit(
        EventType.LINK_VERDICT,
        url=scan.url,
        verdict=verdict.verdict,
        legit_score=verdict.legit_score,
        brand=verdict.impersonated_brand,
        signals=verdict.top_signals,
    )
    if verdict.verdict in ("malicious", "suspicious"):
        state.add_feed_item(
            source=IncidentSource.LINK,
            severity=(
                IncidentSeverity.CRITICAL
                if verdict.verdict == "malicious"
                else IncidentSeverity.WARNING
            ),
            title=f"Suspicious link: {scan.url}",
            summary=verdict.reasoning,
            verdict=verdict.verdict,
            risk_score=round((1.0 - verdict.legit_score) * 100),
            ref=scan.url,
            url=scan.url,
        )
    return verdict
