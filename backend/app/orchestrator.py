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
from pathlib import Path
from uuid import uuid4

from .agents import get_agent
from .attack_log import append_attack_response, capture_sha256, filter_sha256
from .config import settings
from .link_agents import get_link_scout
from .models import (
    AgentConnectionFailure,
    AgentIn,
    AgentOut,
    AnomalyIn,
    AttackCaptureSummary,
    AttackResponseLog,
    AttackResponseOutcome,
    AttackResponseSummary,
    DeploymentStatus,
    EventType,
    Heartbeat,
    IncidentSeverity,
    IncidentSource,
    LinkScanIn,
    LinkVerdict,
    LiveEvent,
    NodeState,
    OracleOut,
    PatchAttemptLog,
    PatchAttemptOutcome,
    PreviousDeploymentLog,
)
from .oracle import run_oracle
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
    oracle_call: OracleFn | None = None,
    step_delay: float = 0.6,
    max_retries: int = MAX_RETRIES,
    agent_conn_retries: int = AGENT_CONN_RETRIES,
    conn_backoff: float = 2.0,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    attack_log_path: Path | None = None,
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
    response_started_ts = time.time()
    initial_attack_guess = anomaly.guessed_type or "unknown"
    previous_deployment = state.deployed.get(node_id)
    response_log = AttackResponseLog(
        response_id=str(uuid4()),
        incident_id=incident.id,
        node_id=node_id,
        detected_ts=anomaly.timestamp,
        response_started_ts=response_started_ts,
        agent_backend=settings.agent,
        initial_attack_guess=initial_attack_guess,
        capture=AttackCaptureSummary(
            frame_count=len(anomaly.frame_hex),
            sha256=capture_sha256(anomaly.frame_hex),
            rssi=anomaly.rssi,
            bssid=anomaly.bssid,
            sender_mac=anomaly.sender_mac,
            stats=anomaly.anomaly_stats,
        ),
        previous_deployment=(
            PreviousDeploymentLog(
                firmware_version=previous_deployment.fw_version,
                attack_class=previous_deployment.attack_class,
                filter_sha256=filter_sha256(previous_deployment.filter_c_code),
                protected_attack_frame_count=len(previous_deployment.sample_frames),
            )
            if previous_deployment is not None
            else None
        ),
        summary=AttackResponseSummary(attack_type=initial_attack_guess),
    )

    def emit(etype: EventType, **payload: object) -> None:
        payload["incident_id"] = incident.id
        event = LiveEvent(type=etype, node_id=node_id, ts=time.time(), payload=payload)
        incident.events.append(event)
        state.emit(event)

    async def persist_response(
        outcome: AttackResponseOutcome, final_failure_reason: str | None = None
    ) -> None:
        completed_ts = time.time()
        response_log.completed_ts = completed_ts
        response_log.total_response_ms = max(0, round((completed_ts - response_started_ts) * 1000))
        response_log.outcome = outcome
        resolved_attack = next(
            (
                attempt.attack_class
                for attempt in reversed(response_log.attempts)
                if attempt.attack_class
            ),
            initial_attack_guess,
        )
        successful_approach = next(
            (
                attempt.approach_summary
                for attempt in reversed(response_log.attempts)
                if attempt.outcome is PatchAttemptOutcome.ORACLE_PASSED
            ),
            None,
        )
        successful_attempt = next(
            (
                attempt.attempt_number
                for attempt in response_log.attempts
                if attempt.outcome is PatchAttemptOutcome.ORACLE_PASSED
            ),
            None,
        )
        failed_approaches = [
            f"{attempt.approach_summary} Failure: {attempt.failure_reason}"
            for attempt in response_log.attempts
            if attempt.outcome is PatchAttemptOutcome.ORACLE_FAILED
        ]
        response_log.summary = AttackResponseSummary(
            attack_type=resolved_attack,
            successful_attempt=successful_attempt,
            successful_approach=successful_approach,
            failed_approaches=failed_approaches,
            final_failure_reason=final_failure_reason,
        )
        path = attack_log_path or Path(settings.attack_responses_path)
        try:
            await asyncio.to_thread(append_attack_response, path, response_log)
        except Exception as exc:
            # Analytics must never prevent an independently verified deployment.
            emit(EventType.AGENT_STEP, text=f"attack response log failed: {exc}")

    def complete_attempt(
        patch_attempt: PatchAttemptLog,
        outcome: PatchAttemptOutcome,
        failure_reason: str | None = None,
    ) -> None:
        completed_ts = time.time()
        patch_attempt.completed_ts = completed_ts
        patch_attempt.duration_ms = max(0, round((completed_ts - patch_attempt.started_ts) * 1000))
        patch_attempt.outcome = outcome
        patch_attempt.failure_reason = failure_reason

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

    previous_attack_frames = (
        previous_deployment.sample_frames if previous_deployment is not None else []
    )
    verification_attack_frames = list(dict.fromkeys([*previous_attack_frames, *anomaly.frame_hex]))
    agent_in = AgentIn(
        frame_hex=anomaly.frame_hex,
        anomaly_stats=anomaly.anomaly_stats,
        prev_filter=(
            previous_deployment.filter_c_code if previous_deployment is not None else None
        ),
    )
    verdict: OracleOut | None = None
    agent_out: AgentOut | None = None

    for attempt in range(max_retries + 1):
        await sleep(step_delay)
        emit(EventType.AGENT_ANALYZING, attempt=attempt + 1)
        patch_attempt = PatchAttemptLog(attempt_number=attempt + 1, started_ts=time.time())
        response_log.attempts.append(patch_attempt)
        # Retry transient network errors (DNS blip, dropped connection) before
        # giving up — a single hiccup reaching Devin must not kill the incident.
        agent_out = None
        for conn_try in range(agent_conn_retries + 1):
            try:
                agent_out = await asyncio.to_thread(partial(agent_call, agent_in, on_step=on_step))
                break
            except OSError as exc:
                patch_attempt.connection_errors.append(
                    AgentConnectionFailure(
                        try_number=conn_try + 1,
                        ts=time.time(),
                        error_type=type(exc).__name__,
                        message=str(exc),
                    )
                )
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
                failure_reason = f"{type(exc).__name__}: {exc}"
                complete_attempt(patch_attempt, PatchAttemptOutcome.AGENT_FAILED, failure_reason)
                await persist_response(AttackResponseOutcome.AGENT_FAILED, failure_reason)
                return False
            except Exception as exc:
                emit(EventType.AGENT_STEP, text=f"agent unavailable: {exc}")
                state.set_node_state(node_id, NodeState.ALERT)
                failure_reason = f"{type(exc).__name__}: {exc}"
                complete_attempt(patch_attempt, PatchAttemptOutcome.AGENT_FAILED, failure_reason)
                await persist_response(AttackResponseOutcome.AGENT_FAILED, failure_reason)
                return False
        assert agent_out is not None
        patch_attempt.approach_summary = agent_out.explanation
        patch_attempt.attack_class = agent_out.attack_class
        patch_attempt.confidence = agent_out.confidence
        patch_attempt.agent_iterations = agent_out.iterations
        patch_attempt.compiled = agent_out.compiled
        patch_attempt.self_tpr = agent_out.self_tpr
        patch_attempt.self_fpr = agent_out.self_fpr
        patch_attempt.session_url = agent_out.session_url
        patch_attempt.filter_sha256 = filter_sha256(agent_out.filter_c_code)
        patch_attempt.filter_c_code = agent_out.filter_c_code
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
        if oracle_call is None:
            verdict = await asyncio.to_thread(
                run_oracle,
                agent_out.filter_c_code,
                attack_frames=verification_attack_frames,
            )
        else:
            verdict = await asyncio.to_thread(oracle_call, agent_out.filter_c_code)
        result_payload = {
            "tpr": verdict.tpr,
            "fpr": verdict.fpr,
            "tests": f"{verdict.tests_passed}/{verdict.tests_total}",
            "attack_class": agent_out.attack_class,
        }
        incident.oracle = verdict  # keep the verdict (pass or fail) for the report
        patch_attempt.oracle = verdict
        if verdict.passed:
            complete_attempt(patch_attempt, PatchAttemptOutcome.ORACLE_PASSED)
            emit(EventType.VERIFY_PASSED, **result_payload)
            break
        # Surface WHY it failed (compile error / unparseable) so the dashboard
        # shows a reason instead of a cryptic 0/0. First non-empty log line.
        reason = next((ln.strip() for ln in verdict.log.splitlines() if ln.strip()), "")
        if not reason:
            reason = f"oracle rejected patch: TPR={verdict.tpr:.3f}, FPR={verdict.fpr:.3f}"
        complete_attempt(patch_attempt, PatchAttemptOutcome.ORACLE_FAILED, reason)
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
        failure_reason = response_log.attempts[-1].failure_reason
        await persist_response(AttackResponseOutcome.VERIFICATION_FAILED, failure_reason)
        return False

    assert agent_out is not None
    await sleep(step_delay)
    state.set_node_state(node_id, NodeState.UPDATING)
    emit(EventType.OTA_DEPLOYING, attack_class=agent_out.attack_class)
    deployment_started_ts = time.time()
    response_log.deployment.started_ts = deployment_started_ts

    # Publish the real filter for OTA (a node can pull + load it) and bump fw.
    firmware_version = state.set_deployed_filter(
        node_id,
        agent_out.filter_c_code,
        agent_out.attack_class,
        verification_attack_frames,
    )

    await sleep(step_delay)
    state.set_node_state(node_id, NodeState.PROTECTED)
    incident.deployed = True
    incident.deployed_ts = time.time()
    response_log.deployment.status = DeploymentStatus.PUBLISHED
    response_log.deployment.completed_ts = incident.deployed_ts
    response_log.deployment.duration_ms = max(
        0, round((incident.deployed_ts - deployment_started_ts) * 1000)
    )
    response_log.deployment.firmware_version = firmware_version
    response_log.deployment.filter_sha256 = filter_sha256(agent_out.filter_c_code)
    emit(EventType.DEPLOYED, attack_class=agent_out.attack_class)

    # The backend is the brain: detect -> Devin -> oracle -> publish the filter.
    # It does NOT enforce. Enforcement happens in the traffic path on the
    # sentinel-edge gateway, which pulls this filter over /firmware, drops
    # matching frames, and reports real counts back via POST /enforcement.
    await persist_response(AttackResponseOutcome.DEPLOYED)
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
