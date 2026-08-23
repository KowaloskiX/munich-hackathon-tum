"""Full autonomous loop: fail -> retry -> pass -> deploy, with real oracle."""

import asyncio
import json
from pathlib import Path

import httpx

from app.agent_stub import call_agent
from app.attack_log import read_attack_responses
from app.models import AgentOut, AnomalyIn, AnomalyStats, EventType
from app.orchestrator import handle_anomaly
from app.state import AppState

DEAUTH = ["c0003a01ffffffffffff001122334455001122334455"]
AUTH = ["b0003a01ffffffffffff001122334455001122334455"]
ASSOCIATION = ["00003a01ffffffffffff001122334455001122334455"]
PREEMPTIVE_FILTER = """\
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
bool block_frame(const uint8_t *f, size_t n) {
    if (n < 1) return false;
    uint8_t subtype = (f[0] >> 4) & 0xF;
    return subtype == 0xC || subtype == 0xA || subtype == 0xB || subtype == 0x0;
}
"""


async def _nosleep(_: float) -> None:
    return None


def _run_loop(attack_log_path: Path | None = None) -> tuple[bool, AppState]:
    state = AppState()
    anomaly = AnomalyIn(
        node_id="esp-01",
        timestamp=1.0,
        frame_hex=DEAUTH,
        rssi=-42,
        bssid="34:fa:9f:5d:24:a9",
        sender_mac="02:00:00:00:00:01",
        anomaly_stats=AnomalyStats(subtype=12, channel=11, count_in_window=200),
        guessed_type="deauth_flood",
    )
    deployed = asyncio.run(
        handle_anomaly(
            state,
            anomaly,
            agent_call=call_agent,
            attack_log_path=attack_log_path,
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
    # The backend is the brain: the loop ends at DEPLOYED. Enforcement (and the
    # FRAME_BLOCKED counts) happen on the edge gateway, not here.
    assert types[-1] is EventType.DEPLOYED
    assert EventType.FRAME_BLOCKED not in types

    detected = next(event for event in state.events if event.type is EventType.ANOMALY_DETECTED)
    assert detected.payload["attack_class"] == "deauth_flood"


def test_counters_advance():
    _, state = _run_loop()
    assert state.counters.threats_detected == 1
    assert state.counters.filters_deployed == 1
    # The backend does not enforce, so it never fabricates a blocked count.
    assert state.counters.frames_blocked == 0


def test_deploy_publishes_the_real_filter_for_ota():
    _, state = _run_loop()
    deployed = state.deployed["esp-01"]
    assert "block_frame" in deployed.filter_c_code  # the actual C, not a version string
    assert deployed.fw_version == "v2"  # bumped from v1 on deploy


def test_stub_builds_cumulative_filters_for_staged_demo_variants(tmp_path):
    state = AppState()
    path = tmp_path / "attack_responses.jsonl"
    previous_filters: list[str | None] = []

    def recording_agent(payload, on_step=None):
        previous_filters.append(payload.prev_filter)
        return call_agent(payload, on_step=on_step)

    variants = [
        (DEAUTH, 12, "deauth_flood"),
        (AUTH, 11, "auth_flood"),
        (ASSOCIATION, 0, "association_flood"),
    ]

    for frames, subtype, attack_class in variants:
        anomaly = AnomalyIn(
            node_id="esp-01",
            timestamp=float(subtype + 20),
            frame_hex=frames,
            anomaly_stats=AnomalyStats(subtype=subtype, count_in_window=50),
            guessed_type=attack_class,
        )
        assert asyncio.run(
            handle_anomaly(
                state,
                anomaly,
                agent_call=recording_agent,
                attack_log_path=path,
                step_delay=0.0,
                sleep=_nosleep,
            )
        )

    deployed = state.deployed["esp-01"]
    assert deployed.fw_version == "v4"
    assert "subtype == 0xC" in deployed.filter_c_code
    assert "subtype == 0xB" in deployed.filter_c_code
    assert "subtype == 0x0" in deployed.filter_c_code
    assert deployed.sample_frames == [*DEAUTH, *AUTH, *ASSOCIATION]
    assert previous_filters[0] is None
    assert previous_filters[-1] is not None

    responses = read_attack_responses(path)
    assert len(responses) == 3
    assert responses[0].previous_deployment is None
    assert responses[1].previous_deployment is not None
    assert responses[1].previous_deployment.firmware_version == "v2"
    assert responses[1].previous_deployment.protected_attack_frame_count == 1
    assert responses[2].previous_deployment is not None
    assert responses[2].previous_deployment.protected_attack_frame_count == 2


def test_orchestrator_rejects_filter_that_hides_future_demo_stages(tmp_path):
    state = AppState()
    anomaly = AnomalyIn(
        node_id="esp-01",
        timestamp=1.0,
        frame_hex=DEAUTH,
        anomaly_stats=AnomalyStats(subtype=12, count_in_window=50),
        guessed_type="deauth_flood",
    )

    def preemptive_agent(_payload, on_step=None):
        return AgentOut(
            attack_class="deauth_flood",
            confidence=0.9,
            filter_c_code=PREEMPTIVE_FILTER,
            explanation="Block every staged subtype up front.",
        )

    deployed = asyncio.run(
        handle_anomaly(
            state,
            anomaly,
            agent_call=preemptive_agent,
            attack_log_path=tmp_path / "attacks.jsonl",
            step_delay=0.0,
            max_retries=0,
            sleep=_nosleep,
        )
    )

    assert deployed is False
    assert "esp-01" not in state.deployed
    assert EventType.VERIFY_FAILED in [event.type for event in state.events]


def test_incident_is_recorded_and_id_stamped():
    _, state = _run_loop()
    assert len(state.incidents) == 1
    incident = next(iter(state.incidents.values()))
    # Every emitted event carries the incident id so the dashboard can group them.
    assert all(e.payload.get("incident_id") == incident.id for e in state.events)
    # The report backing is populated end to end (enforcement is filled later,
    # by the edge gateway's POST /enforcement — None until then).
    assert incident.deployed is True
    assert incident.oracle is not None and incident.oracle.passed
    assert incident.enforcement is None
    assert "block_frame" in incident.filter_c_code


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


def test_transient_connection_error_is_retried_then_succeeds():
    """A DNS/connection blip must not kill the incident — it is retried."""
    fails = {"left": 2}

    def flaky(payload, on_step=None):
        if fails["left"] > 0:
            fails["left"] -= 1
            raise httpx.ConnectError("[Errno 8] nodename nor servname provided")
        return call_agent(payload, on_step=on_step)

    state = AppState()
    anomaly = AnomalyIn(
        node_id="esp-01",
        timestamp=1.0,
        frame_hex=DEAUTH,
        anomaly_stats=AnomalyStats(subtype=12, count_in_window=200),
    )
    deployed = asyncio.run(
        handle_anomaly(
            state, anomaly, agent_call=flaky, step_delay=0.0, conn_backoff=0.0, sleep=_nosleep
        )
    )
    assert deployed is True  # recovered after the transient failures
    assert fails["left"] == 0  # both blips were hit and retried past
    assert EventType.DEPLOYED in [e.type for e in state.events]
    steps = [e for e in state.events if e.type is EventType.AGENT_STEP]
    assert any("retry" in str(e.payload.get("text", "")) for e in steps)


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


def test_attack_response_log_keeps_failed_and_successful_approaches(tmp_path):
    path = tmp_path / "attack_responses.jsonl"
    deployed, state = _run_loop(path)

    assert deployed is True
    lines = path.read_text().splitlines()
    assert len(lines) == 1
    response = json.loads(lines[0])
    incident = next(iter(state.incidents.values()))
    assert response["incident_id"] == incident.id
    assert response["node_id"] == "esp-01"
    assert response["outcome"] == "deployed"
    assert response["schema_version"] == 2
    assert response["capture"]["frame_count"] == 1
    assert response["capture"]["bssid"] == "34:fa:9f:5d:24:a9"
    assert response["capture"]["sender_mac"] == "02:00:00:00:00:01"
    assert response["capture"]["stats"]["channel"] == 11
    assert len(response["capture"]["sha256"]) == 64
    assert response["agent_backend"] == "stub"
    assert response["summary"]["attack_type"] == "deauth_flood"
    assert response["summary"]["successful_attempt"] == 2
    assert "Narrowed to the observed" in response["summary"]["successful_approach"]
    assert len(response["summary"]["failed_approaches"]) == 1
    assert "block all mgmt" in response["summary"]["failed_approaches"][0]

    failed, successful = response["attempts"]
    assert failed["outcome"] == "oracle_failed"
    assert failed["oracle"]["passed"] is False
    assert failed["failure_reason"]
    assert successful["outcome"] == "oracle_passed"
    assert successful["oracle"]["passed"] is True
    assert len(successful["filter_sha256"]) == 64
    assert "block_frame" in successful["filter_c_code"]

    deployment = response["deployment"]
    assert deployment["status"] == "published"
    assert deployment["firmware_version"] == "v2"
    assert deployment["duration_ms"] >= 0
    assert response["total_response_ms"] >= deployment["duration_ms"]


def test_attack_response_log_records_terminal_agent_failure(tmp_path):
    def boom(_payload, on_step=None):
        raise ConnectionError("Devin DNS lookup failed")

    path = tmp_path / "attack_responses.jsonl"
    state = AppState()
    anomaly = AnomalyIn(
        node_id="esp-07",
        timestamp=1.0,
        frame_hex=DEAUTH,
        anomaly_stats=AnomalyStats(subtype=12, count_in_window=5),
        guessed_type="deauth_flood",
    )
    deployed = asyncio.run(
        handle_anomaly(
            state,
            anomaly,
            agent_call=boom,
            attack_log_path=path,
            agent_conn_retries=0,
            step_delay=0.0,
            sleep=_nosleep,
        )
    )

    assert deployed is False
    response = json.loads(path.read_text().splitlines()[0])
    assert response["outcome"] == "agent_failed"
    assert response["summary"]["successful_approach"] is None
    assert "DNS lookup failed" in response["summary"]["final_failure_reason"]
    assert response["attempts"][0]["outcome"] == "agent_failed"
    assert response["attempts"][0]["connection_errors"][0]["try_number"] == 1
    assert response["deployment"]["status"] == "not_attempted"


def test_attack_response_log_appends_with_unique_response_ids(tmp_path):
    path = tmp_path / "attack_responses.jsonl"
    _run_loop(path)

    # A legacy line written before agent_backend existed still parses; the model
    # fills the default ("unknown") on read.
    lines = path.read_text().splitlines()
    legacy = json.loads(lines[0])
    legacy.pop("agent_backend")
    path.write_text(json.dumps(legacy) + "\n")

    _run_loop(path)

    responses = read_attack_responses(path)
    assert len(responses) == 2
    assert responses[0].agent_backend == "unknown"
    assert responses[1].agent_backend == "stub"
    assert responses[0].response_id != responses[1].response_id
