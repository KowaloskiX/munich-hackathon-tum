"""The /v1/hmi/status adapter matches the ESP32 display firmware contract."""

import time

from app.hmi import HmiStream
from app.models import EventType, Heartbeat, LiveEvent, NodeState
from app.state import AppState

# Fields the firmware (backend_client.cpp) hard-requires in the status JSON.
REQUIRED = {
    "schema_version",
    "stream_id",
    "stream_generation",
    "seq",
    "status",
    "valid_for_ms",
    "active_alerts",
    "sensors",
    "metrics",
}


def _attacked_state() -> AppState:
    s = AppState()
    s.apply_heartbeat(Heartbeat(node_id="esp-03", timestamp=time.time()))
    s.set_node_state("esp-03", NodeState.ALERT)
    s.emit(
        LiveEvent(
            type=EventType.FILTER_GENERATED,
            node_id="esp-03",
            ts=time.time(),
            payload={"attack_class": "deauth_flood"},
        )
    )
    return s


def test_safe_when_no_alerts():
    out = HmiStream().build(AppState()).model_dump()
    assert REQUIRED <= out.keys()
    assert out["schema_version"] == 1
    assert out["status"] == "SAFE"
    assert out["stream_id"]  # non-empty
    assert isinstance(out["stream_generation"], int) and isinstance(out["seq"], int)
    assert out["sensors"] == {"online": 0, "expected": 0}
    assert out["incident"] is None


def test_attack_surfaces_incident_and_metrics():
    state = _attacked_state()
    state.counters.frames_blocked = 247
    out = HmiStream().build(state).model_dump()
    assert out["status"] == "ATTACK"
    assert out["active_alerts"] == 1
    assert out["sensors"] == {"online": 1, "expected": 1}
    assert out["metrics"]["attack_frames_detected"] == 247
    assert out["incident"]["node_id"] == "esp-03"
    assert out["incident"]["attack_class"] == "deauth_flood"
    assert out["incident"]["id"]  # non-empty


def test_seq_advances_on_status_change():
    stream = HmiStream()
    first = stream.build(AppState()).seq
    same = stream.build(AppState()).seq
    assert same == first  # SAFE -> SAFE, no bump
    bumped = stream.build(_attacked_state()).seq
    assert bumped > first  # SAFE -> ATTACK bumps


def test_system_status_event_wraps_the_authoritative_snapshot():
    stream = HmiStream()
    event = stream.event(_attacked_state(), node_id="hmi-01")

    assert event.type == "SYSTEM_STATUS"
    assert event.node_id == "hmi-01"
    assert event.event_id
    assert event.stream_id == event.payload.stream_id
    assert event.stream_generation == event.payload.stream_generation
    assert event.seq == event.payload.seq
    assert event.payload.status == "ATTACK"


def test_seq_advances_when_metrics_change():
    state = _attacked_state()
    stream = HmiStream()
    first = stream.build(state).seq
    state.counters.frames_blocked = 20

    assert stream.build(state).seq > first
