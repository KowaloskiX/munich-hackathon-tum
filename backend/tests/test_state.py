"""Fleet liveness: heartbeats register nodes; staleness flips them OFFLINE."""

from app.models import Heartbeat, HeartbeatStats, NodeState
from app.state import OFFLINE_AFTER_S, AppState


def test_heartbeat_registers_new_node():
    state = AppState()
    assert state.apply_heartbeat(Heartbeat(node_id="esp-01", timestamp=100.0)) is True
    assert state.apply_heartbeat(Heartbeat(node_id="esp-01", timestamp=101.0)) is False
    assert state.counters.active_nodes == 1


def test_stale_node_goes_offline():
    state = AppState()
    state.apply_heartbeat(Heartbeat(node_id="esp-01", timestamp=100.0))
    newly = state.mark_offline(now=100.0 + OFFLINE_AFTER_S + 1)
    assert newly == ["esp-01"]
    assert state.nodes["esp-01"].state is NodeState.OFFLINE
    assert state.counters.active_nodes == 0


def test_fresh_node_stays_online():
    state = AppState()
    state.apply_heartbeat(Heartbeat(node_id="esp-01", timestamp=100.0))
    assert state.mark_offline(now=100.0 + 1) == []


def test_filter_versions_keep_advancing_across_device_heartbeats():
    state = AppState()
    heartbeat = Heartbeat(
        node_id="esp-01",
        timestamp=100.0,
        stats=HeartbeatStats(fw_version="1.0.0"),
    )
    state.apply_heartbeat(heartbeat)

    assert state.set_deployed_filter("esp-01", "filter one", "deauth_flood", []) == "v2"

    # The board reports its static build version on every heartbeat. That must
    # not make the next edge-filter deployment reuse v2.
    state.apply_heartbeat(heartbeat.model_copy(update={"timestamp": 101.0}))
    assert state.set_deployed_filter("esp-01", "filter two", "auth_flood", []) == "v3"


def test_demo_reset_preserves_live_nodes_and_forgets_learned_state():
    state = AppState()
    state.apply_heartbeat(Heartbeat(node_id="esp-01", timestamp=100.0))
    state.set_deployed_filter("esp-01", "filter", "deauth_flood", [])
    first = state.create_incident("esp-01", 100.0)
    state.counters.threats_detected = 3
    state.counters.filters_deployed = 2
    state.counters.frames_blocked = 7

    assert state.reset_demo() == 1

    assert not state.deployed
    assert not state.incidents
    assert not state.events
    assert state.nodes["esp-01"].state is NodeState.NORMAL
    assert state.nodes["esp-01"].fw_version == "v1"
    assert state.counters.active_nodes == 1
    assert state.counters.threats_detected == 0
    assert state.counters.filters_deployed == 0
    assert state.counters.frames_blocked == 0
    assert state.create_incident("esp-01", 101.0).id != first.id
