"""Fleet liveness: heartbeats register nodes; staleness flips them OFFLINE."""

from app.models import Heartbeat, NodeState
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
