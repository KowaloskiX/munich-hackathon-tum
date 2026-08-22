"""Contract models validate good payloads and reject malformed ones."""

import pytest
from pydantic import ValidationError

from app.models import AnomalyIn, Heartbeat, NodeState


def test_anomaly_parses_minimal():
    a = AnomalyIn(node_id="esp-01", timestamp=1.0, frame_hex=["c000"])
    assert a.node_id == "esp-01"
    assert a.anomaly_stats.window_ms == 1000  # default applied


def test_heartbeat_defaults():
    hb = Heartbeat(node_id="esp-02", timestamp=2.0)
    assert hb.state is NodeState.NORMAL
    assert hb.stats.fw_version == "v1"


def test_heartbeat_rejects_bad_state():
    with pytest.raises(ValidationError):
        Heartbeat(node_id="esp-03", timestamp=3.0, state="EXPLODED")


def test_anomaly_requires_node_id():
    with pytest.raises(ValidationError):
        AnomalyIn(timestamp=1.0)
