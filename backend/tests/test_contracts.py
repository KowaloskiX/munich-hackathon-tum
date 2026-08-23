"""Contract models validate good payloads and reject malformed ones."""

import pytest
from pydantic import ValidationError

from app.models import AnomalyIn, Heartbeat, NodeState


def test_anomaly_parses_minimal():
    a = AnomalyIn(node_id="esp-01", timestamp=1.0, frame_hex=["c000"])
    assert a.node_id == "esp-01"
    assert a.anomaly_stats.window_ms == 1000  # default applied


def test_anomaly_accepts_network_identity_metadata():
    anomaly = AnomalyIn.model_validate(
        {
            "node_id": "esp-01",
            "timestamp": 1.0,
            "bssid": "34:fa:9f:5d:24:a9",
            "sender_mac": "02:00:00:00:00:01",
            "anomaly_stats": {"channel": 11},
        }
    )

    assert anomaly.bssid == "34:fa:9f:5d:24:a9"
    assert anomaly.sender_mac == "02:00:00:00:00:01"
    assert anomaly.anomaly_stats.channel == 11


def test_anomaly_rejects_invalid_network_identity_metadata():
    with pytest.raises(ValidationError):
        AnomalyIn(node_id="esp-01", timestamp=1.0, sender_mac="not-a-mac")


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
