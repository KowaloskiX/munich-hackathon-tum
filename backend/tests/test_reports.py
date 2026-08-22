"""Real OTA serve, enforcement report ingest, and the incident report."""

import asyncio

import pytest
from fastapi import HTTPException

from app import main
from app.models import (
    EnforcementReport,
    EnforcementResult,
    EventType,
    Heartbeat,
    OracleOut,
)
from app.report import render_markdown
from app.state import AppState


def _seeded_incident(state: AppState):
    inc = state.create_incident("esp-01", 1000.0)
    inc.attack_class = "deauth_flood"
    inc.confidence = 0.9
    inc.frames = 3
    inc.filter_c_code = "bool block_frame(const uint8_t *f, size_t n) { return true; }"
    inc.iterations = 2
    inc.self_tpr = 1.0
    inc.self_fpr = 0.0
    inc.oracle = OracleOut(passed=True, tpr=1.0, fpr=0.0, tests_total=10, tests_passed=10)
    inc.enforcement = EnforcementResult(
        blocked=3, passed=2, attack_total=3, benign_total=2, false_positives=0
    )
    inc.deployed = True
    inc.deployed_ts = 1001.0
    inc.session_url = "https://app.devin.ai/sessions/abc"
    return inc


def test_render_markdown_has_filter_oracle_and_enforcement():
    inc = _seeded_incident(AppState())
    md = render_markdown(inc)
    assert inc.id in md
    assert "block_frame" in md  # the deployed C filter is embedded
    assert "10/10" in md  # held-out oracle result
    assert "Blocked **3/5**" in md  # real enforcement measurement
    assert "devin.ai" in md  # link back to the Devin session


def test_firmware_endpoint_serves_the_real_filter():
    main.state = AppState()
    main.state.apply_heartbeat(Heartbeat(node_id="esp-01", timestamp=1.0))
    main.state.set_deployed_filter(
        "esp-01", "bool block_frame(const uint8_t *f, size_t n){return false;}", "deauth", ["c000"]
    )
    fw = asyncio.run(main.get_firmware("esp-01"))
    assert "block_frame" in fw.filter_c_code
    assert fw.fw_version == "v2"
    assert fw.sample_frames == ["c000"]


def test_firmware_endpoint_when_nothing_deployed():
    main.state = AppState()
    fw = asyncio.run(main.get_firmware("unknown"))
    assert fw.filter_c_code == ""
    assert fw.fw_version == "v1"


def test_enforcement_endpoint_emits_real_frame_blocked():
    main.state = AppState()
    main.state.apply_heartbeat(Heartbeat(node_id="esp-sw-01", timestamp=1.0))
    asyncio.run(
        main.post_enforcement(
            EnforcementReport(node_id="esp-sw-01", fw_version="v2", blocked=7, passed=3)
        )
    )
    assert main.state.counters.frames_blocked == 7
    event = main.state.events[-1]
    assert event.type is EventType.FRAME_BLOCKED
    assert event.payload["real"] is True
    assert event.payload["count"] == 7


def test_report_endpoint_404_for_unknown_incident():
    main.state = AppState()
    with pytest.raises(HTTPException):
        asyncio.run(main.get_incident_report("inc-9999"))
