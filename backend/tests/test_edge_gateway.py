"""The edge gateway drops attacks in-path, suppresses residual, and reports."""

import asyncio
import json
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from app.edge.config import EdgeSettings
from app.edge.filter_store import FilterStore
from app.edge.gateway import (
    EdgeState,
    IngestIn,
    _status,
    create_app,
    poll_once,
    process_ingest,
)
from tests.test_edge_runtime import ATTACK, BENIGN, DEAUTH_C

AUTH = "b0003a01ffffffffffff001122334455001122334455"
ASSOCIATION = "00003a01ffffffffffff001122334455001122334455"
DEAUTH_AUTH_C = DEAUTH_C.replace(
    "return subtype == 0xC || subtype == 0xA;",
    "return subtype == 0xC || subtype == 0xA || subtype == 0xB;",
)


def _state(handler) -> tuple[EdgeState, list[tuple[str, str, dict]]]:
    calls: list[tuple[str, str, dict]] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        calls.append((request.method, request.url.path, body))
        return handler(request)

    client = httpx.AsyncClient(base_url="http://backend", transport=httpx.MockTransport(wrapped))
    st = EdgeState(store=FilterStore(), client=client, settings=EdgeSettings())
    return st, calls


def _ok(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"status": "accepted"})


def test_pass_through_when_no_filter_loaded():
    st, calls = _state(_ok)
    payload = IngestIn(node_id="esp-01", timestamp=1.0, frame_hex=ATTACK + BENIGN)
    res = asyncio.run(process_ingest(st, payload))
    assert res == {"node_id": "esp-01", "forwarded": 4, "dropped": 0, "fw_version": None}
    ingests = [c for c in calls if c[1] == "/ingest"]
    assert len(ingests) == 1 and ingests[0][2]["frame_hex"] == ATTACK + BENIGN
    assert not [c for c in calls if c[1] == "/enforcement"]


def test_drops_attack_and_suppresses_residual():
    st, calls = _state(_ok)
    st.store.runtime("esp-01").reload(DEAUTH_C, "v2", "deauth_flood")
    payload = IngestIn(node_id="esp-01", timestamp=1.0, frame_hex=ATTACK + BENIGN)
    res = asyncio.run(process_ingest(st, payload))
    assert res == {"node_id": "esp-01", "forwarded": 0, "dropped": 2, "fw_version": "v2"}
    assert not [c for c in calls if c[1] == "/ingest"]  # residual not forwarded
    enf = [c for c in calls if c[1] == "/enforcement"]
    assert enf and enf[0][2] == {
        "node_id": "esp-01",
        "fw_version": "v2",
        "blocked": 2,
        "passed": 2,
    }


def test_repeat_is_suppressed_but_unseen_stage_reaches_backend():
    st, calls = _state(_ok)
    st.store.runtime("esp-01").reload(DEAUTH_AUTH_C, "v3", "auth_flood")

    repeated = IngestIn(node_id="esp-01", timestamp=1.0, frame_hex=[AUTH])
    unseen = IngestIn(node_id="esp-01", timestamp=2.0, frame_hex=[ASSOCIATION])
    assert asyncio.run(process_ingest(st, repeated))["dropped"] == 1
    assert asyncio.run(process_ingest(st, unseen))["forwarded"] == 1

    assert len([call for call in calls if call[1] == "/enforcement"]) == 1
    ingests = [call for call in calls if call[1] == "/ingest"]
    assert len(ingests) == 1
    assert ingests[0][2]["frame_hex"] == [ASSOCIATION]


def test_poll_compiles_persists_and_status(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/firmware/esp-01":
            return httpx.Response(
                200,
                json={
                    "node_id": "esp-01",
                    "fw_version": "v2",
                    "filter_c_code": DEAUTH_C,
                    "attack_class": "deauth_flood",
                    "sample_frames": [],
                },
            )
        return httpx.Response(200, json={})

    st, _ = _state(handler)
    st.settings.artifact_dir = str(tmp_path)
    st.seen.add("esp-01")
    asyncio.run(poll_once(st))

    rt = st.store.get("esp-01")
    assert rt is not None and rt.loaded and rt.version == "v2"
    # A real native artifact was persisted (source + compiled shared object).
    assert (tmp_path / "esp-01" / "filter.c").read_text() == DEAUTH_C
    assert (tmp_path / "esp-01" / "filter.so").exists()
    assert (tmp_path / "esp-01" / "v2" / "filter.c").exists()

    # Status surfaces what is enforced + native proof.
    node = _status(st)["nodes"]["esp-01"]
    assert node["version"] == "v2"
    assert node["native"]["so_bytes"] > 0
    assert "block_frame" in node["filter_c_code"]


def test_heartbeat_passes_through():
    calls: list[tuple[str, str, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path, json.loads(request.content or b"{}")))
        return httpx.Response(200, json={"status": "ok"})

    client = httpx.AsyncClient(base_url="http://backend", transport=httpx.MockTransport(handler))
    app = create_app(cfg=EdgeSettings(poll_interval_s=999.0), client=client)
    hb = {"node_id": "esp-01", "timestamp": 1.0, "stats": {"blocked": 0, "fw_version": "v1"}}
    with TestClient(app) as tc:
        assert tc.post("/heartbeat", json=hb).json() == {"status": "ok"}
    assert [c for c in calls if c[1] == "/heartbeat"]


def test_demo_reset_unloads_filters_and_clears_edge_counters():
    client = httpx.AsyncClient(base_url="http://backend", transport=httpx.MockTransport(_ok))
    app = create_app(cfg=EdgeSettings(poll_interval_s=999.0), client=client)
    edge = app.state.edge
    runtime = edge.store.runtime("esp-01")
    runtime.reload(DEAUTH_C, "v2", "deauth_flood")
    so_path = Path(runtime.so_path or "")
    edge.seen.add("esp-01")
    edge.stats["esp-01"] = {"evaluated": 2, "blocked": 1, "passed": 1}

    with TestClient(app) as tc:
        assert tc.post("/demo/reset").json() == {"status": "reset"}

    assert edge.store.get("esp-01") is None
    assert not edge.seen
    assert not edge.stats
    assert not so_path.exists()
