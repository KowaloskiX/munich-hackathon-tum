"""Hardware HTTP routes normalize device clocks and register first contact."""

import asyncio
import time

import httpx
from fastapi.testclient import TestClient

from app import main
from app.hardware_multicast import (
    HeartbeatMarker,
    SimulatedDeauthMarker,
    SimulatedMgmtFloodMarker,
    anomaly_from_marker,
    heartbeat_from_marker,
    remember_marker,
    route_marker_anomaly,
)
from app.hmi import HmiStream
from app.models import AnomalyIn, Heartbeat
from app.state import AppState


def test_heartbeat_uses_backend_receipt_time(monkeypatch):
    isolated = AppState()
    monkeypatch.setattr(main, "state", isolated)
    received_after = time.time()

    asyncio.run(main.post_heartbeat(Heartbeat(node_id="esp-sniffer-01", timestamp=1.0)))

    assert isolated.nodes["esp-sniffer-01"].last_seen >= received_after


def test_ingest_registers_node_before_background_pipeline(monkeypatch):
    isolated = AppState()
    monkeypatch.setattr(main, "state", isolated)
    monkeypatch.setattr(main, "ingest_tasks", set())
    created: list[object] = []

    class _Pending:
        def add_done_callback(self, callback: object) -> None:
            del callback

        def close(self) -> None:
            pass

    def capture_task(coro: object) -> _Pending:
        created.append(coro)
        return _Pending()

    monkeypatch.setattr(main.asyncio, "create_task", capture_task)
    anomaly = AnomalyIn(node_id="esp-sniffer-01", timestamp=1.0)

    result = asyncio.run(main.post_ingest(anomaly))

    assert result == {"status": "accepted"}
    assert "esp-sniffer-01" in isolated.nodes
    assert created
    created[0].close()


def test_demo_reset_flushes_edge_then_backend(monkeypatch):
    isolated = AppState()
    isolated.apply_heartbeat(Heartbeat(node_id="esp-sniffer-01", timestamp=1.0))
    isolated.set_deployed_filter("esp-sniffer-01", "filter", "deauth_flood", [])
    isolated.create_incident("esp-sniffer-01", 1.0)
    monkeypatch.setattr(main, "state", isolated)
    monkeypatch.setattr(main, "ingest_tasks", set())
    requests: list[str] = []

    class Response:
        def raise_for_status(self) -> None:
            pass

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args: object) -> None:
            del args

        async def post(self, path: str) -> Response:
            requests.append(path)
            return Response()

    monkeypatch.setattr(main.httpx, "AsyncClient", lambda **kwargs: Client())

    result = asyncio.run(main.reset_demo())

    assert requests == ["/demo/reset"]
    assert result.status == "reset"
    assert result.nodes_preserved == 1
    assert not isolated.deployed
    assert not isolated.incidents


def test_hmi_websocket_sends_system_status(monkeypatch):
    monkeypatch.setenv("MOCK", "0")
    monkeypatch.setattr(main, "state", AppState())
    monkeypatch.setattr(main, "hmi_stream", HmiStream())

    with (
        TestClient(main.app) as client,
        client.websocket_connect("/v1/hmi/live?node_id=screen-bench") as websocket,
    ):
        event = websocket.receive_json()

    assert event["type"] == "SYSTEM_STATUS"
    assert event["node_id"] == "screen-bench"
    assert event["seq"] == event["payload"]["seq"]


def test_multicast_marker_becomes_frozen_ingest_contract():
    marker = SimulatedDeauthMarker.model_validate_json(
        '{"schema_version":1,"type":"SIMULATED_DEAUTH",'
        '"node_id":"esp-sniffer-01","uptime_ms":1234,"count":20,'
        '"channel":11,"bssid":"34:fa:9f:5d:24:a9"}'
    )

    anomaly = anomaly_from_marker(marker, received_at=123.0)

    assert anomaly.node_id == "esp-sniffer-01"
    assert anomaly.timestamp == 123.0
    assert anomaly.guessed_type == "deauth_flood"
    assert anomaly.anomaly_stats.subtype == 12
    assert anomaly.anomaly_stats.count_in_window == 20
    assert anomaly.frame_hex[0].startswith("c0")

    seen: set[tuple[str, int]] = set()
    assert remember_marker(seen, marker) is True
    assert remember_marker(seen, marker) is False


def test_changed_multicast_markers_preserve_subtype_and_attack_class():
    auth = SimulatedMgmtFloodMarker.model_validate_json(
        '{"schema_version":1,"type":"SIMULATED_MGMT_FLOOD",'
        '"node_id":"esp-sniffer-01","uptime_ms":1235,"count":50,'
        '"channel":11,"bssid":"34:fa:9f:5d:24:a9",'
        '"subtype":11,"attack_class":"auth_flood"}'
    )
    association = auth.model_copy(
        update={"uptime_ms": 1236, "count": 20, "subtype": 0, "attack_class": "association_flood"}
    )

    auth_anomaly = anomaly_from_marker(auth, received_at=124.0)
    association_anomaly = anomaly_from_marker(association, received_at=125.0)

    assert auth_anomaly.anomaly_stats.subtype == 11
    assert auth_anomaly.guessed_type == "auth_flood"
    assert auth_anomaly.frame_hex[0].startswith("b0")
    assert association_anomaly.anomaly_stats.subtype == 0
    assert association_anomaly.guessed_type == "association_flood"
    assert association_anomaly.frame_hex[0].startswith("00")


def test_multicast_heartbeat_uses_backend_receipt_time():
    marker = HeartbeatMarker.model_validate_json(
        '{"schema_version":1,"type":"HEARTBEAT",'
        '"node_id":"esp-sniffer-01","uptime_ms":1234,'
        '"frames_seen":456,"fw_version":"1.0.0"}'
    )

    heartbeat = heartbeat_from_marker(marker, received_at=987.0)

    assert heartbeat.node_id == "esp-sniffer-01"
    assert heartbeat.timestamp == 987.0
    assert heartbeat.stats.frames_seen == 456
    assert heartbeat.stats.fw_version == "1.0.0"


def test_multicast_anomaly_routes_through_edge_before_backend():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"forwarded": 1, "dropped": 0})

    async def scenario() -> tuple[str, AppState]:
        state = AppState()
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(base_url="http://edge", transport=transport) as client:
            anomaly = AnomalyIn(
                node_id="esp-sniffer-01",
                timestamp=1.0,
                frame_hex=["c000"],
                guessed_type="deauth_flood",
            )
            route = await route_marker_anomaly(state, anomaly, client)
        return route, state

    route, state = asyncio.run(scenario())

    assert route == "edge"
    assert len(requests) == 1
    assert requests[0].url.path == "/ingest"
    assert b'"frame_hex":["c000"]' in requests[0].content
    assert not state.events  # edge owns forwarding; no direct backend incident


def test_multicast_anomaly_falls_back_when_edge_is_down(monkeypatch):
    import app.hardware_multicast as multicast

    handled: list[AnomalyIn] = []

    async def fake_handle(_state: AppState, anomaly: AnomalyIn) -> bool:
        handled.append(anomaly)
        return True

    def unavailable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("edge down", request=request)

    async def scenario() -> str:
        monkeypatch.setattr(multicast, "handle_anomaly", fake_handle)
        transport = httpx.MockTransport(unavailable)
        async with httpx.AsyncClient(base_url="http://edge", transport=transport) as client:
            return await route_marker_anomaly(
                AppState(), AnomalyIn(node_id="esp-sniffer-01", timestamp=1.0), client
            )

    assert asyncio.run(scenario()) == "backend"
    assert len(handled) == 1


def test_hmi_multicast_publisher_recovers_after_send_error(monkeypatch):
    import app.hardware_multicast as multicast

    class FlakySocket:
        def __init__(self) -> None:
            self.attempts = 0
            self.sent = asyncio.Event()

        def setsockopt(self, *args: object) -> None:
            del args

        def sendto(self, payload: bytes, destination: tuple[str, int]) -> int:
            del payload, destination
            self.attempts += 1
            if self.attempts == 1:
                raise OSError("temporary route failure")
            self.sent.set()
            return 1

        def close(self) -> None:
            pass

    async def scenario() -> None:
        sock = FlakySocket()
        monkeypatch.setattr(multicast.socket, "socket", lambda *args: sock)
        monkeypatch.setattr(multicast, "HMI_SEND_RETRY_S", 0.001)
        task = asyncio.create_task(multicast.publish_hmi_status(AppState(), HmiStream()))
        try:
            await asyncio.wait_for(sock.sent.wait(), timeout=0.2)
            assert sock.attempts == 2
            assert not task.done()
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(scenario())
