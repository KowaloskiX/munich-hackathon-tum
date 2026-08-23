"""Bench multicast bridge for client-isolated Wi-Fi networks.

The venue WLAN allows multicast while blocking direct client-to-client TCP.
The sniffer's safe serial self-test already emits a small UDP marker. This
module validates that marker, re-enters the local edge enforcement path, and
publishes the same authoritative HMI event used by the WebSocket endpoint.
It falls back to the backend pipeline only when the edge process is unavailable.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import time
from typing import Annotated, Any, Literal

import httpx
from pydantic import BaseModel, Field, TypeAdapter

from .hmi import HmiStream
from .models import AnomalyIn, AnomalyStats, EventType, Heartbeat, LiveEvent
from .orchestrator import handle_anomaly
from .state import AppState

MARKER_GROUP = "239.255.77.77"
MARKER_PORT = 37777
HMI_GROUP = "239.255.77.78"
HMI_PORT = 37778
HMI_REFRESH_S = 3.0
HMI_SEND_RETRY_S = 0.25
DEFAULT_EDGE_URL = "http://127.0.0.1:8100"

_SYNTHETIC_DEAUTH = "c0003a01ffffffffffff00112233445500112233445500700700"


class SimulatedDeauthMarker(BaseModel):
    schema_version: Literal[1]
    type: Literal["SIMULATED_DEAUTH"]
    node_id: str = Field(min_length=1, max_length=80)
    uptime_ms: int = Field(ge=0)
    count: int = Field(ge=1, le=100_000)
    channel: int = Field(ge=1, le=14)
    bssid: str = Field(min_length=17, max_length=17)


class SimulatedMgmtFloodMarker(BaseModel):
    schema_version: Literal[1]
    type: Literal["SIMULATED_MGMT_FLOOD"]
    node_id: str = Field(min_length=1, max_length=80)
    uptime_ms: int = Field(ge=0)
    count: int = Field(ge=1, le=100_000)
    channel: int = Field(ge=1, le=14)
    bssid: str = Field(min_length=17, max_length=17)
    subtype: Literal[0, 11]
    attack_class: Literal["association_flood", "auth_flood"]


class HeartbeatMarker(BaseModel):
    schema_version: Literal[1]
    type: Literal["HEARTBEAT"]
    node_id: str = Field(min_length=1, max_length=80)
    uptime_ms: int = Field(ge=0)
    frames_seen: int = Field(ge=0)
    fw_version: str = Field(min_length=1, max_length=80)


SimulatedMarker = SimulatedDeauthMarker | SimulatedMgmtFloodMarker
HardwareMarker = Annotated[SimulatedMarker | HeartbeatMarker, Field(discriminator="type")]
_MARKER_ADAPTER = TypeAdapter(HardwareMarker)


class _MarkerProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue[bytes]) -> None:
        self.queue = queue

    def datagram_received(self, data: bytes, addr: tuple[Any, ...]) -> None:
        del addr
        try:
            self.queue.put_nowait(data)
        except asyncio.QueueFull:
            pass


def anomaly_from_marker(marker: SimulatedMarker, *, received_at: float | None = None) -> AnomalyIn:
    """Convert a validated safe-test marker to the frozen ingest contract."""
    subtype = marker.subtype if isinstance(marker, SimulatedMgmtFloodMarker) else 12
    attack_class = (
        marker.attack_class if isinstance(marker, SimulatedMgmtFloodMarker) else "deauth_flood"
    )
    synthetic_frame = f"{subtype << 4:02x}" + _SYNTHETIC_DEAUTH[2:]
    return AnomalyIn(
        node_id=marker.node_id,
        timestamp=time.time() if received_at is None else received_at,
        frame_hex=[synthetic_frame],
        anomaly_stats=AnomalyStats(
            frame_type="mgmt",
            subtype=subtype,
            count_in_window=marker.count,
            window_ms=1000,
        ),
        guessed_type=attack_class,
    )


def heartbeat_from_marker(
    marker: HeartbeatMarker, *, received_at: float | None = None
) -> Heartbeat:
    """Convert device uptime into an authoritative backend receipt time."""
    return Heartbeat.model_validate(
        {
            "node_id": marker.node_id,
            "timestamp": time.time() if received_at is None else received_at,
            "stats": {
                "frames_seen": marker.frames_seen,
                "fw_version": marker.fw_version,
            },
        }
    )


def remember_marker(seen: set[tuple[str, int]], marker: SimulatedMarker) -> bool:
    """Return false for repeated UDP copies of the same physical keypress."""
    marker_id = (marker.node_id, marker.uptime_ms)
    if marker_id in seen:
        return False
    if len(seen) >= 256:
        seen.clear()
    seen.add(marker_id)
    return True


async def route_marker_anomaly(
    state: AppState, anomaly: AnomalyIn, edge_client: httpx.AsyncClient
) -> Literal["edge", "backend"]:
    """Put multicast test traffic through enforcement before the backend.

    The UDP bridge exists because the venue WLAN blocks ESP-to-laptop TCP. Once
    the marker reaches the laptop, it must re-enter at the local edge gateway;
    sending it straight to the backend would bypass the deployed C filter and
    make every repeated test look like a new, unhandled incident.
    """
    try:
        response = await edge_client.post("/ingest", json=anomaly.model_dump(mode="json"))
        response.raise_for_status()
        return "edge"
    except httpx.HTTPError as exc:
        # Preserve the old single-process bench mode when edge is not running.
        # This fallback detects the incident but cannot claim in-path blocking.
        print(f"[hardware-multicast] edge unavailable; backend fallback: {exc}", flush=True)
        await handle_anomaly(state, anomaly)
        return "backend"


def _multicast_receiver(group: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    with contextlib.suppress(OSError):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(("", port))
    membership = socket.inet_aton(group) + socket.inet_aton("0.0.0.0")
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
    sock.setblocking(False)
    return sock


async def listen_for_markers(state: AppState) -> None:
    """Receive safe-test markers and feed them into the real orchestrator."""
    loop = asyncio.get_running_loop()
    sock = _multicast_receiver(MARKER_GROUP, MARKER_PORT)
    datagrams: asyncio.Queue[bytes] = asyncio.Queue(maxsize=64)
    try:
        transport, _protocol = await loop.create_datagram_endpoint(
            lambda: _MarkerProtocol(datagrams), sock=sock
        )
    except BaseException:
        sock.close()
        raise
    seen: set[tuple[str, int]] = set()
    edge_url = os.environ.get("HARDWARE_EDGE_URL", DEFAULT_EDGE_URL).rstrip("/")
    try:
        async with httpx.AsyncClient(base_url=edge_url, timeout=2.0) as edge_client:
            while True:
                raw = await datagrams.get()
                try:
                    marker = _MARKER_ADAPTER.validate_json(raw)
                except ValueError:
                    continue
                if isinstance(marker, HeartbeatMarker):
                    heartbeat = heartbeat_from_marker(marker)
                    is_new = state.apply_heartbeat(heartbeat)
                    if is_new:
                        state.emit(
                            LiveEvent(
                                type=EventType.NODE_UP,
                                node_id=heartbeat.node_id,
                                ts=time.time(),
                            )
                        )
                    continue
                if not remember_marker(seen, marker):
                    continue
                await route_marker_anomaly(state, anomaly_from_marker(marker), edge_client)
    finally:
        transport.close()


async def publish_hmi_status(state: AppState, stream: HmiStream) -> None:
    """Publish full ordered HMI snapshots on change and as a TTL refresh."""
    queue = state.broadcaster.subscribe()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    try:
        while True:
            event = stream.event(state, node_id="hmi-multicast")
            try:
                sock.sendto(event.model_dump_json().encode(), (HMI_GROUP, HMI_PORT))
            except OSError:
                # Wi-Fi route changes are transient on demo laptops. Keep the
                # publisher alive so one failed datagram cannot strand the HMI
                # in BRAK DANYCH until the backend is manually restarted.
                await asyncio.sleep(HMI_SEND_RETRY_S)
                continue
            try:
                await asyncio.wait_for(queue.get(), timeout=HMI_REFRESH_S)
            except TimeoutError:
                pass
    finally:
        state.broadcaster.unsubscribe(queue)
        sock.close()
