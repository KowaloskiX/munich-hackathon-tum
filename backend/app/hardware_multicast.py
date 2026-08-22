"""Bench multicast bridge for client-isolated Wi-Fi networks.

The venue WLAN allows multicast while blocking direct client-to-client TCP.
The sniffer's safe serial self-test already emits a small UDP marker. This
module validates that marker, runs the normal anomaly pipeline, and publishes
the same authoritative HMI event used by the WebSocket endpoint.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import time
from typing import Annotated, Any, Literal

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

_SYNTHETIC_DEAUTH = "c0003a01ffffffffffff00112233445500112233445500700700"


class SimulatedDeauthMarker(BaseModel):
    schema_version: Literal[1]
    type: Literal["SIMULATED_DEAUTH"]
    node_id: str = Field(min_length=1, max_length=80)
    uptime_ms: int = Field(ge=0)
    count: int = Field(ge=1, le=100_000)
    channel: int = Field(ge=1, le=14)
    bssid: str = Field(min_length=17, max_length=17)


class HeartbeatMarker(BaseModel):
    schema_version: Literal[1]
    type: Literal["HEARTBEAT"]
    node_id: str = Field(min_length=1, max_length=80)
    uptime_ms: int = Field(ge=0)
    frames_seen: int = Field(ge=0)
    fw_version: str = Field(min_length=1, max_length=80)


HardwareMarker = Annotated[SimulatedDeauthMarker | HeartbeatMarker, Field(discriminator="type")]
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


def anomaly_from_marker(
    marker: SimulatedDeauthMarker, *, received_at: float | None = None
) -> AnomalyIn:
    """Convert a validated safe-test marker to the frozen ingest contract."""
    return AnomalyIn(
        node_id=marker.node_id,
        timestamp=time.time() if received_at is None else received_at,
        frame_hex=[_SYNTHETIC_DEAUTH],
        anomaly_stats=AnomalyStats(
            frame_type="mgmt",
            subtype=12,
            count_in_window=marker.count,
            window_ms=1000,
        ),
        guessed_type="deauth_flood",
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


def remember_marker(seen: set[tuple[str, int]], marker: SimulatedDeauthMarker) -> bool:
    """Return false for repeated UDP copies of the same physical keypress."""
    marker_id = (marker.node_id, marker.uptime_ms)
    if marker_id in seen:
        return False
    if len(seen) >= 256:
        seen.clear()
    seen.add(marker_id)
    return True


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
    try:
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
            anomaly = anomaly_from_marker(marker)
            if anomaly.node_id not in state.nodes:
                state.apply_heartbeat(Heartbeat(node_id=anomaly.node_id, timestamp=time.time()))
                state.emit(
                    LiveEvent(
                        type=EventType.NODE_UP,
                        node_id=anomaly.node_id,
                        ts=time.time(),
                    )
                )
            await handle_anomaly(state, anomaly)
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
