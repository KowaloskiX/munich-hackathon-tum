"""FastAPI spine: ingest, heartbeat, fleet snapshot, OTA stub, live WS feed.

Mock loops run by default so the dashboard is alive with no hardware. Disable
per-source with env flags at integration:
    MOCK=0            -> everything real
    MOCK_HEARTBEAT=0  -> real ESP heartbeats only
    MOCK_ANOMALY=0    -> real /ingest anomalies only
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import time
from collections.abc import AsyncIterator

import httpx
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse

from . import mockgen
from .config import settings
from .hardware_multicast import listen_for_markers, publish_hmi_status
from .hmi import HmiStatus, HmiStream
from .models import (
    AnomalyIn,
    DemoResetResult,
    EnforcementReport,
    EnforcementResult,
    EventType,
    FirmwarePayload,
    FleetSnapshot,
    Heartbeat,
    IncidentSummary,
    LiveEvent,
)
from .orchestrator import handle_anomaly
from .report import render_markdown
from .state import AppState

state = AppState()
hmi_stream = HmiStream()
ingest_tasks: set[asyncio.Task[bool]] = set()


def _flag(name: str, default: bool = True) -> bool:
    master = os.environ.get("MOCK", "1") != "0"
    return master and os.environ.get(name, "1") != "0"


async def _offline_sweeper() -> None:
    while True:
        for node_id in state.mark_offline(time.time()):
            state.emit(LiveEvent(type=EventType.NODE_DOWN, node_id=node_id, ts=time.time()))
        await asyncio.sleep(2.0)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    tasks: list[asyncio.Task[None]] = [asyncio.create_task(_offline_sweeper())]
    if _flag("MOCK_HEARTBEAT"):
        tasks.append(asyncio.create_task(mockgen.heartbeat_loop(state)))
    # With a real agent (devin), don't auto-fire synthetic anomalies — each one
    # is a real multi-minute session. Trigger anomalies manually via POST /ingest.
    if _flag("MOCK_ANOMALY") and settings.agent != "devin":
        tasks.append(asyncio.create_task(mockgen.anomaly_loop(state)))
    if os.environ.get("HARDWARE_MULTICAST", "0") == "1":
        tasks.append(asyncio.create_task(listen_for_markers(state)))
        tasks.append(asyncio.create_task(publish_hmi_status(state, hmi_stream)))
    try:
        yield
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


app = FastAPI(title="Autonomous Anomaly Defense", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/nodes", response_model=FleetSnapshot)
async def get_nodes() -> FleetSnapshot:
    return state.snapshot()


@app.get("/v1/hmi/status", response_model=HmiStatus)
async def get_hmi_status() -> HmiStatus:
    """Aggregate SOC status for the ESP32 display firmware (see app/hmi.py)."""
    return hmi_stream.build(state)


@app.post("/heartbeat")
async def post_heartbeat(hb: Heartbeat) -> dict[str, str]:
    received = hb.model_copy(update={"timestamp": time.time()})
    is_new = state.apply_heartbeat(received)
    if is_new:
        state.emit(LiveEvent(type=EventType.NODE_UP, node_id=received.node_id, ts=time.time()))
    return {"status": "ok"}


def _log_task_error(task: asyncio.Task[bool]) -> None:
    ingest_tasks.discard(task)
    if not task.cancelled() and (exc := task.exception()) is not None:
        print(f"[ingest] handle_anomaly crashed: {exc!r}")


@app.post("/ingest")
async def post_ingest(anomaly: AnomalyIn) -> dict[str, str]:
    if anomaly.node_id not in state.nodes:
        received = Heartbeat(node_id=anomaly.node_id, timestamp=time.time())
        state.apply_heartbeat(received)
        state.emit(LiveEvent(type=EventType.NODE_UP, node_id=anomaly.node_id, ts=time.time()))
    # Fire and forget: the loop drives itself and streams progress over WS.
    task = asyncio.create_task(handle_anomaly(state, anomaly))
    ingest_tasks.add(task)
    task.add_done_callback(_log_task_error)
    return {"status": "accepted"}


@app.post("/demo/reset", response_model=DemoResetResult)
async def reset_demo() -> DemoResetResult:
    """Return the hardware showcase to its pre-attack state."""
    edge_url = os.environ.get("HARDWARE_EDGE_URL", "http://127.0.0.1:8100").rstrip("/")
    async with httpx.AsyncClient(base_url=edge_url, timeout=3.0) as client:
        try:
            response = await client.post("/demo/reset")
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="edge reset failed") from exc

    pending = list(ingest_tasks)
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    nodes_preserved = state.reset_demo()
    return DemoResetResult(nodes_preserved=nodes_preserved)


@app.get("/firmware/{node_id}", response_model=FirmwarePayload)
async def get_firmware(node_id: str) -> FirmwarePayload:
    """Serve the real deployed filter for a node to pull, compile, and load."""
    deployed = state.deployed.get(node_id)
    if deployed is None:
        node = state.nodes.get(node_id)
        return FirmwarePayload(node_id=node_id, fw_version=node.fw_version if node else "v1")
    return FirmwarePayload(
        node_id=node_id,
        fw_version=deployed.fw_version,
        filter_c_code=deployed.filter_c_code,
        attack_class=deployed.attack_class,
        sample_frames=list(deployed.sample_frames),
    )


@app.post("/enforcement")
async def post_enforcement(rep: EnforcementReport) -> dict[str, str]:
    """The edge gateway reports what its loaded filter actually dropped.

    Enforcement is the edge's job (the backend only detects + publishes), so
    this is the single source of the real FRAME_BLOCKED counts. We attach the
    counts to the node's deployed incident so the report + thread show them.
    """
    incident = state.latest_deployed_incident(rep.node_id)
    incident_id = incident.id if incident else None
    if incident is not None:
        incident.enforcement = EnforcementResult(blocked=rep.blocked, passed=rep.passed)
    state.emit(
        LiveEvent(
            type=EventType.FRAME_BLOCKED,
            node_id=rep.node_id,
            ts=time.time(),
            payload={
                "count": rep.blocked,
                "passed": rep.passed,
                "fw_version": rep.fw_version,
                "source": "edge",
                "incident_id": incident_id,
                "real": True,
            },
        )
    )
    return {"status": "ok"}


@app.get("/incidents", response_model=list[IncidentSummary])
async def get_incidents() -> list[IncidentSummary]:
    return state.list_incidents()


@app.get("/incidents/{incident_id}/report.md")
async def get_incident_report(incident_id: str) -> PlainTextResponse:
    incident = state.incidents.get(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="unknown incident")
    return PlainTextResponse(render_markdown(incident), media_type="text/markdown")


@app.websocket("/live")
async def live(ws: WebSocket) -> None:
    await ws.accept()
    queue = state.broadcaster.subscribe()
    try:
        # Bootstrap the client with the current fleet before streaming events.
        snapshot = state.snapshot().model_dump(mode="json")
        await ws.send_json({"type": "SNAPSHOT", "payload": snapshot})
        while True:
            event = await queue.get()
            await ws.send_json(event.model_dump(mode="json"))
    except WebSocketDisconnect:
        pass
    finally:
        state.broadcaster.unsubscribe(queue)


@app.websocket("/v1/hmi/live")
async def hmi_live(ws: WebSocket, node_id: str = "hmi-01") -> None:
    """Ordered aggregate status feed for the fail-safe ESP32 HMI."""
    await ws.accept()
    queue = state.broadcaster.subscribe()
    last_seq = -1
    try:
        while True:
            event = hmi_stream.event(state, node_id)
            if event.seq != last_seq:
                await ws.send_json(event.model_dump(mode="json"))
                last_seq = event.seq
            await queue.get()
    except WebSocketDisconnect:
        pass
    finally:
        state.broadcaster.unsubscribe(queue)
