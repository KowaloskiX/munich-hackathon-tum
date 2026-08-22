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

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from . import mockgen
from .config import settings
from .hmi import HmiStatus, HmiStream
from .models import AnomalyIn, EventType, FleetSnapshot, Heartbeat, LiveEvent
from .orchestrator import handle_anomaly
from .state import AppState

state = AppState()
hmi_stream = HmiStream()


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
    is_new = state.apply_heartbeat(hb)
    if is_new:
        state.emit(LiveEvent(type=EventType.NODE_UP, node_id=hb.node_id, ts=time.time()))
    return {"status": "ok"}


def _log_task_error(task: asyncio.Task[bool]) -> None:
    if not task.cancelled() and (exc := task.exception()) is not None:
        print(f"[ingest] handle_anomaly crashed: {exc!r}")


@app.post("/ingest")
async def post_ingest(anomaly: AnomalyIn) -> dict[str, str]:
    # Fire and forget: the loop drives itself and streams progress over WS.
    task = asyncio.create_task(handle_anomaly(state, anomaly))
    task.add_done_callback(_log_task_error)
    return {"status": "accepted"}


@app.get("/firmware/{node_id}")
async def get_firmware(node_id: str) -> dict[str, str]:
    node = state.nodes.get(node_id)
    return {"node_id": node_id, "fw_version": node.fw_version if node else "v1"}


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
