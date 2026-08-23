"""The edge gateway: an in-path inline-drop proxy.

    ESP fleet  ->  edge (/ingest)  ->  backend (/ingest)

Frames flow through here. For each node, the currently-enforced native filter
drops malicious frames; only survivors reach the backend. A background poller
pulls newly deployed filters from the backend (`GET /firmware/{node}`), compiles
them, and hot-swaps. Real blocked/passed counts go back via `POST /enforcement`.

Run: `uv run uvicorn app.edge.gateway:app --host 0.0.0.0 --port 8100`
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal

import httpx
from fastapi import FastAPI
from pydantic import BaseModel, Field

from .artifacts import persist_filter
from .config import EdgeSettings, edge_settings
from .filter_runtime import CLANG_ARGS, CompileError
from .filter_store import FilterStore

CLANG_ARGS_STR = " ".join(CLANG_ARGS)


# --- ingest payload (mirrors the backend AnomalyIn contract) --------------
class AnomalyStats(BaseModel):
    frame_type: str = "mgmt"
    subtype: int | None = None
    count_in_window: int = 0
    window_ms: int = 1000


class IngestIn(BaseModel):
    node_id: str
    timestamp: float
    frame_hex: list[str] = Field(default_factory=list)
    rssi: int | None = None
    anomaly_stats: AnomalyStats = Field(default_factory=AnomalyStats)
    guessed_type: str | None = None


class EdgeResetResult(BaseModel):
    status: Literal["reset"] = "reset"


@dataclass
class EdgeState:
    store: FilterStore
    client: httpx.AsyncClient
    settings: EdgeSettings
    seen: set[str] = field(default_factory=set)
    stats: dict[str, dict[str, int]] = field(default_factory=dict)

    def stat(self, node_id: str) -> dict[str, int]:
        return self.stats.setdefault(node_id, {"evaluated": 0, "blocked": 0, "passed": 0})


def _log(msg: str) -> None:
    print(msg, flush=True)


async def process_ingest(st: EdgeState, payload: IngestIn) -> dict[str, object]:
    """Filter the frames, forward survivors, report real counts."""
    st.seen.add(payload.node_id)
    kept, dropped = st.store.partition(payload.node_id, payload.frame_hex)
    version = st.store.version(payload.node_id)
    blocked, passed = len(dropped), len(kept)

    stat = st.stat(payload.node_id)
    stat["evaluated"] += len(payload.frame_hex)
    stat["blocked"] += blocked
    stat["passed"] += passed

    if blocked:
        # The deployed filter matched: this attack is already handled here.
        # Report the real drop and DO NOT forward the benign residual (waking
        # the backend would spawn a spurious new incident + agent run).
        with contextlib.suppress(Exception):
            await st.client.post(
                "/enforcement",
                json={
                    "node_id": payload.node_id,
                    "fw_version": version or "v1",
                    "blocked": blocked,
                    "passed": passed,
                },
            )
        forwarded_count = 0
    else:
        # Nothing matched — normal / not-yet-filtered traffic. Pass it through so
        # the backend can detect a new anomaly and drive the agent loop.
        with contextlib.suppress(Exception):
            await st.client.post("/ingest", json=payload.model_dump())
        forwarded_count = passed

    _log(
        f"[edge] {payload.node_id} v={version or '-'}: "
        f"in {len(payload.frame_hex)} forwarded {forwarded_count} dropped {blocked}"
    )
    return {
        "node_id": payload.node_id,
        "forwarded": forwarded_count,
        "dropped": blocked,
        "fw_version": version,
    }


async def poll_once(st: EdgeState) -> None:
    """Pull the latest deployed filter for every seen node; compile + hot-swap."""
    for node_id in list(st.seen):
        try:
            resp = await st.client.get(f"/firmware/{node_id}")
            data = resp.json()
        except Exception as exc:  # transient backend/link error — try next tick
            _log(f"[edge] firmware poll failed for {node_id}: {exc}")
            continue
        code = str(data.get("filter_c_code") or "")
        version = str(data.get("fw_version") or "")
        if not code:
            continue
        rt = st.store.runtime(node_id)
        if rt.version == version:
            continue
        try:
            await asyncio.to_thread(rt.reload, code, version, str(data.get("attack_class") or ""))
        except CompileError as exc:
            _log(f"[edge] rejected {version} for {node_id}: {exc}")
            continue
        # Loud, honest proof that real native code was built and loaded.
        _log(
            f"[edge] compiled {version} for {node_id}: {CLANG_ARGS_STR} filter.c -> "
            f"filter.so (sha {rt.so_sha}, {rt.so_bytes} bytes native); "
            f"loaded block_frame() via dlopen"
        )
        with contextlib.suppress(Exception):
            path = persist_filter(
                st.settings.artifact_dir,
                node_id,
                version,
                rt.attack_class,
                rt.code,
                rt.so_path,
                rt.so_sha,
                rt.so_bytes,
                datetime.now(UTC).isoformat(timespec="seconds"),
            )
            _log(f"[edge] artifact written: {path}/filter.c (+ filter.so, manifest.json)")


def _status(st: EdgeState) -> dict[str, object]:
    nodes: dict[str, object] = {}
    for node_id in sorted(st.seen):
        rt = st.store.get(node_id)
        stat = st.stat(node_id)
        native = None
        if rt and rt.loaded:
            native = {"so_sha": rt.so_sha, "so_bytes": rt.so_bytes, "so_path": rt.so_path}
        nodes[node_id] = {
            "version": rt.version if rt else None,
            "attack_class": rt.attack_class if rt else "",
            "native": native,
            "frames_evaluated": stat["evaluated"],
            "blocked": stat["blocked"],
            "passed": stat["passed"],
            "filter_c_code": rt.code if rt else "",
        }
    return {"backend_url": st.settings.backend_url, "nodes": nodes}


def create_app(cfg: EdgeSettings | None = None, client: httpx.AsyncClient | None = None) -> FastAPI:
    cfg = cfg or edge_settings
    owns_client = client is None
    client = client or httpx.AsyncClient(base_url=cfg.backend_url.rstrip("/"), timeout=10.0)
    st = EdgeState(store=FilterStore(), client=client, settings=cfg)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        async def poller() -> None:
            while True:
                await poll_once(st)
                await asyncio.sleep(cfg.poll_interval_s)

        task = asyncio.create_task(poller())
        _log(f"[edge] gateway up: backend={cfg.backend_url} poll={cfg.poll_interval_s}s")
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            if owns_client:
                await client.aclose()

    app = FastAPI(title="sentinel-edge enforcement gateway", lifespan=lifespan)
    app.state.edge = st

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/status")
    async def status() -> dict[str, object]:
        return _status(st)

    @app.post("/demo/reset", response_model=EdgeResetResult)
    async def reset_demo() -> EdgeResetResult:
        st.store.clear()
        st.seen.clear()
        st.stats.clear()
        _log("[edge] demo filters and counters flushed")
        return EdgeResetResult()

    @app.post("/ingest")
    async def ingest(payload: IngestIn) -> dict[str, object]:
        return await process_ingest(st, payload)

    @app.post("/heartbeat")
    async def heartbeat(payload: dict[str, object]) -> dict[str, str]:
        # Heartbeats are not filtered — pass them straight through so a node can
        # point BACKEND_BASE_URL at the edge for everything.
        with contextlib.suppress(Exception):
            await st.client.post("/heartbeat", json=payload)
        return {"status": "ok"}

    return app


app = create_app()
