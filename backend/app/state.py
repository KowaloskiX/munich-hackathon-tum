"""In-memory fleet state, event log, and WebSocket broadcaster.

Single process, single source of truth. No DB — this is a hackathon spine.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque

from .models import (
    Counters,
    DeployedFilter,
    EventType,
    FleetSnapshot,
    Heartbeat,
    Incident,
    IncidentList,
    IncidentReport,
    IncidentSeverity,
    IncidentSource,
    IncidentSummary,
    LiveEvent,
    NodeState,
    NodeView,
)

OFFLINE_AFTER_S = 10.0


def _next_version(current: str) -> str:
    """Bump a `vN` firmware version; used when a new filter is deployed."""
    try:
        return f"v{int(current.lstrip('v')) + 1}"
    except ValueError:
        return "v2"


class Node:
    def __init__(self, node_id: str, ts: float, fw_version: str = "v1") -> None:
        self.node_id = node_id
        self.state = NodeState.NORMAL
        self.last_seen = ts
        self.fw_version = fw_version
        self.label = node_id
        self.blocked = 0

    def view(self) -> NodeView:
        return NodeView(
            node_id=self.node_id,
            state=self.state,
            last_seen=self.last_seen,
            fw_version=self.fw_version,
            label=self.label,
            blocked=self.blocked,
        )


class Broadcaster:
    """Fan-out of LiveEvents to all connected WebSocket clients."""

    def __init__(self) -> None:
        self._queues: set[asyncio.Queue[LiveEvent]] = set()

    def subscribe(self) -> asyncio.Queue[LiveEvent]:
        q: asyncio.Queue[LiveEvent] = asyncio.Queue(maxsize=256)
        self._queues.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[LiveEvent]) -> None:
        self._queues.discard(q)

    def publish(self, event: LiveEvent) -> None:
        for q in list(self._queues):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # Slow client: drop oldest, keep the stream live.
                try:
                    q.get_nowait()
                    q.put_nowait(event)
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    pass


class AppState:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.events: deque[LiveEvent] = deque(maxlen=200)
        self.counters = Counters()
        self.broadcaster = Broadcaster()
        # Real OTA: the filter each node should pull + load (see node_agent.py).
        self.deployed: dict[str, DeployedFilter] = {}
        # Durable per-incident record backing the incident report + history.
        self.incidents: dict[str, IncidentReport] = {}
        # Unified cross-domain feed (email + link + esp) for the dashboard list.
        # Bounded like the event log so a long run can't grow it without limit.
        self.feed: deque[Incident] = deque(maxlen=500)
        self._incident_seq = 0

    # --- ingest paths ----------------------------------------------------
    def apply_heartbeat(self, hb: Heartbeat) -> bool:
        """Update fleet from a heartbeat. Returns True if this is a new node."""
        is_new = hb.node_id not in self.nodes
        node = self.nodes.get(hb.node_id) or Node(hb.node_id, hb.timestamp)
        node.last_seen = hb.timestamp
        node.fw_version = hb.stats.fw_version
        node.blocked = hb.stats.blocked
        # A heartbeat's own state is advisory; orchestrator owns ALERT/UPDATING.
        if node.state in (NodeState.OFFLINE, NodeState.NORMAL):
            node.state = hb.state
        self.nodes[hb.node_id] = node
        self._recount()
        return is_new

    def set_node_state(self, node_id: str, state: NodeState) -> None:
        node = self.nodes.get(node_id)
        if node is not None:
            node.state = state
            self._recount()

    def set_deployed_filter(
        self,
        node_id: str,
        filter_c_code: str,
        attack_class: str,
        sample_frames: list[str],
    ) -> str:
        """Publish a filter for OTA and bump the node's fw_version. Returns it."""
        node = self.nodes.get(node_id)
        current = node.fw_version if node else "v1"
        version = _next_version(current)
        self.deployed[node_id] = DeployedFilter(
            fw_version=version,
            filter_c_code=filter_c_code,
            attack_class=attack_class,
            sample_frames=list(sample_frames),
        )
        if node is not None:
            node.fw_version = version
        return version

    # --- unified cross-domain feed (email + link + esp) -----------------
    def add_feed_item(
        self,
        *,
        source: IncidentSource,
        severity: IncidentSeverity,
        title: str,
        summary: str = "",
        verdict: str = "",
        risk_score: int | None = None,
        ref: str = "",
        url: str = "",
        report_id: str = "",
    ) -> Incident:
        """Append a cross-domain feed item and stream it to the dashboard.

        Every domain (email, link, esp) funnels findings here so there is one
        queryable list (GET /feed) for later analysis. Distinct from the ESP-only
        IncidentReport store (self.incidents) that drives OTA/report. `report_id`
        links an ESP item to its IncidentReport so the emitted event keeps the
        loop-wide `incident_id` stamp other events carry.
        """
        self._incident_seq += 1
        incident = Incident(
            id=self._incident_seq,
            ts=time.time(),
            source=source,
            severity=severity,
            title=title,
            summary=summary,
            verdict=verdict,
            risk_score=risk_score,
            ref=ref,
            url=url,
        )
        self.feed.append(incident)
        payload = incident.model_dump(mode="json")
        if report_id:
            payload["incident_id"] = report_id
        self.emit(
            LiveEvent(
                type=EventType.INCIDENT_CREATED,
                node_id=ref if source is IncidentSource.ESP else None,
                ts=incident.ts,
                payload=payload,
            )
        )
        return incident

    def list_feed(
        self,
        source: IncidentSource | None = None,
        cursor: int | None = None,
        limit: int = 50,
    ) -> IncidentList:
        """Newest-first feed page (id-descending), optionally by source."""
        items = [
            i
            for i in reversed(self.feed)
            if (source is None or i.source is source) and (cursor is None or i.id < cursor)
        ]
        page = items[:limit]
        next_cursor = page[-1].id if len(items) > limit and page else None
        return IncidentList(items=page, next_cursor=next_cursor)

    # --- incidents -------------------------------------------------------
    def create_incident(self, node_id: str, ts: float) -> IncidentReport:
        self._incident_seq += 1
        incident = IncidentReport(
            id=f"inc-{self._incident_seq:04d}", node_id=node_id, started_ts=ts
        )
        self.incidents[incident.id] = incident
        return incident

    def latest_deployed_incident(self, node_id: str) -> IncidentReport | None:
        """Most recent deployed incident for a node (edge counts attach here)."""
        for incident in reversed(self.incidents.values()):
            if incident.node_id == node_id and incident.deployed:
                return incident
        return None

    def list_incidents(self) -> list[IncidentSummary]:
        return [
            IncidentSummary(
                id=inc.id,
                node_id=inc.node_id,
                started_ts=inc.started_ts,
                attack_class=inc.attack_class,
                deployed=inc.deployed,
                blocked=inc.enforcement.blocked if inc.enforcement else 0,
                oracle_passed=inc.oracle.passed if inc.oracle else None,
            )
            for inc in self.incidents.values()
        ]

    def mark_offline(self, now: float) -> list[str]:
        """Flip stale nodes to OFFLINE. Returns node_ids newly offline."""
        newly: list[str] = []
        for node in self.nodes.values():
            if node.state is not NodeState.OFFLINE and now - node.last_seen > OFFLINE_AFTER_S:
                node.state = NodeState.OFFLINE
                newly.append(node.node_id)
        if newly:
            self._recount()
        return newly

    # --- events ----------------------------------------------------------
    def emit(self, event: LiveEvent) -> None:
        # Counter side effects live here so mock and real paths agree.
        if event.type is EventType.ANOMALY_DETECTED:
            self.counters.threats_detected += 1
        elif event.type is EventType.DEPLOYED:
            self.counters.filters_deployed += 1
        elif event.type is EventType.FRAME_BLOCKED:
            n = int(event.payload.get("count", 1))
            self.counters.frames_blocked += n
            if event.node_id and event.node_id in self.nodes:
                self.nodes[event.node_id].blocked += n
        elif event.type is EventType.LINK_VERDICT and event.payload.get("verdict") == "malicious":
            self.counters.threats_detected += 1
        self.events.append(event)
        self.broadcaster.publish(event)

    def _recount(self) -> None:
        self.counters.active_nodes = sum(
            1 for n in self.nodes.values() if n.state is not NodeState.OFFLINE
        )

    def snapshot(self) -> FleetSnapshot:
        return FleetSnapshot(
            nodes=[n.view() for n in self.nodes.values()],
            counters=self.counters,
        )
