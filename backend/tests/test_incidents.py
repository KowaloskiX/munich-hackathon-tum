"""The unified cross-domain feed: every domain lands in one queryable list."""

from __future__ import annotations

import asyncio

from app.link_scout import scan_link_stub
from app.models import (
    AgentOut,
    AnomalyIn,
    AnomalyStats,
    EventType,
    IncidentSeverity,
    IncidentSource,
    LinkScanIn,
    OracleOut,
)
from app.orchestrator import handle_anomaly, handle_link_scan
from app.state import AppState


async def _no_sleep(_: float) -> None:
    return None


def test_add_and_list_newest_first_and_filter() -> None:
    s = AppState()
    s.add_feed_item(source=IncidentSource.EMAIL, severity=IncidentSeverity.CRITICAL, title="a")
    s.add_feed_item(source=IncidentSource.LINK, severity=IncidentSeverity.WARNING, title="b")
    assert [i.title for i in s.list_feed().items] == ["b", "a"]
    only_email = s.list_feed(source=IncidentSource.EMAIL)
    assert len(only_email.items) == 1
    assert only_email.items[0].source is IncidentSource.EMAIL


def test_pagination() -> None:
    s = AppState()
    for i in range(3):
        s.add_feed_item(source=IncidentSource.ESP, severity=IncidentSeverity.INFO, title=str(i))
    page = s.list_feed(limit=2)
    assert len(page.items) == 2
    assert page.next_cursor is not None
    rest = s.list_feed(cursor=page.next_cursor, limit=2)
    assert len(rest.items) == 1
    assert rest.next_cursor is None


def test_add_feed_item_emits_event() -> None:
    s = AppState()
    s.add_feed_item(source=IncidentSource.LINK, severity=IncidentSeverity.WARNING, title="x")
    assert any(e.type is EventType.INCIDENT_CREATED for e in s.events)


def test_esp_anomaly_creates_feed_item() -> None:
    s = AppState()

    def fake_agent(_in: object, on_step: object = None) -> AgentOut:
        return AgentOut(
            attack_class="deauth",
            confidence=1.0,
            filter_c_code="bool block_frame(const uint8_t *f, size_t n){return false;}",
        )

    def fake_oracle(_code: str) -> OracleOut:
        return OracleOut(passed=True, tpr=1.0, fpr=0.0, tests_total=1, tests_passed=1)

    asyncio.run(
        handle_anomaly(
            s,
            AnomalyIn(
                node_id="esp-9",
                timestamp=0.0,
                frame_hex=["c0"],
                anomaly_stats=AnomalyStats(subtype=12, count_in_window=100),
            ),
            agent_call=fake_agent,
            oracle_call=fake_oracle,
            step_delay=0.0,
            sleep=_no_sleep,
        )
    )
    esp = s.list_feed(source=IncidentSource.ESP)
    assert esp.items
    assert esp.items[0].ref == "esp-9"


def test_malicious_link_creates_feed_item() -> None:
    s = AppState()
    asyncio.run(
        handle_link_scan(
            s,
            LinkScanIn(url="https://ledger-livedsktpp.pages.dev/"),
            scout=scan_link_stub,
            sleep=_no_sleep,
        )
    )
    link = s.list_feed(source=IncidentSource.LINK)
    assert link.items
    assert link.items[0].verdict == "malicious"
    assert link.items[0].severity is IncidentSeverity.CRITICAL
