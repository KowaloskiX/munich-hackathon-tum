"""The web-domain orchestration streams its loop and counts a malicious link
as a threat — no human in the loop, mirroring the ESP path."""

from __future__ import annotations

import asyncio

from app.models import EventType, LinkScanIn
from app.orchestrator import handle_link_scan
from app.state import AppState


async def _no_sleep(_: float) -> None:
    return None


def test_scan_emits_full_sequence_and_counts_threat() -> None:
    state = AppState()
    verdict = asyncio.run(
        handle_link_scan(
            state,
            LinkScanIn(url="https://ledger-livedsktpp.pages.dev/"),
            sleep=_no_sleep,
        )
    )
    assert verdict.verdict == "malicious"
    types = [e.type for e in state.events]
    assert EventType.LINK_SUBMITTED in types
    assert EventType.LINK_BROWSING in types
    assert EventType.LINK_RESEARCHING in types
    assert EventType.LINK_VERDICT in types
    assert state.counters.threats_detected == 1


def test_legit_link_is_not_counted_as_threat() -> None:
    state = AppState()
    verdict = asyncio.run(
        handle_link_scan(state, LinkScanIn(url="https://www.kraken.com/"), sleep=_no_sleep)
    )
    assert verdict.verdict == "legit"
    assert state.counters.threats_detected == 0
