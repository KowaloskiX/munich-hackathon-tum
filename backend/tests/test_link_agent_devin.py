"""The devin scout synthesizes browse+research into one verdict — tested
offline against a scripted transport (no key, no network, no ACUs)."""

from __future__ import annotations

import pytest

from app import link_agent_devin
from app.link_agent_devin import build_mock_client, scan_link_devin
from app.models import LinkScanIn


@pytest.fixture(autouse=True)
def _fast_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(link_agent_devin.settings, "devin_poll_interval_s", 0.0)


def test_devin_scout_synthesizes_verdict_offline() -> None:
    client = build_mock_client()  # canned malicious verdict for both sessions
    v = scan_link_devin(LinkScanIn(url="https://ledger-livedsktpp.pages.dev/"), client=client)
    assert v.verdict == "malicious"
    assert v.legit_score < 0.35
    assert v.browse_score is not None
    assert v.research_score is not None


def test_devin_scout_streams_steps_offline() -> None:
    client = build_mock_client()
    steps: list[str] = []
    scan_link_devin(LinkScanIn(url="https://x.example/"), on_step=steps.append, client=client)
    assert steps
    assert any("verdict" in s for s in steps)
