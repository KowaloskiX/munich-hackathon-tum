"""The web-domain scout's verdict is deterministic and offline (stub)."""

from __future__ import annotations

from app.link_scout import scan_link
from app.models import LinkScanIn


def test_official_domain_is_legit() -> None:
    v = scan_link(LinkScanIn(url="https://www.ledger.com/"))
    assert v.verdict == "legit"
    assert v.legit_score >= 0.9
    assert v.impersonated_brand == ""


def test_throwaway_brand_clone_is_malicious() -> None:
    v = scan_link(LinkScanIn(url="https://ledger-livedsktpp.pages.dev/"))
    assert v.verdict == "malicious"
    assert v.impersonated_brand == "ledger.com"
    assert v.legit_score < 0.2


def test_records_narration_steps() -> None:
    steps: list[str] = []
    scan_link(LinkScanIn(url="http://kraknkrakenlogn.webflow.io/"), on_step=steps.append)
    assert steps
    assert any("verdict" in s for s in steps)
