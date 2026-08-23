"""Link/URL legitimacy scout — the web domain's detector (2nd domain).

Mirrors the ESP agent's role: given a suspicious URL it returns a structured
verdict (LinkVerdict). Default is an offline heuristic stub; a real two-agent
(browse + research) Devin backend slots in behind the same signature later.

Kept a leaf like the ESP agent (see tests/test_layering.py): it must not reach
the oracle, the orchestrator, or the live fleet state.
"""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlparse

from .models import LinkScanIn, LinkVerdict

StepFn = Callable[[str], None]

# Free/throwaway hosting a real brand would never use for its primary site.
THROWAWAY_HOSTS: tuple[str, ...] = (
    "vercel.app",
    "pages.dev",
    "webflow.io",
    "framer.website",
    "netlify.app",
    "blogspot.com",
    "glitch.me",
    "onrender.com",
)

# brand token -> official registrable domain.
KNOWN_BRANDS: dict[str, str] = {
    "ledger": "ledger.com",
    "kraken": "kraken.com",
    "citibank": "citi.com",
    "citi": "citi.com",
    "netflix": "netflix.com",
    "paypal": "paypal.com",
    "dhl": "dhl.com",
    "coinbase": "coinbase.com",
}


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def scan_link_stub(scan: LinkScanIn, on_step: StepFn | None = None) -> LinkVerdict:
    """Offline heuristic verdict: host/brand/throwaway analysis, no live fetch.

    Deterministic so it drives tests and the mock demo without a network. The
    real browse+research Devin scout replaces this behind the same signature.
    """

    def step(msg: str) -> None:
        if on_step is not None:
            on_step(msg)

    host = _host(scan.url)
    flat = host.replace(".", "")
    signals: list[str] = []

    step(f"browse: opening {scan.url}")
    throwaway = next((h for h in THROWAWAY_HOSTS if host.endswith(h)), None)
    brand = next((b for b in KNOWN_BRANDS if b in flat), "")
    official = KNOWN_BRANDS.get(brand, "")
    impersonates = bool(brand and official and not host.endswith(official))

    step("research: checking reputation / domain ownership")
    if throwaway:
        signals.append(f"hosted on throwaway platform {throwaway}")
    if impersonates:
        signals.append(f"host references brand '{brand}' but is not its domain {official}")

    if impersonates and throwaway:
        verdict, score = "malicious", 0.04
    elif impersonates or throwaway:
        verdict, score = "suspicious", 0.4
    elif official and host.endswith(official):
        verdict, score = "legit", 0.96
        signals.append(f"official registrable domain {official}")
    else:
        verdict, score = "legit", 0.7
        signals.append("no impersonation or throwaway-host signals")

    step(f"verdict: {verdict} ({score})")
    return LinkVerdict(
        url=scan.url,
        verdict=verdict,
        legit_score=score,
        impersonated_brand=(official if impersonates else ""),
        top_signals=signals,
        reasoning="heuristic stub: host/brand/throwaway analysis (no live fetch)",
        browse_score=score,
        research_score=score,
    )


# The configured scout. A devin-backed two-agent implementation slots in here
# behind the same (LinkScanIn, on_step) -> LinkVerdict signature.
scan_link = scan_link_stub
