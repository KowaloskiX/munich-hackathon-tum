"""Devin-backed two-agent link scout (browse + research).

Behind the same `(LinkScanIn, on_step) -> LinkVerdict` signature as the stub, so
it drops in via LINK_AGENT=devin. One Devin session walks the site, a second
researches its reputation; their scores are synthesized into one verdict. Any
URL gets a real semantic verdict, not a host heuristic.

Leaf module (see tests/test_layering.py): no oracle/orchestrator/state imports.
The DevinClient is injectable so tests run offline against a MockTransport.
"""

from __future__ import annotations

import contextlib
import json
import re
import time
from collections.abc import Callable
from typing import Any

import httpx

from .config import settings
from .devin_client import DevinClient, DevinSession
from .models import LinkScanIn, LinkVerdict

StepFn = Callable[[str], None]


class LinkScoutError(RuntimeError):
    """Devin failed to produce a usable link verdict (timeout / dead / bad output)."""


LINK_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string"},
        "legit_score": {"type": "number"},
        "impersonated_brand": {"type": "string"},
        "top_signals": {"type": "array", "items": {"type": "string"}},
        "reasoning": {"type": "string"},
    },
    "required": ["verdict", "legit_score", "reasoning"],
}

BROWSE_PROMPT = (
    "You are a defensive web-safety analyst in a sandboxed VM (safe to open risky "
    "pages). Open this URL and navigate it: {url}\n\n"
    "Click through the pages you find (home, login, about, contact, terms/privacy, "
    "and any wallet-connect / seed-phrase / login / payment form). Decide, ONLY from "
    "what you directly observe, whether this is the LEGITIMATE first-party site for "
    "its apparent brand or a phishing / impersonation clone. Weigh where forms submit "
    "(same registrable domain vs foreign), TLS, the domain vs the brand's real domain, "
    "content depth, broken/placeholder pages, and any request for credentials or a "
    "crypto seed phrase. Observation only — no external reputation services.\n"
    "Return the structured verdict. legit_score: 1.0 = clearly legit, 0.0 = clearly malicious."
)

RESEARCH_PROMPT = (
    "You are a defensive web-safety analyst. WITHOUT loading the target in a browser, "
    "assess the reputation of this URL via web search / OSINT: {url}\n\n"
    "Check domain age / WHOIS / registrar; whether this is the brand's official domain "
    "or a lookalike; presence on phishing blocklists (PhishTank, OpenPhish, URLhaus, "
    "Google Safe Browsing); scam reports; and whether it is on a throwaway host "
    "(vercel.app, pages.dev, webflow.io) while claiming to be a known brand. Identify "
    "any impersonated brand and whether that brand owns this domain.\n"
    "Return the structured verdict. legit_score: 1.0 = clearly legit, 0.0 = clearly malicious."
)


def _parse(raw: Any) -> dict[str, Any] | None:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        text = raw.strip()
        fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
        if fenced:
            text = fenced.group(1)
        with contextlib.suppress(json.JSONDecodeError):
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
    return None


def _looks_final(out: dict[str, Any] | None) -> bool:
    """Devin sometimes fills the schema early with an interim placeholder
    ('Investigation in progress'). Treat only a settled verdict as done."""
    if out is None:
        return False
    return "progress" not in str(out.get("verdict", "")).lower()


def _score(out: dict[str, Any]) -> float:
    try:
        return float(out.get("legit_score", 0.5))
    except (TypeError, ValueError):
        return 0.5


def _combine(
    url: str,
    browse: dict[str, Any] | None,
    research: dict[str, Any] | None,
    browse_session_url: str | None = None,
    research_session_url: str | None = None,
) -> LinkVerdict:
    scores = [_score(o) for o in (browse, research) if o is not None]
    avg = sum(scores) / len(scores) if scores else 0.5
    verdict = "legit" if avg >= 0.65 else "suspicious" if avg >= 0.35 else "malicious"
    brand = ""
    signals: list[str] = []
    for o in (browse, research):
        if not o:
            continue
        brand = brand or str(o.get("impersonated_brand", "") or "")
        signals.extend(str(s) for s in (o.get("top_signals") or []))
    reason = "; ".join(
        f"{name}: {o.get('verdict')}"
        for name, o in (("browse", browse), ("research", research))
        if o
    )
    return LinkVerdict(
        url=url,
        verdict=verdict,
        legit_score=round(avg, 3),
        impersonated_brand=brand,
        top_signals=signals[:8],
        reasoning=reason or "no agent output",
        browse_score=_score(browse) if browse else None,
        research_score=_score(research) if research else None,
        browse_session_url=browse_session_url,
        research_session_url=research_session_url,
        browse_result=browse or {},
        research_result=research or {},
    )


def _poll_both(
    client: DevinClient, ids: dict[str, str], on_step: StepFn | None
) -> dict[str, dict[str, Any] | None]:
    deadline = time.monotonic() + settings.devin_timeout_s
    out: dict[str, dict[str, Any] | None] = {}
    while len(out) < len(ids):
        for label, sid in ids.items():
            if label in out:
                continue
            session: DevinSession = client.get_session(sid)
            parsed = _parse(session.structured_output)
            if session.has_output and _looks_final(parsed):
                out[label] = parsed
                if on_step is not None:
                    on_step(f"{label} verdict: {parsed.get('verdict') if parsed else '?'}")
            elif session.is_dead:
                out[label] = None
                if on_step is not None:
                    on_step(f"{label} session ended with no verdict")
        if len(out) == len(ids):
            break
        if time.monotonic() > deadline:
            for label in ids:
                out.setdefault(label, None)
            break
        time.sleep(settings.devin_poll_interval_s)
    return out


def scan_link_devin(
    scan: LinkScanIn,
    on_step: StepFn | None = None,
    client: DevinClient | None = None,
) -> LinkVerdict:
    if client is None and not settings.devin_api_key:
        raise LinkScoutError("DEVIN_API_KEY is not set (use LINK_AGENT=stub or set .env)")
    client = client or DevinClient()

    def step(msg: str) -> None:
        if on_step is not None:
            on_step(msg)

    step(f"browse: dispatching Devin on {scan.url}")
    browse = client.create_session(
        BROWSE_PROMPT.format(url=scan.url), structured_output_schema=LINK_SCHEMA
    )
    step(f"research: dispatching Devin on {scan.url}")
    research = client.create_session(
        RESEARCH_PROMPT.format(url=scan.url), structured_output_schema=LINK_SCHEMA
    )

    ids = {"browse": browse.session_id, "research": research.session_id}
    results = _poll_both(client, ids, on_step)

    if settings.devin_terminate_on_done:
        for sid in ids.values():
            with contextlib.suppress(Exception):
                client.terminate(sid)

    return _combine(
        scan.url,
        results["browse"],
        results["research"],
        browse.url,
        research.url,
    )


# --- offline mock client (no key / no network) — for tests ---------------
def build_mock_client(structured: dict[str, Any] | None = None) -> DevinClient:
    """A DevinClient wired to a scripted transport returning a canned verdict."""
    out = structured or {
        "verdict": "malicious",
        "legit_score": 0.03,
        "impersonated_brand": "ledger.com",
        "top_signals": ["throwaway host pages.dev", "not the official domain"],
        "reasoning": "brand-impersonation clone on a throwaway host",
    }
    gets = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "DELETE":
            return httpx.Response(200, json={"ok": True})
        if request.method == "POST" and path.endswith("/sessions"):
            sid = f"mock-{gets['n']}-{path[-1]}"
            return httpx.Response(
                200, json={"session_id": sid, "url": "https://app.devin.ai/x", "status": "new"}
            )
        if request.method == "GET":
            gets["n"] += 1
            if gets["n"] < 2:  # first poll still running
                return httpx.Response(200, json={"status": "running", "structured_output": None})
            return httpx.Response(
                200,
                json={
                    "status": "running",
                    "status_detail": "waiting_for_user",
                    "structured_output": out,
                },
            )
        return httpx.Response(404, json={"error": "unmapped"})

    return DevinClient(api_key="mock", org_id="mock", transport=httpx.MockTransport(handler))
