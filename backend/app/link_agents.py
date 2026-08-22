"""Web-domain scout selection — resolves the configured link scout behind the
LinkScanIn -> LinkVerdict signature. Mirrors agents.get_agent for the ESP side.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import lru_cache

from .config import settings
from .link_scout import scan_link_stub
from .models import LinkScanIn, LinkVerdict

LinkScoutFn = Callable[..., LinkVerdict]  # (LinkScanIn, on_step=None) -> LinkVerdict


@lru_cache(maxsize=1)
def get_link_scout() -> LinkScoutFn:
    """Return the configured scout: stub (default) or devin."""
    if settings.link_agent == "devin":
        from .link_agent_devin import scan_link_devin

        return scan_link_devin
    return scan_link_stub


def scan_link(payload: LinkScanIn) -> LinkVerdict:
    """Convenience passthrough to the configured scout."""
    return get_link_scout()(payload)
