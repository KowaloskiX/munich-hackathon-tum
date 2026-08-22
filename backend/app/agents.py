"""Agent selection — resolves the configured agent behind the AgentIn->AgentOut
contract. Wired into the orchestrator at integration (Step 5.2); standalone now.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import lru_cache

from .agent_stub import call_agent as _stub_call
from .config import settings
from .models import AgentIn, AgentOut

AgentFn = Callable[..., AgentOut]  # (AgentIn, on_step=None) -> AgentOut


@lru_cache(maxsize=1)
def get_agent() -> AgentFn:
    """Return the configured agent callable: stub (default) or devin."""
    if settings.agent == "devin":
        from .agent_devin import DevinAgent

        agent = DevinAgent()
        return agent.call
    return _stub_call


def call_agent(payload: AgentIn) -> AgentOut:
    """Convenience passthrough to the configured agent."""
    return get_agent()(payload)
