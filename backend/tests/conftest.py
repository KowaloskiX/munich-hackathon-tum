"""Test isolation: never emit telemetry to a real Langfuse during tests.

A developer .env may carry live Langfuse keys; without this, importing the app
would ship a trace per test to the local instance and spam it.
"""

import pytest


@pytest.fixture(autouse=True)
def _isolate_external(monkeypatch):
    """No test may touch a real Langfuse or a real Devin session."""
    from app import agents
    from app.config import settings

    monkeypatch.setattr(settings, "langfuse_public_key", "")
    monkeypatch.setattr(settings, "langfuse_secret_key", "")
    monkeypatch.setattr(settings, "agent", "stub")  # never resolve real Devin
    agents.get_agent.cache_clear()
    yield
    agents.get_agent.cache_clear()
