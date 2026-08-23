"""Test isolation: never emit telemetry to a real Langfuse during tests.

A developer .env may carry live Langfuse keys; without this, importing the app
would ship a trace per test to the local instance and spam it.
"""

import pytest


@pytest.fixture(autouse=True)
def _isolate_external(monkeypatch, tmp_path):
    """No test may touch a real Langfuse or a real Devin session."""
    from app import agents
    from app.config import settings

    monkeypatch.setattr(settings, "langfuse_public_key", "")
    monkeypatch.setattr(settings, "langfuse_secret_key", "")
    monkeypatch.setattr(settings, "agent", "stub")  # never resolve real Devin
    monkeypatch.setattr(settings, "email_agent", "stub")
    monkeypatch.setattr(settings, "email_security_enabled", False)
    monkeypatch.setattr(settings, "command_enabled", False)
    monkeypatch.setattr(settings, "command_agent", "stub")
    monkeypatch.setattr(settings, "attack_responses_path", str(tmp_path / "attack_responses.jsonl"))
    monkeypatch.setattr(settings, "scope_history_path", str(tmp_path / "scope_history.jsonl"))
    monkeypatch.setattr(settings, "command_db_path", str(tmp_path / "command.db"))
    agents.get_agent.cache_clear()
    yield
    agents.get_agent.cache_clear()
