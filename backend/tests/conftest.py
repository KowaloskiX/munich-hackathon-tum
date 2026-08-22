"""Test isolation: never emit telemetry to a real Langfuse during tests.

A developer .env may carry live Langfuse keys; without this, importing the app
would ship a trace per test to the local instance and spam it.
"""

import pytest


@pytest.fixture(autouse=True)
def _disable_langfuse():
    from app.config import settings

    settings.langfuse_public_key = ""
    settings.langfuse_secret_key = ""
    yield
