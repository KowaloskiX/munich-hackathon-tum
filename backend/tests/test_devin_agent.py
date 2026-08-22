"""DevinAgent drives sessions correctly over a mocked transport (no network)."""

import json
from pathlib import Path

import httpx
import pytest

from app.agent_devin import DevinAgent, DevinAgentError, build_mock_client
from app.devin_client import DevinClient
from app.models import AgentIn, AnomalyStats
from app.prompts import build_devin_prompt

DEAUTH = (Path(__file__).resolve().parent.parent / "oracle/filters/deauth.c").read_text()


def _payload(**kw) -> AgentIn:
    return AgentIn(
        frame_hex=["c0003a01ffffffffffff001122334455"],
        anomaly_stats=AnomalyStats(subtype=12, count_in_window=200),
        **kw,
    )


def test_call_returns_filter_that_passes_oracle():
    from app.oracle import run_oracle

    out = DevinAgent(client=build_mock_client()).call(_payload())
    assert out.attack_class == "deauth_flood"
    assert run_oracle(out.filter_c_code).passed is True


def test_prompt_contains_frames_signature_and_spec():
    prompt = build_devin_prompt(_payload())
    assert "c0003a01ffffffffffff001122334455" in prompt
    assert "bool block_frame(const uint8_t *f, size_t n)" in prompt
    assert "filter_c_code" in prompt


def test_retry_sends_followup_message_and_repolls():
    calls: list[str] = []
    good = json.dumps(
        {
            "attack_class": "deauth_flood",
            "confidence": 0.9,
            "filter_c_code": DEAUTH,
            "explanation": "x",
        }
    )

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        calls.append(f"{request.method} {path}")
        if request.method == "POST" and path.endswith("/sessions"):
            return httpx.Response(200, json={"session_id": "s1", "url": "u"})
        if request.method == "POST" and path.endswith("/message"):
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(200, json={"status_enum": "finished", "structured_output": good})

    agent = DevinAgent(client=DevinClient(api_key="k", transport=httpx.MockTransport(handler)))
    agent.call(_payload())  # opens session s1
    agent.call(_payload(failure_log="fpr=0.5 too many false positives", prev_filter=DEAUTH))

    assert any(c.endswith("/session/s1/message") for c in calls)
    # exactly one session created, message used for the retry
    assert sum(1 for c in calls if c.endswith("/sessions")) == 1


def test_unparseable_output_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path.endswith("/sessions"):
            return httpx.Response(200, json={"session_id": "s1"})
        return httpx.Response(
            200, json={"status_enum": "finished", "structured_output": "not json {{"}
        )

    agent = DevinAgent(client=DevinClient(api_key="k", transport=httpx.MockTransport(handler)))
    with pytest.raises(DevinAgentError):
        agent.call(_payload())


def test_missing_key_without_client_raises():
    # settings.devin_api_key is empty in the test env -> constructing without a client fails.
    with pytest.raises(DevinAgentError):
        DevinAgent()
