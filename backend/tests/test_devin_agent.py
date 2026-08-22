"""DevinAgent drives v3 sessions correctly over a mocked transport (no network)."""

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


def _good_output() -> dict:
    return {
        "attack_class": "deauth_flood",
        "confidence": 0.9,
        "filter_c_code": DEAUTH,
        "explanation": "x",
    }


def test_call_returns_filter_that_passes_oracle():
    from app.oracle import run_oracle

    out = DevinAgent(client=build_mock_client()).call(_payload())
    assert out.attack_class == "deauth_flood"
    assert run_oracle(out.filter_c_code).passed is True


def test_streams_sandbox_steps_and_parses_self_test():
    steps: list[str] = []
    out = DevinAgent(client=build_mock_client()).call(_payload(), on_step=steps.append)
    # Devin's narration streamed once each (deduped by event_id across polls).
    assert len(steps) == 2
    assert any("compiled" in s for s in steps)
    # self-test evidence parsed from structured_output.
    assert out.iterations == 2
    assert out.self_tpr == 1.0
    assert out.self_fpr == 0.0
    assert out.compiled is True


def test_prompt_contains_frames_signature_and_spec():
    prompt = build_devin_prompt(_payload())
    assert "c0003a01ffffffffffff001122334455" in prompt
    assert "bool block_frame(const uint8_t *f, size_t n)" in prompt
    assert "filter_c_code" in prompt


def test_retry_sends_followup_message_and_reuses_session():
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        calls.append(f"{request.method} {path}")
        if request.method == "POST" and path.endswith("/messages"):
            return httpx.Response(200, json={"ok": True})
        if request.method == "POST" and path.endswith("/sessions"):
            return httpx.Response(200, json={"session_id": "s1", "url": "u", "status": "new"})
        return httpx.Response(
            200,
            json={
                "status": "running",
                "status_detail": "finished",
                "structured_output": _good_output(),
            },
        )

    agent = DevinAgent(
        client=DevinClient(api_key="k", org_id="o", transport=httpx.MockTransport(handler))
    )
    agent.call(_payload())  # opens session s1
    agent.call(_payload(failure_log="fpr=0.5 too many false positives", prev_filter=DEAUTH))

    assert any(c.endswith("/messages") for c in calls)
    # exactly one session created; the retry reuses it via a message.
    assert sum(1 for c in calls if c.endswith("/sessions")) == 1


def test_unparseable_output_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path.endswith("/sessions"):
            return httpx.Response(200, json={"session_id": "s1", "status": "new"})
        return httpx.Response(
            200,
            json={
                "status": "running",
                "status_detail": "finished",
                "structured_output": "not json {{",
            },
        )

    agent = DevinAgent(
        client=DevinClient(api_key="k", org_id="o", transport=httpx.MockTransport(handler))
    )
    with pytest.raises(DevinAgentError):
        agent.call(_payload())


def test_dead_session_without_output_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path.endswith("/sessions"):
            return httpx.Response(200, json={"session_id": "s1", "status": "new"})
        return httpx.Response(200, json={"status": "error", "structured_output": None})

    agent = DevinAgent(
        client=DevinClient(api_key="k", org_id="o", transport=httpx.MockTransport(handler))
    )
    with pytest.raises(DevinAgentError):
        agent.call(_payload())


def test_create_body_has_disposable_vm_and_acu_cap():
    bodies: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path.endswith("/sessions"):
            import json as _json

            bodies.append(_json.loads(request.content))
            return httpx.Response(200, json={"session_id": "s1", "status": "new"})
        return httpx.Response(
            200,
            json={
                "status": "running",
                "status_detail": "finished",
                "structured_output": _good_output(),
            },
        )

    agent = DevinAgent(
        client=DevinClient(api_key="k", org_id="o", transport=httpx.MockTransport(handler))
    )
    agent.call(_payload())
    assert bodies[0]["resumable"] is False  # disposable VM, no idle billing
    assert bodies[0]["max_acu_limit"] > 0  # hard cost ceiling


def test_terminate_issues_delete():
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        if request.method == "POST" and request.url.path.endswith("/sessions"):
            return httpx.Response(200, json={"session_id": "s1", "status": "new"})
        if request.method == "DELETE":
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(
            200,
            json={
                "status": "running",
                "status_detail": "finished",
                "structured_output": _good_output(),
            },
        )

    agent = DevinAgent(
        client=DevinClient(api_key="k", org_id="o", transport=httpx.MockTransport(handler))
    )
    agent.call(_payload())
    agent.terminate()
    assert "DELETE" in calls


def test_missing_key_without_client_raises(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "devin_api_key", "")
    with pytest.raises(DevinAgentError):
        DevinAgent()
