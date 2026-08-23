"""DevinAgent drives v3 sessions correctly over a mocked transport (no network)."""

from pathlib import Path

import httpx
import pytest

from app.agent_devin import DevinAgent, DevinAgentError, _clean_c, build_mock_client
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


def test_clean_c_strips_markdown_fences():
    body = "bool block_frame(const uint8_t *f, size_t n){return false;}"
    assert _clean_c(f"Here you go:\n```c\n{body}\n```\n") == body
    plain = "bool block_frame(const uint8_t *f, size_t n){return true;}"
    assert _clean_c(plain) == plain


def test_call_returns_filter_that_passes_oracle():
    from app.oracle import run_oracle

    out = DevinAgent(client=build_mock_client()).call(_payload())
    assert out.attack_class == "deauth_flood"
    assert run_oracle(out.filter_c_code).passed is True


def test_streams_sandbox_steps_and_parses_self_test():
    steps: list[str] = []
    out = DevinAgent(client=build_mock_client()).call(_payload(), on_step=steps.append)
    # Devin's narration streamed once each (deduped by event_id across polls);
    # progress heartbeats (⏳) are separate and excluded here.
    narration = [s for s in steps if not s.startswith("⏳")]
    assert len(narration) == 2
    assert any("compiled" in s for s in narration)
    assert any(s.startswith("⏳") for s in steps)  # heartbeat present too
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


def test_prompt_requires_existing_protections_to_survive_adaptation():
    prompt = build_devin_prompt(_payload(prev_filter=DEAUTH))

    assert "Existing deployed protection" in prompt
    assert "Preserve every attack subtype" in prompt
    assert DEAUTH in prompt


def test_prompt_forbids_preemptively_blocking_future_demo_subtypes():
    prompt = build_devin_prompt(_payload(prev_filter=DEAUTH))

    assert "Do not proactively block" in prompt
    assert "future attack stage" in prompt


def test_prompt_self_test_includes_current_non_deauth_capture():
    auth = "b0003a01ffffffffffff001122334455"
    payload = AgentIn(
        frame_hex=[auth],
        anomaly_stats=AnomalyStats(subtype=11, count_in_window=200),
    )
    prompt = build_devin_prompt(payload)
    attack_section = prompt.split("attack.hex:", 1)[1].split("benign.hex:", 1)[0]

    assert auth in attack_section


def test_prompt_classifies_from_current_capture_not_regression_samples():
    prompt = build_devin_prompt(_payload())

    assert "Use only the current captured anomaly to classify" in prompt
    assert "not evidence of the current attack" in prompt


def test_poll_ignores_intermediate_output_until_session_finishes(monkeypatch):
    polls = 0
    from app.agent_devin import settings

    monkeypatch.setattr(settings, "devin_poll_interval_s", 0)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal polls
        if request.method == "POST" and request.url.path.endswith("/sessions"):
            return httpx.Response(200, json={"session_id": "s1", "status": "new"})
        polls += 1
        if polls == 1:
            draft = _good_output()
            draft["attack_class"] = "deauth_flood"
            draft["filter_c_code"] = "/* incomplete progress draft */"
            return httpx.Response(
                200,
                json={
                    "session_id": "s1",
                    "status": "running",
                    "status_detail": "working",
                    "structured_output": draft,
                },
            )
        final = _good_output()
        final["attack_class"] = "auth_flood"
        return httpx.Response(
            200,
            json={
                "session_id": "s1",
                "status": "running",
                "status_detail": "finished",
                "structured_output": final,
            },
        )

    agent = DevinAgent(
        client=DevinClient(api_key="k", org_id="o", transport=httpx.MockTransport(handler))
    )
    out = agent.call(_payload())

    assert polls >= 2
    assert out.attack_class == "auth_flood"
    assert out.filter_c_code == DEAUTH.strip()


def test_retry_waits_for_revised_output_from_reused_session(monkeypatch):
    calls: list[str] = []
    state = {"retry": False, "retry_gets": 0}
    from app.agent_devin import settings

    monkeypatch.setattr(settings, "devin_poll_interval_s", 0)

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        calls.append(f"{request.method} {path}")
        if request.method == "POST" and path.endswith("/messages"):
            state["retry"] = True
            return httpx.Response(200, json={"ok": True})
        if request.method == "POST" and path.endswith("/sessions"):
            return httpx.Response(200, json={"session_id": "s1", "url": "u", "status": "new"})
        output = _good_output()
        if state["retry"]:
            state["retry_gets"] += 1
            if state["retry_gets"] > 1:
                output["explanation"] = "revised after independent oracle failure"
        return httpx.Response(
            200,
            json={
                "status": "running",
                "status_detail": "finished",
                "structured_output": output,
            },
        )

    agent = DevinAgent(
        client=DevinClient(api_key="k", org_id="o", transport=httpx.MockTransport(handler))
    )
    agent.call(_payload())  # opens session s1
    retried = agent.call(
        _payload(failure_log="fpr=0.5 too many false positives", prev_filter=DEAUTH)
    )

    assert any(c.endswith("/messages") for c in calls)
    # exactly one session created; the retry reuses it via a message.
    assert sum(1 for c in calls if c.endswith("/sessions")) == 1
    assert state["retry_gets"] >= 2
    assert retried.explanation == "revised after independent oracle failure"


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
