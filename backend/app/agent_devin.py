"""DevinAgent — drives a real Devin session to write the C filter.

Behind the frozen AgentIn -> AgentOut contract, so it drops into the orchestrator
as a one-liner later. Standalone-runnable from the CLI (see __main__) with a
--mock mode that needs no API key or network.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import re
import time
from pathlib import Path
from typing import Any

import httpx

from . import tracing
from .config import settings
from .devin_client import DevinClient
from .models import AgentIn, AgentOut, AnomalyStats
from .prompts import STRUCTURED_OUTPUT_SCHEMA, build_devin_prompt

_FILTERS_DIR = Path(__file__).resolve().parent.parent / "oracle/filters"
_FIXTURES = Path(__file__).resolve().parent.parent / "oracle/fixtures"


class DevinAgentError(RuntimeError):
    """Devin failed to produce a usable filter (timeout / no key / bad output)."""


def _extract_json(raw: Any) -> dict[str, Any]:
    """structured_output may be a dict already, or a (possibly fenced) JSON string."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        text = raw.strip()
        fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
        if fenced:
            text = fenced.group(1)
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise DevinAgentError(f"structured_output is not valid JSON: {exc}") from exc
        if isinstance(parsed, dict):
            return parsed
    raise DevinAgentError(f"unexpected structured_output type: {type(raw).__name__}")


def _to_agent_out(data: dict[str, Any]) -> AgentOut:
    if "filter_c_code" not in data:
        raise DevinAgentError("structured_output missing 'filter_c_code'")
    return AgentOut(
        attack_class=str(data.get("attack_class", "unknown")),
        confidence=float(data.get("confidence", 0.0)),
        filter_c_code=str(data["filter_c_code"]),
        explanation=str(data.get("explanation", "")),
    )


class DevinAgent:
    def __init__(self, client: DevinClient | None = None) -> None:
        if client is None and not settings.devin_api_key:
            raise DevinAgentError("DEVIN_API_KEY is not set (use --mock or set .env)")
        self.client = client or DevinClient()
        self._session_id: str | None = None
        self.session_url: str | None = None
        self.last_acus: float | None = None
        self.last_usd: float | None = None
        self.last_cost_final: bool = False

    def call(self, payload: AgentIn) -> AgentOut:
        trace = tracing.start_trace(
            "devin.agent",
            input={"frame_hex": payload.frame_hex, "stats": payload.anomaly_stats.model_dump()},
        )

        # Retry path: reuse the open session with a follow-up message.
        if payload.failure_log and self._session_id:
            model_input = f"[retry] failure log:\n{payload.failure_log}"
            with tracing.span(
                trace, "devin.retry_message", input={"log": payload.failure_log[:2000]}
            ):
                self.client.send_message(
                    self._session_id,
                    "Independent verification failed. Fix filter.c.\n\n"
                    f"Failure log:\n{payload.failure_log}",
                )
        else:
            prompt = build_devin_prompt(payload)
            model_input = prompt
            session = self.client.create_session(
                prompt, structured_output_schema=STRUCTURED_OUTPUT_SCHEMA
            )
            self._session_id = session.session_id
            self.session_url = session.url

        session = self._poll(trace)
        data = _extract_json(session.structured_output)
        out = _to_agent_out(data)

        # Cost: acus_consumed is provisional while running. Re-fetch once to get
        # the latest value, and record whether it is final (session stopped).
        with contextlib.suppress(Exception):
            refreshed = self.client.get_session(session.session_id)
            if refreshed.acus_consumed is not None:
                session = refreshed
        self.last_acus = session.acus_consumed
        self.last_usd = (
            round(self.last_acus * settings.devin_usd_per_acu, 4)
            if self.last_acus is not None and settings.devin_usd_per_acu
            else None
        )
        cost_final = session.is_dead or session.status_detail == "finished"
        self.last_cost_final = cost_final
        meta = {
            "session_url": self.session_url,
            "status": session.status,
            "status_detail": session.status_detail,
            "acus_consumed": self.last_acus,
            "usd": self.last_usd,
            "cost_final": cost_final,
        }

        # Record the Devin session as a generation: prompt in, filter out, ACU cost.
        usage: dict[str, Any] = {"unit": "ACU", "total": self.last_acus or 0}
        if self.last_usd is not None:
            usage["totalCost"] = self.last_usd
        with tracing.generation(
            trace,
            "devin.session",
            model="devin",
            input=model_input,
            output=session.structured_output,
            metadata=meta,
            usage=usage,
        ):
            pass

        tracing.update_trace(
            trace,
            output={
                "attack_class": out.attack_class,
                "confidence": out.confidence,
                "explanation": out.explanation,
                "filter_c_code": out.filter_c_code,
            },
            metadata=meta,
        )
        if self.last_acus is not None:
            tracing.score(trace, "acus_consumed", self.last_acus)
        return out

    def terminate(self) -> None:
        """Tear down the current session's VM so it cannot idle-bill."""
        if self._session_id:
            with contextlib.suppress(Exception):
                self.client.terminate(self._session_id)
            self._session_id = None

    def _poll(self, trace: tracing.Trace) -> Any:
        assert self._session_id is not None
        deadline = time.monotonic() + settings.devin_timeout_s
        polls = 0
        while True:
            session = self.client.get_session(self._session_id)
            polls += 1
            if session.has_output:
                with tracing.span(
                    trace, "devin.poll_done", output={"polls": polls, "status": session.status}
                ):
                    pass
                return session
            if session.is_dead:
                raise DevinAgentError(
                    f"session {self._session_id} ended ({session.status}/"
                    f"{session.status_detail}) with no structured_output"
                )
            if time.monotonic() > deadline:
                raise DevinAgentError(
                    f"Devin session {self._session_id} timed out after {settings.devin_timeout_s}s"
                )
            time.sleep(settings.devin_poll_interval_s)


# --- offline mock client (no key / no network) ---------------------------
def build_mock_client(filter_code: str | None = None) -> DevinClient:
    """A DevinClient wired to a scripted transport returning a canned filter (v3 shapes)."""
    code = filter_code if filter_code is not None else (_FILTERS_DIR / "deauth.c").read_text()
    structured = {
        "attack_class": "deauth_flood",
        "confidence": 0.95,
        "filter_c_code": code,
        "explanation": "Blocks 802.11 mgmt deauth/disassoc frames; data/beacons pass.",
    }
    state = {"gets": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "DELETE":
            return httpx.Response(200, json={"ok": True})
        if request.method == "POST" and path.endswith("/messages"):
            return httpx.Response(200, json={"ok": True})
        if request.method == "POST" and path.endswith("/sessions"):
            return httpx.Response(
                200,
                json={
                    "session_id": "mock-session",
                    "url": "https://app.devin.ai/sessions/mock",
                    "status": "new",
                },
            )
        if request.method == "GET":
            state["gets"] += 1
            # First poll still running, then output appears — mimics real latency.
            if state["gets"] < 2:
                return httpx.Response(
                    200,
                    json={
                        "status": "running",
                        "status_detail": "working",
                        "structured_output": None,
                    },
                )
            return httpx.Response(
                200,
                json={
                    "status": "running",
                    "status_detail": "waiting_for_user",
                    "structured_output": structured,
                    "acus_consumed": 0.25,
                },
            )
        return httpx.Response(404, json={"error": "unmapped"})

    return DevinClient(api_key="mock", org_id="mock", transport=httpx.MockTransport(handler))


# --- standalone CLI -------------------------------------------------------
def _load_frames(args: argparse.Namespace) -> list[str]:
    if args.frames_file:
        lines = Path(args.frames_file).read_text().splitlines()
        return [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]
    # default --fixtures: the sample attack capture
    lines = (_FIXTURES / "attack.hex").read_text().splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Standalone Devin anomaly-defense agent")
    parser.add_argument("--frames-file", help="hex frames, one per line (default: sample fixtures)")
    parser.add_argument("--fixtures", action="store_true", help="use bundled sample attack frames")
    parser.add_argument("--mock", action="store_true", help="offline: no API key / network")
    parser.add_argument(
        "--no-verify", dest="verify", action="store_false", help="skip oracle verify"
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=0,
        help="on oracle FAIL, feed the log back to Devin and retry (needs --verify)",
    )
    parser.add_argument(
        "--keep-session",
        action="store_true",
        help="do not terminate the Devin session on exit (leave the VM for inspection)",
    )
    parser.set_defaults(verify=True)
    args = parser.parse_args(argv)

    frames = _load_frames(args)
    payload = AgentIn(
        frame_hex=frames,
        anomaly_stats=AnomalyStats(frame_type="mgmt", subtype=12, count_in_window=len(frames)),
    )

    agent = DevinAgent(client=build_mock_client() if args.mock else None)
    from .oracle import run_oracle

    rc = 0
    try:
        for attempt in range(args.retries + 1):
            try:
                out = agent.call(payload)
            except DevinAgentError as exc:
                print(f"❌ Devin agent failed: {exc}")
                rc = 1
                break

            print(f"\n=== attempt {attempt + 1} ===")
            print(f"attack_class : {out.attack_class}")
            print(f"confidence   : {out.confidence}")
            print(f"explanation  : {out.explanation}")
            if agent.session_url:
                print(f"session      : {agent.session_url}")
            if agent.last_acus is not None:
                final = "" if agent.last_cost_final else " (provisional)"
                usd = f" (~${agent.last_usd})" if agent.last_usd else ""
                print(f"cost         : {agent.last_acus} ACU{usd}{final}")
            print("---- filter.c ----")
            print(out.filter_c_code)
            print("------------------")

            if not args.verify:
                break

            verdict = run_oracle(out.filter_c_code)
            mark = "✅" if verdict.passed else "❌"
            print(
                f"{mark} oracle: passed={verdict.passed} tpr={verdict.tpr} fpr={verdict.fpr} "
                f"({verdict.tests_passed}/{verdict.tests_total})"
            )
            if verdict.passed or attempt == args.retries:
                break
            print("↻ feeding failure back to Devin for another attempt…")
            payload = AgentIn(
                frame_hex=frames,
                anomaly_stats=payload.anomaly_stats,
                prev_filter=out.filter_c_code,
                failure_log=verdict.log,
            )
    finally:
        if settings.devin_terminate_on_done and not args.keep_session:
            agent.terminate()
            print("session      : terminated (VM torn down, no idle cost)")
        if settings.langfuse_enabled:
            print(f"langfuse: trace(s) sent to {settings.langfuse_host}")
        tracing.flush()
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
