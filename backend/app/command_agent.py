"""COMMAND agent: autonomous cross-domain assessment and report drafting."""

from __future__ import annotations

import contextlib
import json
import time
from collections.abc import Callable
from typing import Any

from .config import settings
from .devin_client import DevinClient
from .models import (
    AttackerContextFinding,
    CommandCorrelation,
    CommandDecision,
    CommandMetrics,
    EmployeeAdvisory,
    IntelligenceObservation,
)

StepFn = Callable[[str], None]


class CommandAgentError(RuntimeError):
    pass


def _evidence_packet(observations: list[IntelligenceObservation], metrics: CommandMetrics) -> str:
    return json.dumps(
        {
            "metrics": metrics.model_dump(mode="json"),
            "observations": [item.model_dump(mode="json") for item in observations],
        },
        separators=(",", ":"),
    )


def command_stub(
    observations: list[IntelligenceObservation],
    metrics: CommandMetrics,
    on_step: StepFn | None = None,
    failure_log: str | None = None,
) -> tuple[CommandDecision, str | None]:
    del failure_log
    if on_step:
        on_step("COMMAND compared current activity with the seven-day baseline")
    required = (
        metrics.phishing_spike or metrics.signal_incidents > 0 or metrics.malicious_scope_checks > 0
    )
    ids = [item.id for item in observations[:30]]
    shared = metrics.shared_entities[0] if metrics.shared_entities else ""
    correlations = (
        [
            CommandCorrelation(
                claim=f"Entity {shared} appears across security surfaces",
                confidence=0.82,
                evidence_ids=[
                    item.id
                    for item in observations
                    if shared in str(item.entities.model_dump()).casefold()
                ][:8],
                explanation="Independent observations reference the same normalized entity.",
            )
        ]
        if shared
        else []
    )
    if not required:
        return CommandDecision(
            decision="NO_REPORT", reason="No material deviation from baseline"
        ), None
    if on_step:
        on_step("COMMAND found reportable activity and assembled cited evidence")
    domains = sorted({domain for item in observations for domain in item.entities.domains})
    context = [
        AttackerContextFinding(
            entity=domain,
            finding=(
                "Domain appears in flagged campaign evidence; ownership requires "
                "independent confirmation."
            ),
            confidence=0.68,
            evidence_ids=[item.id for item in observations if domain in item.entities.domains][:8],
        )
        for domain in domains[:3]
    ]
    spike = (
        f"Flagged email activity rose to {metrics.email_current_flagged}/"
        f"{metrics.email_current_total} today from {metrics.email_baseline_flagged}/"
        f"{metrics.email_baseline_total} in the prior seven-day baseline."
    )
    decision = CommandDecision(
        decision="CREATE_REPORT",
        reason="Phishing spike or material security incident crossed the reporting threshold",
        urgency="CRITICAL" if metrics.signal_incidents and metrics.phishing_spike else "HIGH",
        title="Coordinated security activity requires company response",
        executive_summary=spike,
        what_happened=[spike, f"SIGNAL recorded {metrics.signal_incidents} network incident(s)."],
        cause_analysis=[
            "Observed activity is consistent with credential-harvesting and access "
            "probing; attribution remains unconfirmed."
        ],
        correlations=correlations,
        attacker_context=context,
        actions_taken=[
            item.summary for item in observations if item.source.value == "SIGNAL" and item.summary
        ][:5],
        recommendations=[
            "Warn employees about current credential-phishing themes and direct them "
            "to SCOPE before opening unfamiliar links.",
            "Preserve email headers, link evidence, and network captures for "
            "follow-up investigation.",
            "Monitor for repeated domains, senders, and authentication anomalies "
            "over the next 24 hours.",
        ],
        evidence_ids=ids,
        confidence=0.88,
        employee_advisory=EmployeeAdvisory(
            needed=metrics.phishing_spike,
            subject="Security notice: increased phishing activity detected",
            body=(
                "We detected an increase in fraudulent email activity. Do not enter credentials "
                "after following an unexpected link. Verify unfamiliar links with "
                "SCOPE and report suspicious messages."
            ),
        ),
    )
    return decision, None


def command_devin(
    observations: list[IntelligenceObservation],
    metrics: CommandMetrics,
    on_step: StepFn | None = None,
    failure_log: str | None = None,
    client: DevinClient | None = None,
) -> tuple[CommandDecision, str | None]:
    if client is None and not settings.devin_api_key:
        raise CommandAgentError("DEVIN_API_KEY is not set")
    client = client or DevinClient()
    packet = _evidence_packet(observations, metrics)
    correction = f"\nPrevious draft failed verification:\n{failure_log}\n" if failure_log else ""
    prompt = f"""You are COMMAND, the autonomous security lead for a company.
Assess the typed evidence packet below after a newly completed security activity.
Decide whether the company needs a separate report. Research exposed domains, URLs,
IPs, hosting, registration, brand impersonation, and campaign context as far as the
available sandbox and internet allow. Never claim a real-world attacker identity
without evidence. MAC/BSSID values are spoofable context, not attribution.

Every factual correlation must cite observation IDs from the packet. External research
must include http(s) source URLs. Explain patches, failed approaches, independent oracle
verification, deployments, phishing changes against baseline, and employee guidance.
Return only the required structured CommandDecision. A material spike, critical incident,
failed patch, or cross-surface entity should normally create a report.{correction}

EVIDENCE PACKET:
{packet}
"""
    session = client.create_session(
        prompt,
        structured_output_schema=CommandDecision.model_json_schema(),
        title="COMMAND cross-domain security assessment",
        tags=["command", "security-report"],
        max_acu_limit=settings.command_max_acu_limit,
        bypass_approval=True,
    )
    deadline = time.monotonic() + settings.command_timeout_s
    last_detail = ""
    final = session
    try:
        while True:
            final = client.get_session(session.session_id)
            if final.status_detail and final.status_detail != last_detail and on_step:
                last_detail = final.status_detail
                on_step(f"COMMAND Devin: {last_detail}")
            if final.has_output:
                raw: Any = final.structured_output
                if isinstance(raw, str):
                    raw = json.loads(raw)
                return CommandDecision.model_validate(raw), session.url
            if final.is_dead:
                raise CommandAgentError(f"COMMAND Devin ended with status {final.status}")
            if time.monotonic() > deadline:
                raise CommandAgentError("COMMAND Devin timed out")
            time.sleep(settings.command_poll_interval_s)
    finally:
        if settings.devin_terminate_on_done:
            with contextlib.suppress(Exception):
                client.terminate(session.session_id)
