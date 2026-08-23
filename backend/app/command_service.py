"""COMMAND orchestration: normalize evidence, assess, verify, and persist reports."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import time
from collections.abc import Callable
from email.utils import parseaddr
from functools import partial
from pathlib import Path
from urllib.parse import urlparse

from .attack_log import read_attack_responses
from .command_agent import command_devin, command_stub
from .config import settings
from .intelligence_store import IntelligenceStore
from .models import (
    AttackResponseLog,
    CommandDecision,
    CommandDemoSeedResult,
    CommandMetrics,
    CommandOverview,
    CommandReport,
    EmailAnalysisDetail,
    EmailPayload,
    EvidenceEntities,
    EvidenceProvenance,
    EvidenceSource,
    IncidentSeverity,
    IntelligenceObservation,
    ScopeHistoryLog,
    ScopeToolCall,
    ThreatReport,
)
from .scope_log import append_scope_history, read_scope_history

StepFn = Callable[[str], None]
CommandAgentFn = Callable[..., tuple[CommandDecision, str | None]]


def _fingerprint(*parts: object) -> str:
    return hashlib.sha256("|".join(str(part) for part in parts).encode()).hexdigest()


def _domain(value: str) -> str:
    candidate = value.rsplit("@", 1)[-1] if "@" in value else value
    return (urlparse(candidate).hostname or candidate).casefold().strip(' <>"')


def _email_address(value: str) -> str:
    address = parseaddr(value)[1].casefold().strip()
    return address if "@" in address and _domain(address) else ""


def _email_addresses(payload: EmailPayload) -> list[str]:
    return sorted(
        filter(
            None,
            {
                _email_address(payload.from_address),
                _email_address(payload.reply_to),
                _email_address(payload.return_path),
            },
        )
    )


def _public_ips(value: str) -> list[str]:
    addresses: set[str] = set()
    for token in re.split(r"[\s,;=()\[\]<>]+", value):
        try:
            address = ipaddress.ip_address(token.strip(".\"'"))
        except ValueError:
            continue
        if address.is_global:
            addresses.add(address.compressed)
    return sorted(addresses)


def mandatory_report_reasons(
    observations: list[IntelligenceObservation], metrics: CommandMetrics
) -> list[str]:
    reasons: list[str] = []
    if metrics.phishing_spike:
        reasons.append("flagged email activity materially exceeds the seven-day baseline")
    if any(item.source is EvidenceSource.SIGNAL for item in observations):
        reasons.append("a network attack response completed")
    if any(
        item.source is EvidenceSource.SCOPE and item.verdict == "malicious" for item in observations
    ):
        reasons.append("SCOPE recorded a malicious destination")
    if any((item.risk_score or 0) >= 90 for item in observations):
        reasons.append("evidence reached critical risk score 90 or higher")
    if metrics.shared_entities:
        reasons.append("the same entity appears across multiple security surfaces")
    return reasons


def verify_command_decision(
    decision: CommandDecision,
    observations: list[IntelligenceObservation],
    metrics: CommandMetrics,
) -> list[str]:
    errors: list[str] = []
    required = mandatory_report_reasons(observations, metrics)
    valid_ids = {item.id for item in observations}
    cited_ids = set(decision.evidence_ids)
    for correlation in decision.correlations:
        cited_ids.update(correlation.evidence_ids)
        if not correlation.evidence_ids:
            errors.append(f"correlation has no evidence IDs: {correlation.claim}")
    for finding in decision.attacker_context:
        cited_ids.update(finding.evidence_ids)
        if not finding.evidence_ids and not finding.sources:
            errors.append(f"attacker-context finding is uncited: {finding.entity}")
        if any(urlparse(source).scheme not in {"http", "https"} for source in finding.sources):
            errors.append(f"research source is not an HTTP(S) URL: {finding.entity}")
    unknown = cited_ids - valid_ids
    if unknown:
        errors.append(f"unknown evidence IDs: {sorted(unknown)}")
    if required and decision.decision != "CREATE_REPORT":
        errors.append("report is mandatory: " + "; ".join(required))
    if decision.decision == "CREATE_REPORT":
        if not decision.title or not decision.executive_summary:
            errors.append("report title and executive summary are required")
        if not cited_ids:
            errors.append("report cites no evidence")
        if not decision.recommendations:
            errors.append("report contains no recommended actions")
        has_observable_entities = any(
            (
                item.source is EvidenceSource.SIGNAL
                or item.verdict.casefold() in {"flagged", "malicious", "inconclusive"}
                or (item.risk_score or 0) >= 70
            )
            and any(
                (
                    item.entities.domains,
                    item.entities.urls,
                    item.entities.ips,
                    item.entities.macs,
                    item.entities.emails,
                )
            )
            for item in observations
        )
        if has_observable_entities and not decision.attacker_context:
            errors.append("report omits attacker-context analysis")
    return errors


class CommandService:
    def __init__(
        self,
        *,
        store: IntelligenceStore | None = None,
        agent: CommandAgentFn | None = None,
    ) -> None:
        self.store = store or IntelligenceStore(settings.command_db_path)
        self.agent = agent or (command_devin if settings.command_agent == "devin" else command_stub)
        self.progress = ""

    def record_attack(self, response: AttackResponseLog, *, trigger: bool = True) -> int:
        capture = response.capture
        attempts = [
            {
                "attempt_number": item.attempt_number,
                "outcome": item.outcome,
                "approach_summary": item.approach_summary,
                "failure_reason": item.failure_reason,
                "oracle": item.oracle.model_dump(mode="json") if item.oracle else None,
                "filter_sha256": item.filter_sha256,
                "duration_ms": item.duration_ms,
                "session_url": item.session_url,
            }
            for item in response.attempts
        ]
        macs = [value for value in (capture.bssid, capture.sender_mac) if value]
        summary = (
            f"{response.summary.attack_type}: {response.outcome or 'unfinished'}; "
            f"{len(response.attempts)} patch attempt(s), deployment {response.deployment.status}."
        )
        observation = IntelligenceObservation(
            occurred_ts=response.detected_ts,
            recorded_ts=time.time(),
            source=EvidenceSource.SIGNAL,
            event_type="ATTACK_RESPONSE",
            severity=(
                IncidentSeverity.WARNING
                if str(response.outcome) == "deployed"
                else IncidentSeverity.CRITICAL
            ),
            title=f"Network response: {response.summary.attack_type}",
            summary=summary,
            verdict=str(response.outcome or "unknown"),
            risk_score=90,
            entities=EvidenceEntities(macs=macs),
            source_ref=response.incident_id,
            evidence={
                "node_id": response.node_id,
                "capture": capture.model_dump(mode="json"),
                "attempts": attempts,
                "failed_approaches": response.summary.failed_approaches,
                "successful_approach": response.summary.successful_approach,
                "deployment": response.deployment.model_dump(mode="json"),
                "total_response_ms": response.total_response_ms,
            },
        )
        observation_id, _ = self.store.add_observation(
            observation,
            fingerprint=_fingerprint("attack", response.response_id),
            trigger=trigger,
        )
        return observation_id

    def record_scope(
        self,
        record: ScopeHistoryLog,
        *,
        trigger: bool = True,
        provenance: EvidenceProvenance = EvidenceProvenance.LIVE,
    ) -> int:
        observation = self._scope_observation(record, provenance)
        observation_id, _ = self.store.add_observation(
            observation,
            fingerprint=_fingerprint("scope", provenance.value, record.scan_id),
            trigger=trigger,
        )
        return observation_id

    def record_email(
        self,
        payload: EmailPayload,
        report: ThreatReport,
        analysis_id: int,
        session_url: str | None,
        *,
        trigger: bool = True,
        provenance: EvidenceProvenance = EvidenceProvenance.LIVE,
    ) -> int:
        emails = _email_addresses(payload)
        domains = [_domain(address) for address in emails]
        domains.extend(link.host.casefold() for link in payload.links if link.host)
        observation = IntelligenceObservation(
            occurred_ts=payload.received_at,
            recorded_ts=time.time(),
            source=EvidenceSource.INBOX,
            event_type="EMAIL_ANALYSIS",
            severity=(
                IncidentSeverity.CRITICAL
                if report.risk_score >= 70
                else IncidentSeverity.WARNING
                if report.verdict.value != "CLEAR"
                else IncidentSeverity.INFO
            ),
            title=f"Email analysis: {payload.subject}",
            summary=report.summary,
            verdict=report.verdict.value,
            risk_score=report.risk_score,
            entities=EvidenceEntities(
                domains=sorted(set(domains)),
                urls=[link.url for link in payload.links],
                ips=_public_ips(payload.authentication_results),
                emails=emails,
            ),
            source_ref=str(analysis_id),
            provenance=provenance,
            evidence={
                "gmail_message_id": payload.gmail_message_id,
                "from_address": payload.from_address,
                "reply_to": payload.reply_to,
                "return_path": payload.return_path,
                "subject": payload.subject,
                "authentication_results": payload.authentication_results,
                "report": report.model_dump(mode="json"),
                "devin_session_url": session_url,
            },
        )
        observation_id, _ = self.store.add_observation(
            observation,
            fingerprint=_fingerprint("email", provenance.value, payload.gmail_message_id),
            trigger=trigger,
        )
        return observation_id

    def record_email_detail(self, detail: EmailAnalysisDetail) -> int | None:
        if detail.report is None:
            return None
        payload = EmailPayload(
            gmail_message_id=detail.gmail_message_id,
            gmail_thread_id=f"history-{detail.gmail_message_id}",
            from_address=detail.from_address,
            subject=detail.subject,
            received_at=detail.received_at,
            snippet=detail.snippet,
            body="",
        )
        return self.record_email(
            payload,
            detail.report,
            detail.id,
            detail.devin_session_url,
            trigger=False,
        )

    def bootstrap_history(self, email_details: list[EmailAnalysisDetail] | None = None) -> None:
        for response in read_attack_responses(Path(settings.attack_responses_path)):
            self.record_attack(response, trigger=False)
        for record in read_scope_history(Path(settings.scope_history_path)):
            provenance = (
                EvidenceProvenance.DEMO
                if record.source.casefold() == "demo" or record.scout_backend.casefold() == "demo"
                else EvidenceProvenance.LIVE
            )
            self.record_scope(record, trigger=False, provenance=provenance)
        for detail in email_details or []:
            self.record_email_detail(detail)

    def seed_demo(self, now: float | None = None) -> CommandDemoSeedResult:
        anchor = now or time.time()
        self.store.delete_demo()
        inserted = 0
        trigger_id = 0
        for day in range(1, 8):
            for index in range(5):
                ts = anchor - day * 86400 - (index + 1) * 1800
                payload = EmailPayload(
                    gmail_message_id=f"demo_baseline_{day}_{index}",
                    gmail_thread_id=f"demo-thread-{day}-{index}",
                    from_address=f"newsletter{index}@trusted-example.com",
                    subject="Routine company update",
                    received_at=ts,
                    snippet="Normal historical business email",
                    body="Routine business communication.",
                )
                report = ThreatReport(
                    verdict="CLEAR",
                    risk_score=5,
                    confidence=0.96,
                    summary="No phishing indicators detected.",
                )
                _, was_inserted = self.store.add_observation(
                    self._demo_email_observation(payload, report),
                    fingerprint=_fingerprint("email", "DEMO", payload.gmail_message_id),
                    trigger=False,
                )
                inserted += int(was_inserted)

        malicious_domain = "microsoft-auth-support.pages.dev"
        subjects = [
            "Urgent Microsoft 365 password expiration",
            "Shared payroll document requires sign-in",
            "IT security verification required today",
            "Unusual login — confirm your identity",
            "Mailbox quota exceeded",
            "Updated benefits portal access",
        ]
        for index, subject in enumerate(subjects):
            ts = anchor - (70 - index * 8) * 60
            payload = EmailPayload(
                gmail_message_id=f"demo_phish_{index}",
                gmail_thread_id=f"demo-phish-thread-{index}",
                from_address=f"security-{index}@{malicious_domain}",
                reply_to=f"collect-{index}@{malicious_domain}",
                subject=subject,
                received_at=ts,
                snippet="Verify your company account immediately.",
                body="Your account will be disabled. Sign in immediately.",
                links=[
                    {
                        "id": f"link-{index}",
                        "url": f"https://{malicious_domain}/login?id={index}",
                        "host": malicious_domain,
                        "display": "Microsoft 365",
                    }
                ],
                authentication_results="spf=fail dkim=none dmarc=fail",
            )
            report = ThreatReport(
                verdict="FLAGGED",
                risk_score=84 + index * 2,
                confidence=0.94,
                summary=(
                    "Credential-phishing message impersonates Microsoft and uses a "
                    "shared lookalike host."
                ),
                recommended_actions=["Do not open the link", "Warn employees about this campaign"],
            )
            observation = self._demo_email_observation(payload, report)
            observation_id, was_inserted = self.store.add_observation(
                observation,
                fingerprint=_fingerprint("email", "DEMO", payload.gmail_message_id),
                trigger=index == len(subjects) - 1,
            )
            inserted += int(was_inserted)
            if index == len(subjects) - 1:
                trigger_id = observation_id

        for index in range(2):
            payload = EmailPayload(
                gmail_message_id=f"demo_today_clear_{index}",
                gmail_thread_id=f"demo-today-clear-{index}",
                from_address="updates@trusted-example.com",
                subject="Normal project update",
                received_at=anchor - (20 - index * 5) * 60,
                snippet="Normal company activity",
                body="Project update.",
            )
            report = ThreatReport(
                verdict="CLEAR", risk_score=4, confidence=0.98, summary="No threat found."
            )
            _, was_inserted = self.store.add_observation(
                self._demo_email_observation(payload, report),
                fingerprint=_fingerprint("email", "DEMO", payload.gmail_message_id),
                trigger=False,
            )
            inserted += int(was_inserted)

        scope_record = self._demo_scope_record(anchor, malicious_domain)
        existing = {item.scan_id for item in read_scope_history(Path(settings.scope_history_path))}
        if scope_record.scan_id not in existing:
            append_scope_history(Path(settings.scope_history_path), scope_record)
        _, was_inserted = self.store.add_observation(
            self._scope_observation(scope_record, EvidenceProvenance.DEMO),
            fingerprint=_fingerprint("scope", "DEMO", scope_record.scan_id),
            trigger=False,
        )
        inserted += int(was_inserted)
        return CommandDemoSeedResult(inserted=inserted, trigger_observation_id=trigger_id)

    def _demo_email_observation(
        self, payload: EmailPayload, report: ThreatReport
    ) -> IntelligenceObservation:
        emails = _email_addresses(payload)
        domains = [
            *(_domain(address) for address in emails),
            *(link.host for link in payload.links),
        ]
        return IntelligenceObservation(
            occurred_ts=payload.received_at,
            recorded_ts=time.time(),
            source=EvidenceSource.INBOX,
            event_type="EMAIL_ANALYSIS",
            severity=(
                IncidentSeverity.CRITICAL if report.risk_score >= 70 else IncidentSeverity.INFO
            ),
            title=f"Email analysis: {payload.subject}",
            summary=report.summary,
            verdict=report.verdict.value,
            risk_score=report.risk_score,
            entities=EvidenceEntities(
                domains=sorted(set(filter(None, domains))),
                urls=[link.url for link in payload.links],
                ips=_public_ips(payload.authentication_results),
                emails=emails,
                brands=["Microsoft"] if "Microsoft" in payload.subject else [],
            ),
            source_ref=payload.gmail_message_id,
            provenance=EvidenceProvenance.DEMO,
            evidence={
                "subject": payload.subject,
                "from_address": payload.from_address,
                "reply_to": payload.reply_to,
                "authentication_results": payload.authentication_results,
                "report": report.model_dump(mode="json"),
            },
        )

    @staticmethod
    def _demo_scope_record(anchor: float, domain: str) -> ScopeHistoryLog:
        started = anchor - 25 * 60
        completed = started + 42
        url = f"https://{domain}/login"
        from .models import LinkVerdict

        verdict = LinkVerdict(
            url=url,
            verdict="malicious",
            legit_score=0.03,
            impersonated_brand="Microsoft",
            top_signals=["throwaway pages.dev host", "credential form", "brand/domain mismatch"],
            reasoning=(
                "Browser and research checks agree this is a Microsoft credential-phishing clone."
            ),
            browse_score=0.02,
            research_score=0.04,
        )
        return ScopeHistoryLog(
            scan_id="demo-scope-microsoft-campaign",
            url=url,
            source="demo",
            started_ts=started,
            completed_ts=completed,
            scout_backend="demo",
            tool_calls=[
                ScopeToolCall(
                    tool="devin_browser",
                    started_ts=started,
                    completed_ts=started + 25,
                    request={"url": url, "objective": "inspect page and forms"},
                    result={"verdict": "malicious", "legit_score": 0.02},
                ),
                ScopeToolCall(
                    tool="devin_research",
                    started_ts=started,
                    completed_ts=completed,
                    request={"url": url, "objective": "research ownership and reputation"},
                    result={"verdict": "malicious", "legit_score": 0.04},
                ),
            ],
            verdict=verdict,
        )

    @staticmethod
    def _scope_observation(
        record: ScopeHistoryLog, provenance: EvidenceProvenance
    ) -> IntelligenceObservation:
        host = _domain(record.url)
        verdict = record.verdict
        return IntelligenceObservation(
            occurred_ts=record.completed_ts,
            recorded_ts=time.time(),
            source=EvidenceSource.SCOPE,
            event_type="SCOPE_VERDICT",
            severity=(
                IncidentSeverity.CRITICAL
                if verdict.verdict == "malicious"
                else IncidentSeverity.WARNING
                if verdict.verdict == "suspicious"
                else IncidentSeverity.INFO
            ),
            title=f"SCOPE verdict: {host}",
            summary=verdict.reasoning,
            verdict=verdict.verdict,
            risk_score=round((1.0 - verdict.legit_score) * 100),
            entities=EvidenceEntities(
                domains=[host] if host else [],
                urls=[record.url],
                brands=[verdict.impersonated_brand] if verdict.impersonated_brand else [],
            ),
            source_ref=record.scan_id,
            provenance=provenance,
            evidence=record.model_dump(mode="json"),
        )

    def overview(self) -> CommandOverview:
        assessments = self.store.assessments()
        return CommandOverview(
            assessing=any(item.status == "RUNNING" for item in assessments),
            metrics=self.store.metrics(),
            observations=self.store.observations(since=time.time() - 30 * 86400, limit=100),
            assessments=assessments,
            reports=self.store.reports(),
        )

    async def run_once(self, *, force: bool = False) -> bool:
        before = time.time() if force else time.time() - settings.command_debounce_s
        assessment_ids = await asyncio.to_thread(self.store.claim_pending, before=before)
        if not assessment_ids:
            return False
        observations = await asyncio.to_thread(
            self.store.observations, since=time.time() - 30 * 86400, limit=250
        )
        metrics = await asyncio.to_thread(self.store.metrics)

        def on_step(message: str) -> None:
            self.progress = message

        failure_log: str | None = None
        session_url: str | None = None
        try:
            for _ in range(2):
                decision, session_url = await asyncio.to_thread(
                    partial(
                        self.agent,
                        observations,
                        metrics,
                        on_step=on_step,
                        failure_log=failure_log,
                    )
                )
                errors = verify_command_decision(decision, observations, metrics)
                if not errors:
                    break
                failure_log = "\n".join(errors)
            else:
                raise ValueError(f"COMMAND report failed verification: {failure_log}")

            report_id: str | None = None
            if decision.decision == "CREATE_REPORT":
                evidence_json = json.dumps(
                    [item.model_dump(mode="json") for item in observations],
                    sort_keys=True,
                    separators=(",", ":"),
                )
                report_id = await asyncio.to_thread(self.store.next_report_id)
                provenance = (
                    EvidenceProvenance.DEMO
                    if any(item.provenance is EvidenceProvenance.DEMO for item in observations)
                    else EvidenceProvenance.LIVE
                )
                report = CommandReport(
                    id=report_id,
                    created_ts=time.time(),
                    title=decision.title,
                    urgency=decision.urgency,
                    executive_summary=decision.executive_summary,
                    confidence=decision.confidence,
                    provenance=provenance,
                    trigger_reason=decision.reason,
                    what_happened=decision.what_happened,
                    cause_analysis=decision.cause_analysis,
                    correlations=decision.correlations,
                    attacker_context=decision.attacker_context,
                    actions_taken=self._verified_actions(observations),
                    recommendations=decision.recommendations,
                    evidence_ids=sorted(
                        set(decision.evidence_ids)
                        | {value for item in decision.correlations for value in item.evidence_ids}
                        | {
                            value
                            for item in decision.attacker_context
                            for value in item.evidence_ids
                        }
                    ),
                    metrics=metrics,
                    employee_advisory=decision.employee_advisory,
                    devin_session_url=session_url,
                    evidence_sha256=hashlib.sha256(evidence_json.encode()).hexdigest(),
                )
                await asyncio.to_thread(self.store.save_report, report)
            await asyncio.to_thread(
                self.store.complete_assessments,
                assessment_ids,
                decision=decision.decision,
                reason=decision.reason,
                report_id=report_id,
                session_url=session_url,
            )
            return True
        except Exception as exc:
            await asyncio.to_thread(self.store.fail_assessments, assessment_ids, str(exc))
            return False
        finally:
            self.progress = ""

    @staticmethod
    def _verified_actions(observations: list[IntelligenceObservation]) -> list[str]:
        actions: list[str] = []
        for item in observations:
            if item.source is EvidenceSource.SIGNAL:
                deployment = item.evidence.get("deployment")
                attempts = item.evidence.get("attempts")
                actions.append(
                    f"SIGNAL processed {len(attempts) if isinstance(attempts, list) else 0} "
                    f"patch attempt(s); deployment record: {deployment}."
                )
            elif item.source is EvidenceSource.INBOX and item.verdict != "CLEAR":
                actions.append(f"INBOX flagged '{item.title.removeprefix('Email analysis: ')}'.")
            elif item.source is EvidenceSource.SCOPE and item.verdict != "legit":
                actions.append(f"SCOPE classified {item.entities.urls[0]} as {item.verdict}.")
        return actions[:20]

    async def worker_loop(self) -> None:
        while True:
            processed = await self.run_once()
            if not processed:
                await asyncio.sleep(0.5)


_service: CommandService | None = None


def get_command_service() -> CommandService:
    global _service
    if _service is None:
        _service = CommandService()
    return _service


def reset_command_service() -> None:
    global _service
    _service = None
