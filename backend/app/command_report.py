"""Render a verified COMMAND report as a portable company artifact."""

from __future__ import annotations

from datetime import UTC, datetime

from .models import CommandReport


def _clock(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def render_command_markdown(report: CommandReport) -> str:
    metrics = report.metrics
    lines = [
        f"# {report.id}: {report.title}",
        "",
        f"- **Created:** {_clock(report.created_ts)}",
        f"- **Urgency:** {report.urgency}",
        f"- **Confidence:** {report.confidence * 100:.0f}%",
        f"- **Evidence mode:** {report.provenance.value}",
        f"- **Evidence SHA-256:** `{report.evidence_sha256}`",
        "",
        "## Executive assessment",
        report.executive_summary,
        "",
        "## Verified activity metrics",
        f"- Current email findings: {metrics.email_current_flagged}/"
        f"{metrics.email_current_total} flagged",
        f"- Seven-day baseline: {metrics.email_baseline_flagged}/"
        f"{metrics.email_baseline_total} flagged",
        f"- Phishing spike: {'YES' if metrics.phishing_spike else 'NO'}",
        f"- Network incidents: {metrics.signal_incidents}",
        f"- Malicious SCOPE findings: {metrics.malicious_scope_checks}",
        "",
        "## What happened",
        *[f"- {item}" for item in report.what_happened],
        "",
        "## Cause and campaign analysis",
        *[f"- {item}" for item in report.cause_analysis],
        "",
        "## Cross-domain correlations",
    ]
    lines.extend(
        f"- **{item.confidence * 100:.0f}%:** {item.claim} "
        f"(evidence {', '.join(map(str, item.evidence_ids))}) — {item.explanation}"
        for item in report.correlations
    )
    lines.extend(["", "## Attacker context (hypotheses, not identity claims)"])
    lines.extend(
        f"- **{item.entity}** ({item.confidence * 100:.0f}%): {item.finding} "
        f"[evidence {', '.join(map(str, item.evidence_ids))}]"
        + (f" — Sources: {', '.join(item.sources)}" if item.sources else "")
        for item in report.attacker_context
    )
    lines.extend(["", "## Autonomous actions completed"])
    lines.extend(f"- {item}" for item in report.actions_taken)
    lines.extend(["", "## Recommended next actions"])
    lines.extend(f"- {item}" for item in report.recommendations)
    if report.employee_advisory.needed:
        lines.extend(
            [
                "",
                "## Employee advisory artifact",
                f"**Subject:** {report.employee_advisory.subject}",
                "",
                report.employee_advisory.body,
            ]
        )
    lines.extend(["", "## Evidence references", ", ".join(map(str, report.evidence_ids)), ""])
    if report.devin_session_url:
        lines.extend([f"Devin investigation: {report.devin_session_url}", ""])
    return "\n".join(lines)
