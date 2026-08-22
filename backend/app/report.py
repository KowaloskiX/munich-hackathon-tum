"""Render a per-incident markdown report — the pitch artifact.

Pulls together the whole autonomous loop for one incident: what was detected,
what Devin did in its VM, the independent oracle verdict on held-out captures,
the real enforcement measurement, the deployed filter, and the timeline.
"""

from __future__ import annotations

from datetime import UTC, datetime

from .models import IncidentReport, LiveEvent


def _clock(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%H:%M:%S")


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{value * 100:.1f}%"


def _event_detail(event: LiveEvent) -> str:
    p = event.payload
    text = p.get("text")
    if isinstance(text, str) and text:
        return text
    if event.type.value == "ANOMALY_DETECTED":
        return f"{p.get('count', '?')} frames in window"
    if event.type.value == "FRAME_BLOCKED":
        return f"{p.get('count', 0)} frames blocked"
    bits: list[str] = []
    if "attack_class" in p:
        bits.append(str(p["attack_class"]))
    if "tests" in p:
        bits.append(f"tests {p['tests']}")
    return ", ".join(bits)


def render_markdown(incident: IncidentReport) -> str:
    inc = incident
    lines: list[str] = []
    lines.append(f"# Incident {inc.id}")
    lines.append("")
    lines.append(f"- **Node:** {inc.node_id}")
    lines.append(f"- **Detected:** {_clock(inc.started_ts)} UTC")
    lines.append(f"- **Attack class:** {inc.attack_class} (confidence {_pct(inc.confidence)})")
    lines.append(f"- **Frames captured:** {inc.frames}")
    status = "deployed" if inc.deployed else "not deployed (left for a human)"
    lines.append(f"- **Outcome:** {status}")
    lines.append("")

    lines.append("## Autonomous response (Devin)")
    lines.append(f"- Sandbox iterations: {inc.iterations}")
    lines.append(f"- Self-test in VM: TPR {_pct(inc.self_tpr)} / FPR {_pct(inc.self_fpr)}")
    if inc.session_url:
        lines.append(f"- Devin session: {inc.session_url}")
    lines.append("")

    lines.append("## Independent verification (oracle, held-out captures)")
    if inc.oracle is not None:
        o = inc.oracle
        verdict = "PASS" if o.passed else "FAIL"
        lines.append(f"- Result: **{verdict}** {o.tests_passed}/{o.tests_total} tests")
        lines.append(f"- TPR {_pct(o.tpr)} / FPR {_pct(o.fpr)}")
    else:
        lines.append("- Not verified.")
    lines.append("")

    lines.append("## Enforcement (compiled filter run on real frames)")
    if inc.enforcement is not None:
        e = inc.enforcement
        total = e.blocked + e.passed
        lines.append(f"- Blocked **{e.blocked}/{total}** frames the loaded filter processed")
        lines.append(f"- False positives: {e.false_positives}/{e.benign_total} benign frames")
    else:
        lines.append("- Not measured.")
    lines.append("")

    lines.append("## Deployed filter (filter.c)")
    lines.append("```c")
    lines.append(inc.filter_c_code.rstrip() if inc.filter_c_code else "// no filter generated")
    lines.append("```")
    lines.append("")

    lines.append("## Timeline")
    for event in inc.events:
        detail = _event_detail(event)
        suffix = f" — {detail}" if detail else ""
        lines.append(f"- `{_clock(event.ts)}` **{event.type.value}**{suffix}")
    lines.append("")

    return "\n".join(lines)
