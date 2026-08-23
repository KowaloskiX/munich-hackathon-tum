import asyncio
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import command_routes
from app.command_report import render_command_markdown
from app.command_service import CommandService, verify_command_decision
from app.intelligence_store import IntelligenceStore
from app.link_scout import scan_link_stub
from app.models import CommandDecision, EvidenceProvenance, EvidenceSource, LinkScanIn
from app.orchestrator import handle_link_scan
from app.scope_log import read_scope_history
from app.state import AppState


async def _nosleep(_: float) -> None:
    return None


def test_scope_history_persists_component_calls_and_results(tmp_path) -> None:
    path = tmp_path / "scope_history.jsonl"
    verdict = asyncio.run(
        handle_link_scan(
            AppState(),
            LinkScanIn(url="https://paypal-login.pages.dev", source="test"),
            scout=scan_link_stub,
            sleep=_nosleep,
            step_delay=0,
            scope_log_path=path,
        )
    )

    records = read_scope_history(path)
    assert len(records) == 1
    assert records[0].verdict == verdict
    assert [call.tool for call in records[0].tool_calls] == [
        "scope_browser_stub",
        "scope_research_stub",
    ]
    assert records[0].tool_calls[0].request["url"] == verdict.url
    assert records[0].tool_calls[1].result["verdict"] == "malicious"


def test_demo_spike_is_measured_and_autonomously_reported(tmp_path, monkeypatch) -> None:
    from app.command_service import settings

    monkeypatch.setattr(settings, "scope_history_path", str(tmp_path / "scope.jsonl"))
    store = IntelligenceStore(str(tmp_path / "command.db"))
    service = CommandService(store=store)
    seeded = service.seed_demo()
    service.bootstrap_history()

    metrics = store.metrics()
    assert seeded.inserted == 44
    assert metrics.email_current_flagged == 6
    assert metrics.email_current_total == 8
    assert metrics.email_baseline_flagged == 0
    assert metrics.email_baseline_total == 35
    assert metrics.phishing_spike is True
    assert metrics.malicious_scope_checks == 1
    assert "microsoft-auth-support.pages.dev" in metrics.shared_entities
    scope_records = [item for item in store.observations() if item.source is EvidenceSource.SCOPE]
    assert len(scope_records) == 1
    assert scope_records[0].provenance is EvidenceProvenance.DEMO

    assert asyncio.run(service.run_once(force=True)) is True
    reports = store.reports()
    assert len(reports) == 1
    report = store.report(reports[0].id)
    assert report is not None
    assert report.provenance.value == "DEMO"
    assert report.employee_advisory.needed is True
    assert "6/8" in report.executive_summary
    assert "Phishing spike: YES" in render_command_markdown(report)


def test_markdown_report_route_is_not_shadowed(tmp_path, monkeypatch) -> None:
    store = IntelligenceStore(str(tmp_path / "command.db"))
    service = CommandService(store=store)
    service.seed_demo()
    assert asyncio.run(service.run_once(force=True)) is True
    report_id = store.reports()[0].id
    monkeypatch.setattr(command_routes, "get_command_service", lambda: service)
    app = FastAPI()
    app.include_router(command_routes.router)

    response = TestClient(app).get(f"/v1/command/reports/{report_id}.md")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert response.text.startswith(f"# {report_id}: {store.reports()[0].title}")


def test_decision_oracle_rejects_suppressed_mandatory_report(tmp_path) -> None:
    store = IntelligenceStore(str(tmp_path / "command.db"))
    service = CommandService(store=store)
    service.seed_demo(now=time.time())
    observations = store.observations(since=time.time() - 30 * 86400)
    metrics = store.metrics()

    errors = verify_command_decision(
        CommandDecision(decision="NO_REPORT", reason="ignore"), observations, metrics
    )

    assert errors
    assert "report is mandatory" in errors[0]
