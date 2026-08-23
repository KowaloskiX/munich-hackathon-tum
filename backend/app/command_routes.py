"""HTTP contract for COMMAND overview and verified company reports."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from .command_report import render_command_markdown
from .command_service import get_command_service
from .models import CommandDemoSeedResult, CommandOverview, CommandReport

router = APIRouter(prefix="/v1/command")


@router.get("/overview", response_model=CommandOverview)
async def command_overview() -> CommandOverview:
    return get_command_service().overview()


@router.get("/reports/{report_id}.md")
async def command_report_markdown(report_id: str) -> PlainTextResponse:
    report = get_command_service().store.report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="COMMAND report not found")
    return PlainTextResponse(render_command_markdown(report), media_type="text/markdown")


@router.get("/reports/{report_id}", response_model=CommandReport)
async def command_report(report_id: str) -> CommandReport:
    report = get_command_service().store.report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="COMMAND report not found")
    return report


@router.post("/demo/seed", response_model=CommandDemoSeedResult)
async def command_demo_seed() -> CommandDemoSeedResult:
    return get_command_service().seed_demo()
