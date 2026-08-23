"""HTTP and WebSocket contract for Gmail threat review."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import secrets
from urllib.parse import urlencode

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response, WebSocket
from fastapi.responses import RedirectResponse

from .config import settings
from .email_service import get_email_service
from .models import (
    EmailAnalysisDetail,
    EmailAnalysisList,
    EmailConnectionStatus,
    EmailImportRequest,
    EmailImportResult,
    EmailMessagePreviewList,
    EmailReviewRequest,
    EmailSettingsUpdate,
)

router = APIRouter(prefix="/v1")
_COOKIE = "email_session"


def _require_enabled() -> None:
    if not settings.email_security_enabled:
        raise HTTPException(status_code=503, detail="Email security is not configured")


def _session_token(request: Request) -> str | None:
    return request.cookies.get(_COOKIE)


def _require_session(request: Request) -> str:
    token = _session_token(request)
    if not get_email_service().valid_session(token):
        raise HTTPException(status_code=401, detail="Gmail session required")
    assert token is not None
    return token


def _require_csrf(request: Request, csrf: str | None) -> str:
    token = _require_session(request)
    if not get_email_service().valid_csrf(token, csrf):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    return token


@router.get("/gmail/status", response_model=EmailConnectionStatus)
async def gmail_status(request: Request) -> EmailConnectionStatus:
    if not settings.email_security_enabled:
        return EmailConnectionStatus(connected=False)
    return get_email_service().status(_session_token(request))


@router.get("/gmail/oauth/start")
async def gmail_oauth_start() -> RedirectResponse:
    _require_enabled()
    if not all(
        (
            settings.gmail_oauth_client_id,
            settings.gmail_oauth_client_secret,
            settings.gmail_pubsub_topic,
            settings.gmail_allowed_email,
        )
    ):
        raise HTTPException(status_code=503, detail="Gmail OAuth configuration is incomplete")
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    service = get_email_service()
    service.save_oauth_state(state, verifier, settings.dashboard_url)
    return RedirectResponse(service.authorization_url(state, challenge))


@router.get("/gmail/oauth/callback")
async def gmail_oauth_callback(
    code: str = Query(default=""),
    state: str = Query(default=""),
    error: str = Query(default=""),
) -> RedirectResponse:
    _require_enabled()
    service = get_email_service()
    saved = service.consume_oauth_state(state)
    if error or not code or saved is None:
        query = urlencode({"email_error": error or "invalid_oauth_state"})
        return RedirectResponse(f"{settings.dashboard_url}?{query}")
    verifier, return_to = saved
    try:
        await asyncio.to_thread(service.connect, code, verifier)
    except Exception as exc:
        query = urlencode({"email_error": str(exc)[:160]})
        return RedirectResponse(f"{return_to}?{query}")
    token, _ = service.create_session()
    response = RedirectResponse(f"{return_to}?email=connected")
    response.set_cookie(
        _COOKIE,
        token,
        httponly=True,
        samesite="lax",
        secure=settings.gmail_oauth_redirect_uri.startswith("https://"),
        max_age=30 * 86400,
        path="/",
    )
    return response


@router.put("/gmail/settings", response_model=EmailConnectionStatus)
async def gmail_settings(
    body: EmailSettingsUpdate,
    request: Request,
    x_csrf_token: str | None = Header(default=None),
) -> EmailConnectionStatus:
    _require_enabled()
    token = _require_csrf(request, x_csrf_token)
    await asyncio.to_thread(get_email_service().set_mode, body.mode)
    return get_email_service().status(token)


@router.post("/gmail/disconnect", status_code=204)
async def gmail_disconnect(
    request: Request,
    response: Response,
    x_csrf_token: str | None = Header(default=None),
) -> None:
    _require_enabled()
    _require_csrf(request, x_csrf_token)
    await asyncio.to_thread(get_email_service().disconnect)
    response.delete_cookie(_COOKIE, path="/")


@router.get("/email/analyses", response_model=EmailAnalysisList)
async def email_analyses(
    request: Request, cursor: int | None = Query(default=None, ge=1)
) -> EmailAnalysisList:
    _require_enabled()
    _require_session(request)
    return await asyncio.to_thread(get_email_service().analyses, cursor)


@router.post("/email/import", response_model=EmailImportResult)
async def email_import(
    body: EmailImportRequest,
    request: Request,
    x_csrf_token: str | None = Header(default=None),
) -> EmailImportResult:
    _require_enabled()
    _require_csrf(request, x_csrf_token)
    if body.limit is not None:
        return await asyncio.to_thread(get_email_service().import_recent, body.limit)
    return await asyncio.to_thread(get_email_service().import_selected, body.message_ids)


@router.get("/email/messages", response_model=EmailMessagePreviewList)
async def email_messages(
    request: Request,
    limit: int = Query(default=50, ge=1, le=50),
    page_token: str | None = Query(default=None, max_length=2048),
) -> EmailMessagePreviewList:
    _require_enabled()
    _require_session(request)
    return await asyncio.to_thread(get_email_service().recent_messages, limit, page_token)


@router.get("/email/analyses/{analysis_id}", response_model=EmailAnalysisDetail)
async def email_analysis(analysis_id: int, request: Request) -> EmailAnalysisDetail:
    _require_enabled()
    _require_session(request)
    detail = await asyncio.to_thread(get_email_service().analysis, analysis_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Email analysis not found")
    return detail


@router.post("/email/analyses/{analysis_id}/review", response_model=EmailAnalysisDetail)
async def email_review(
    analysis_id: int,
    body: EmailReviewRequest,
    request: Request,
    x_csrf_token: str | None = Header(default=None),
) -> EmailAnalysisDetail:
    _require_enabled()
    _require_csrf(request, x_csrf_token)
    try:
        return await asyncio.to_thread(get_email_service().review, analysis_id, body.decision)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Email analysis not found") from exc


@router.websocket("/email/live")
async def email_live(ws: WebSocket) -> None:
    if not settings.email_security_enabled:
        await ws.close(code=1013)
        return
    service = get_email_service()
    if not service.valid_session(ws.cookies.get(_COOKIE)):
        await ws.close(code=1008)
        return
    await ws.accept()
    queue = service.broadcaster.subscribe()
    try:
        while True:
            event = await queue.get()
            await ws.send_json(event.model_dump(mode="json"))
    finally:
        service.broadcaster.unsubscribe(queue)
