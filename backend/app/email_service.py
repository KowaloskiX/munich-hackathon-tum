"""Gmail history synchronization, analysis worker, and human review flow."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import functools
import hashlib
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import replace
from email.utils import getaddresses
from html.parser import HTMLParser
from typing import Any, Protocol
from urllib.parse import urlparse

import httpx
from google.cloud import pubsub_v1

from .config import settings
from .email_agent import DevinEmailThreatAgent, EmailAgentResult, StubEmailThreatAgent
from .email_store import EmailStore, GmailAccountRecord, SecretBox
from .gmail_client import GmailClient
from .models import (
    EmailAnalysisDetail,
    EmailAnalysisList,
    EmailAttachment,
    EmailConnectionStatus,
    EmailEventType,
    EmailImportResult,
    EmailLabels,
    EmailLink,
    EmailLiveEvent,
    EmailMessagePreview,
    EmailMessagePreviewList,
    EmailMonitoringMode,
    EmailPayload,
    EmailReviewDecision,
    GmailMessage,
    GmailNotification,
    GmailPart,
    IncidentSeverity,
    IncidentSource,
)

# Sink that funnels a flagged email into the unified feed. Injected by main.py
# (state.add_feed_item) so this module stays decoupled from AppState.
IncidentSink = Callable[..., object]

_LABEL_NAMES = {
    "scan": "Sentinel/Scan",
    "pending_review": "Sentinel/Pending Review",
    "confirmed_dangerous": "Sentinel/Confirmed Dangerous",
    "not_dangerous": "Sentinel/Not Dangerous",
}
_URL_RE = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)


class ThreatAgent(Protocol):
    def analyze(
        self,
        payload: EmailPayload,
        load_attachment: Callable[[str], tuple[str, bytes, str]],
    ) -> EmailAgentResult: ...


class _HtmlTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.links: list[tuple[str, str]] = []
        self._anchor: str | None = None
        self._anchor_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            href = next((value for key, value in attrs if key == "href"), None)
            if href:
                self._anchor = href
                self._anchor_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._anchor:
            self.links.append((self._anchor, "".join(self._anchor_text).strip()))
            self._anchor = None
            self._anchor_text = []
        if tag in {"p", "div", "br", "li", "tr"}:
            self.text.append("\n")

    def handle_data(self, data: str) -> None:
        self.text.append(data)
        if self._anchor:
            self._anchor_text.append(data)


class EmailBroadcaster:
    def __init__(self) -> None:
        self._queues: set[asyncio.Queue[EmailLiveEvent]] = set()

    def subscribe(self) -> asyncio.Queue[EmailLiveEvent]:
        queue: asyncio.Queue[EmailLiveEvent] = asyncio.Queue(maxsize=128)
        self._queues.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[EmailLiveEvent]) -> None:
        self._queues.discard(queue)

    def publish(self, event: EmailLiveEvent) -> None:
        for queue in list(self._queues):
            with contextlib.suppress(asyncio.QueueFull):
                queue.put_nowait(event)


def _decode(data: str | None) -> str:
    if not data:
        return ""
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded).decode(errors="replace")


def _decode_bytes(data: str) -> bytes:
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded)


def _walk(part: GmailPart) -> list[GmailPart]:
    return [part, *(child for nested in part.parts for child in _walk(nested))]


def parse_message(message: GmailMessage) -> EmailPayload:
    parts = _walk(message.payload)
    headers = {header.name.lower(): header.value for header in message.payload.headers}
    plain = "\n".join(_decode(part.body.data) for part in parts if part.mimeType == "text/plain")
    html = "\n".join(_decode(part.body.data) for part in parts if part.mimeType == "text/html")
    html_parser = _HtmlTextParser()
    if html:
        html_parser.feed(html)
    body = plain.strip() or "".join(html_parser.text).strip()
    truncated = len(body) > settings.email_max_body_chars
    body = body[: settings.email_max_body_chars]

    raw_links = [*html_parser.links, *((url, "") for url in _URL_RE.findall(body))]
    seen: set[str] = set()
    links: list[EmailLink] = []
    for url, display in raw_links:
        normalized = url.rstrip(".,);]")
        if normalized in seen:
            continue
        parsed = urlparse(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            continue
        seen.add(normalized)
        links.append(
            EmailLink(
                id=f"LINK_{len(links) + 1}",
                url=normalized,
                host=parsed.hostname,
                display=display,
            )
        )

    attachments = [
        EmailAttachment(
            id=part.body.attachmentId,
            filename=part.filename,
            mime_type=part.mimeType or "application/octet-stream",
            size=part.body.size,
        )
        for part in parts
        if part.filename and part.body.attachmentId
    ]
    return EmailPayload(
        gmail_message_id=message.id,
        gmail_thread_id=message.threadId,
        from_address=headers.get("from", ""),
        reply_to=headers.get("reply-to", ""),
        return_path=headers.get("return-path", ""),
        to_addresses=[address for _, address in getaddresses([headers.get("to", "")])],
        cc_addresses=[address for _, address in getaddresses([headers.get("cc", "")])],
        subject=headers.get("subject", "(no subject)"),
        received_at=float(message.internalDate) / 1000,
        snippet=message.snippet,
        body=body,
        authentication_results=headers.get("authentication-results", ""),
        links=links,
        attachments=attachments,
        truncated=truncated,
    )


class EmailSecurityService:
    def __init__(
        self,
        *,
        gmail: GmailClient | None = None,
        store: EmailStore | None = None,
        agent: ThreatAgent | None = None,
    ) -> None:
        self.gmail = gmail or GmailClient()
        self.store = store or EmailStore(
            settings.email_db_path, SecretBox(settings.email_token_encryption_key)
        )
        self.agent = agent or (
            DevinEmailThreatAgent() if settings.email_agent == "devin" else StubEmailThreatAgent()
        )
        self.broadcaster = EmailBroadcaster()
        # Set by main.py to funnel flagged emails into the unified feed.
        self.incident_sink: IncidentSink | None = None
        self._sync_lock = asyncio.Lock()
        self._subscriber: pubsub_v1.SubscriberClient | None = None
        self._streaming_future: Any = None

    def _emit(
        self, event_type: EmailEventType, message: str, analysis_id: int | None = None
    ) -> None:
        self.broadcaster.publish(
            EmailLiveEvent(
                type=event_type, analysis_id=analysis_id, ts=time.time(), message=message
            )
        )

    def save_oauth_state(self, state: str, verifier: str, return_to: str) -> None:
        self.store.save_oauth_state(state, verifier, return_to)

    def consume_oauth_state(self, state: str) -> tuple[str, str] | None:
        record = self.store.consume_oauth_state(state)
        return (record.verifier, record.return_to) if record else None

    def authorization_url(self, state: str, challenge: str) -> str:
        return self.gmail.authorization_url(state, challenge)

    def connect(self, code: str, verifier: str) -> GmailAccountRecord:
        token = self.gmail.exchange_code(code, verifier)
        if not token.refresh_token:
            raise ValueError("Google did not return an offline refresh token")
        profile = self.gmail.profile(token.access_token)
        if settings.gmail_allowed_email and (
            profile.emailAddress.casefold() != settings.gmail_allowed_email.casefold()
        ):
            self.gmail.revoke(token.refresh_token)
            raise PermissionError("connected Gmail account is not allowed")
        existing = {label.name: label.id for label in self.gmail.labels(token.access_token)}
        label_ids: dict[str, str] = {}
        for key, name in _LABEL_NAMES.items():
            label_ids[key] = (
                existing.get(name) or self.gmail.create_label(token.access_token, name).id
            )
        labels = EmailLabels(**label_ids)
        watch = self.gmail.watch(token.access_token, EmailMonitoringMode.ALL, labels.scan)
        account = GmailAccountRecord(
            email=profile.emailAddress,
            access_token=token.access_token,
            refresh_token=token.refresh_token,
            token_expires_at=time.time() + token.expires_in,
            mode=EmailMonitoringMode.ALL,
            history_id=watch.historyId,
            watch_expiration=float(watch.expiration) / 1000,
            labels=labels,
            last_sync=time.time(),
        )
        self.store.save_account(account)
        self._emit(EmailEventType.CONNECTION_CHANGED, "Gmail connected")
        return account

    def _account_with_token(self) -> GmailAccountRecord:
        account = self.store.get_account()
        if account is None:
            raise RuntimeError("Gmail is not connected")
        if account.token_expires_at > time.time() + 60:
            return account
        token = self.gmail.refresh(account.refresh_token)
        updated = replace(
            account,
            access_token=token.access_token,
            refresh_token=token.refresh_token or account.refresh_token,
            token_expires_at=time.time() + token.expires_in,
        )
        self.store.save_account(updated)
        return updated

    def status(self, session_token: str | None) -> EmailConnectionStatus:
        account = self.store.get_account()
        csrf = self.store.session_csrf(session_token) if session_token else None
        if account is None:
            return EmailConnectionStatus(connected=False)
        return EmailConnectionStatus(
            connected=True,
            email=account.email,
            mode=account.mode,
            watch_expiration=account.watch_expiration,
            last_sync=account.last_sync,
            labels=account.labels,
            csrf_token=csrf,
        )

    def set_mode(self, mode: EmailMonitoringMode) -> EmailConnectionStatus:
        account = self._account_with_token()
        watch = self.gmail.watch(account.access_token, mode, account.labels.scan)
        updated = replace(
            account,
            mode=mode,
            history_id=watch.historyId,
            watch_expiration=float(watch.expiration) / 1000,
            last_sync=time.time(),
        )
        self.store.save_account(updated)
        self._emit(EmailEventType.CONNECTION_CHANGED, f"Monitoring mode changed to {mode.value}")
        return self.status(None)

    def disconnect(self) -> None:
        account = self.store.get_account()
        if account:
            with contextlib.suppress(httpx.HTTPError):
                self.gmail.stop(account.access_token)
            with contextlib.suppress(httpx.HTTPError):
                self.gmail.revoke(account.refresh_token)
        self.store.delete_all()
        self._emit(EmailEventType.CONNECTION_CHANGED, "Gmail disconnected")

    async def sync_history(self, notification_history_id: str) -> None:
        async with self._sync_lock:
            account = await asyncio.to_thread(self._account_with_token)
            if account.email.casefold() != settings.gmail_allowed_email.casefold():
                raise PermissionError("notification account mismatch")
            label_id = "INBOX" if account.mode is EmailMonitoringMode.ALL else account.labels.scan
            page_token: str | None = None
            latest_history_id = account.history_id
            while True:
                try:
                    history = await asyncio.to_thread(
                        self.gmail.history,
                        account.access_token,
                        account.history_id,
                        label_id,
                        page_token,
                    )
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code != 404:
                        raise
                    await self._recover_after_cursor(account, label_id)
                    watch = await asyncio.to_thread(
                        self.gmail.watch, account.access_token, account.mode, account.labels.scan
                    )
                    self.store.save_account(
                        replace(
                            account,
                            history_id=watch.historyId,
                            watch_expiration=float(watch.expiration) / 1000,
                            last_sync=time.time(),
                        )
                    )
                    return
                for record in history.history:
                    for added in record.messagesAdded:
                        message = await asyncio.to_thread(
                            self.gmail.message, account.access_token, added.message.id
                        )
                        if (
                            account.mode is EmailMonitoringMode.ALL
                            and "INBOX" not in message.labelIds
                        ):
                            continue
                        if (
                            account.mode is EmailMonitoringMode.SELECTED
                            and account.labels.scan not in message.labelIds
                        ):
                            continue
                        analysis_id = self.store.enqueue(parse_message(message))
                        if analysis_id is not None:
                            self._emit(
                                EmailEventType.RECEIVED,
                                "New email queued for threat analysis",
                                analysis_id,
                            )
                latest_history_id = history.historyId or notification_history_id
                page_token = history.nextPageToken
                if not page_token:
                    break
            self.store.update_cursor(latest_history_id or notification_history_id, time.time())

    async def _recover_after_cursor(self, account: GmailAccountRecord, label_id: str) -> None:
        page_token: str | None = None
        after_epoch = int(account.last_sync or time.time())
        while True:
            result = await asyncio.to_thread(
                self.gmail.messages_after,
                account.access_token,
                after_epoch,
                label_id,
                page_token,
            )
            for reference in result.messages:
                message = await asyncio.to_thread(
                    self.gmail.message, account.access_token, reference.id
                )
                analysis_id = self.store.enqueue(parse_message(message))
                if analysis_id is not None:
                    self._emit(
                        EmailEventType.RECEIVED,
                        "Recovered email queued for threat analysis",
                        analysis_id,
                    )
            page_token = result.nextPageToken
            if not page_token:
                return

    def recent_messages(self, limit: int, page_token: str | None = None) -> EmailMessagePreviewList:
        account = self._account_with_token()
        result = self.gmail.recent_messages(account.access_token, None, limit, page_token)
        existing = self.store.existing_message_ids([reference.id for reference in result.messages])
        items: list[EmailMessagePreview] = []
        for reference in result.messages[:limit]:
            message = self.gmail.message(account.access_token, reference.id)
            payload = parse_message(message)
            items.append(
                EmailMessagePreview(
                    gmail_message_id=payload.gmail_message_id,
                    from_address=payload.from_address,
                    subject=payload.subject,
                    snippet=payload.snippet,
                    received_at=payload.received_at,
                    already_imported=payload.gmail_message_id in existing,
                )
            )
        items.sort(key=lambda item: item.received_at, reverse=True)
        return EmailMessagePreviewList(items=items, next_page_token=result.nextPageToken)

    def import_selected(self, message_ids: list[str]) -> EmailImportResult:
        account = self._account_with_token()
        unique_ids = list(dict.fromkeys(message_ids))
        existing = self.store.existing_message_ids(unique_ids)
        imported = 0
        for message_id in unique_ids:
            if message_id in existing:
                continue
            message = self.gmail.message(account.access_token, message_id)
            analysis_id = self.store.enqueue(parse_message(message))
            if analysis_id is None:
                continue
            imported += 1
            self._emit(
                EmailEventType.RECEIVED,
                "Imported email queued for threat analysis",
                analysis_id,
            )
        return EmailImportResult(
            scanned=len(unique_ids),
            imported=imported,
            duplicates=len(existing),
        )

    def import_recent(self, limit: int) -> EmailImportResult:
        account = self._account_with_token()
        label_id = "INBOX" if account.mode is EmailMonitoringMode.ALL else account.labels.scan
        result = self.gmail.recent_messages(account.access_token, label_id, limit)
        references = result.messages[:limit]
        existing = self.store.existing_message_ids([reference.id for reference in references])
        imported = 0
        for reference in references:
            if reference.id in existing:
                continue
            message = self.gmail.message(account.access_token, reference.id)
            if label_id not in message.labelIds:
                continue
            analysis_id = self.store.enqueue(parse_message(message))
            if analysis_id is None:
                continue
            imported += 1
            self._emit(
                EmailEventType.RECEIVED,
                "Imported email queued for threat analysis",
                analysis_id,
            )
        return EmailImportResult(
            scanned=len(references),
            imported=imported,
            duplicates=len(existing),
        )

    def _load_attachment(self, payload: EmailPayload, attachment_id: str) -> tuple[str, bytes, str]:
        attachment = next(item for item in payload.attachments if item.id == attachment_id)
        account = self._account_with_token()
        data = self.gmail.attachment(account.access_token, payload.gmail_message_id, attachment_id)
        content = _decode_bytes(data.data)
        digest = hashlib.sha256(content).hexdigest()
        name = attachment.filename or f"attachment-{digest[:12]}"
        return name, content, attachment.mime_type

    async def worker_loop(self) -> None:
        while True:
            claimed = await asyncio.to_thread(self.store.claim_next)
            if claimed is None:
                await asyncio.sleep(1)
                continue
            analysis_id, payload = claimed
            self._emit(EmailEventType.ANALYSIS_STARTED, "Devin analysis started", analysis_id)
            try:
                result = await asyncio.to_thread(
                    self.agent.analyze,
                    payload,
                    functools.partial(self._load_attachment, payload),
                )
                await asyncio.to_thread(
                    self.store.complete, analysis_id, result.report, result.session_url
                )
                if result.report.verdict.value != "CLEAR":
                    account = await asyncio.to_thread(self._account_with_token)
                    await asyncio.to_thread(
                        self.gmail.modify_labels,
                        account.access_token,
                        payload.gmail_message_id,
                        add=[account.labels.pending_review],
                        remove=[
                            account.labels.confirmed_dangerous,
                            account.labels.not_dangerous,
                        ],
                    )
                    self._emit(EmailEventType.FLAGGED, result.report.summary, analysis_id)
                    if self.incident_sink is not None:
                        self.incident_sink(
                            source=IncidentSource.EMAIL,
                            severity=(
                                IncidentSeverity.CRITICAL
                                if result.report.risk_score >= 70
                                else IncidentSeverity.WARNING
                            ),
                            title=f"Flagged email: {payload.subject}",
                            summary=result.report.summary,
                            verdict=result.report.verdict.value,
                            risk_score=result.report.risk_score,
                            ref=payload.gmail_message_id,
                        )
                else:
                    self._emit(
                        EmailEventType.ANALYSIS_COMPLETED, result.report.summary, analysis_id
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await asyncio.to_thread(self.store.fail, analysis_id, str(exc))
                with contextlib.suppress(Exception):
                    account = await asyncio.to_thread(self._account_with_token)
                    await asyncio.to_thread(
                        self.gmail.modify_labels,
                        account.access_token,
                        payload.gmail_message_id,
                        add=[account.labels.pending_review],
                        remove=[],
                    )
                self._emit(
                    EmailEventType.FAILED, "Analysis failed; manual review required", analysis_id
                )

    async def maintenance_loop(self) -> None:
        while True:
            await asyncio.sleep(3600)
            await asyncio.to_thread(self.store.purge_old, settings.email_report_retention_days)
            account = self.store.get_account()
            if account and account.watch_expiration < time.time() + 2 * 86400:
                refreshed = await asyncio.to_thread(self._account_with_token)
                watch = await asyncio.to_thread(
                    self.gmail.watch,
                    refreshed.access_token,
                    refreshed.mode,
                    refreshed.labels.scan,
                )
                self.store.save_account(
                    replace(refreshed, watch_expiration=float(watch.expiration) / 1000)
                )

    def start_subscriber(self, loop: asyncio.AbstractEventLoop) -> None:
        if not settings.gmail_pubsub_subscription:
            return
        self._subscriber = pubsub_v1.SubscriberClient()

        def callback(message: Any) -> None:
            try:
                notification = GmailNotification.model_validate_json(message.data)
                account = self.store.get_account()
                if (
                    account is None
                    or notification.emailAddress.casefold() != account.email.casefold()
                ):
                    message.ack()
                    return
                future = asyncio.run_coroutine_threadsafe(
                    self.sync_history(notification.historyId), loop
                )
                future.result(timeout=60)
                message.ack()
            except Exception:
                message.nack()

        self._streaming_future = self._subscriber.subscribe(
            settings.gmail_pubsub_subscription, callback=callback
        )

    def stop_subscriber(self) -> None:
        if self._streaming_future is not None:
            self._streaming_future.cancel()
        if self._subscriber is not None:
            self._subscriber.close()

    def create_session(self) -> tuple[str, str]:
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        self.store.save_session(token, csrf)
        return token, csrf

    def valid_session(self, token: str | None) -> bool:
        return bool(token and self.store.session_csrf(token))

    def valid_csrf(self, token: str | None, csrf: str | None) -> bool:
        expected = self.store.session_csrf(token) if token else None
        return bool(expected and csrf and secrets.compare_digest(expected, csrf))

    def analyses(self, cursor: int | None = None) -> EmailAnalysisList:
        return self.store.list_analyses(cursor)

    def analysis(self, analysis_id: int) -> EmailAnalysisDetail | None:
        return self.store.get_analysis(analysis_id)

    def review(self, analysis_id: int, decision: EmailReviewDecision) -> EmailAnalysisDetail:
        detail = self.store.get_analysis(analysis_id)
        if detail is None:
            raise KeyError(analysis_id)
        account = self._account_with_token()
        add = (
            account.labels.confirmed_dangerous
            if decision is EmailReviewDecision.CONFIRMED_DANGEROUS
            else account.labels.not_dangerous
        )
        remove = [
            account.labels.pending_review,
            account.labels.not_dangerous,
            account.labels.confirmed_dangerous,
        ]
        remove.remove(add)
        self.gmail.modify_labels(
            account.access_token, detail.gmail_message_id, add=[add], remove=remove
        )
        self.store.review(analysis_id, decision)
        self._emit(EmailEventType.REVIEWED, f"Review saved: {decision.value}", analysis_id)
        updated = self.store.get_analysis(analysis_id)
        assert updated is not None
        return updated


_service: EmailSecurityService | None = None


def get_email_service() -> EmailSecurityService:
    global _service
    if _service is None:
        _service = EmailSecurityService()
    return _service


def reset_email_service() -> None:
    global _service
    _service = None
