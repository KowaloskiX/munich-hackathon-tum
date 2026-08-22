import base64

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from app.email_agent import StubEmailThreatAgent
from app.email_service import EmailSecurityService, parse_message
from app.email_store import EmailStore, GmailAccountRecord, SecretBox
from app.gmail_client import GmailClient
from app.models import (
    EmailAnalysisStatus,
    EmailImportRequest,
    EmailLabels,
    EmailMonitoringMode,
    EmailPayload,
    EmailReviewDecision,
    GmailBody,
    GmailHeader,
    GmailMessage,
    GmailMessageList,
    GmailMessageRef,
    GmailPart,
)


def _encoded(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")


def _payload(message_id: str = "m1") -> EmailPayload:
    return EmailPayload(
        gmail_message_id=message_id,
        gmail_thread_id="t1",
        from_address="Sender <sender@example.com>",
        to_addresses=["owner@example.com"],
        subject="Urgent: verify your account",
        received_at=1.0,
        snippet="Verify now",
        body="Verify your account password now.",
    )


def test_parse_message_extracts_text_links_and_attachments(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "email_max_body_chars", 10_000)
    message = GmailMessage(
        id="m1",
        threadId="t1",
        labelIds=["INBOX"],
        snippet="hello",
        internalDate="2000",
        payload=GmailPart(
            mimeType="multipart/mixed",
            headers=[
                GmailHeader(name="From", value="Alice <alice@example.com>"),
                GmailHeader(name="To", value="owner@example.com"),
                GmailHeader(name="Subject", value="Invoice"),
            ],
            parts=[
                GmailPart(
                    mimeType="text/html",
                    body=GmailBody(
                        data=_encoded('<p>Open <a href="https://example.com/login">portal</a></p>')
                    ),
                ),
                GmailPart(
                    mimeType="application/pdf",
                    filename="invoice.pdf",
                    body=GmailBody(attachmentId="a1", size=123),
                ),
            ],
        ),
    )

    parsed = parse_message(message)
    assert parsed.subject == "Invoice"
    assert parsed.body == "Open portal"
    assert parsed.links[0].host == "example.com"
    assert parsed.attachments[0].filename == "invoice.pdf"


def test_store_encrypts_payload_deduplicates_and_records_review(tmp_path):
    store = EmailStore(str(tmp_path / "email.db"), SecretBox(Fernet.generate_key().decode()))
    first = store.enqueue(_payload())
    assert first is not None
    assert store.enqueue(_payload()) is None

    claimed = store.claim_next()
    assert claimed is not None
    analysis_id, payload = claimed
    result = StubEmailThreatAgent().analyze(payload, lambda _: ("", b"", ""))
    store.complete(analysis_id, result.report, None)
    detail = store.get_analysis(analysis_id)
    assert detail is not None
    assert detail.status is EmailAnalysisStatus.PENDING_REVIEW
    assert detail.report is not None
    assert detail.report.risk_score == 82

    store.review(analysis_id, EmailReviewDecision.NOT_DANGEROUS)
    reviewed = store.get_analysis(analysis_id)
    assert reviewed is not None
    assert reviewed.review_decision is EmailReviewDecision.NOT_DANGEROUS


def test_stub_agent_marks_benign_mail_clear():
    payload = _payload()
    payload.subject = "Meeting notes"
    payload.body = "Thanks for today's meeting."
    result = StubEmailThreatAgent().analyze(payload, lambda _: ("", b"", ""))
    assert result.report.verdict.value == "CLEAR"
    assert result.report.risk_score < 20


class _ImportGmail(GmailClient):
    def __init__(self, messages: list[GmailMessage]) -> None:
        self.messages_by_id = {message.id: message for message in messages}
        self.requested: tuple[str | None, int, str | None] | None = None
        self.fetched_ids: list[str] = []

    def recent_messages(
        self,
        access_token: str,
        label_id: str | None,
        limit: int,
        page_token: str | None = None,
    ) -> GmailMessageList:
        self.requested = (label_id, limit, page_token)
        return GmailMessageList(
            messages=[
                GmailMessageRef(id=message.id, threadId=message.threadId)
                for message in self.messages_by_id.values()
            ],
            nextPageToken="older-page",
        )

    def message(self, access_token: str, message_id: str) -> GmailMessage:
        self.fetched_ids.append(message_id)
        return self.messages_by_id[message_id]


def _gmail_message(message_id: str, internal_date: str = "2000") -> GmailMessage:
    return GmailMessage(
        id=message_id,
        threadId=f"thread-{message_id}",
        labelIds=["INBOX"],
        snippet=f"Snippet {message_id}",
        internalDate=internal_date,
        payload=GmailPart(
            mimeType="text/plain",
            headers=[
                GmailHeader(name="From", value="sender@example.com"),
                GmailHeader(name="Subject", value=f"Message {message_id}"),
            ],
            body=GmailBody(data=_encoded("A harmless message.")),
        ),
    )


def test_preview_and_selected_import_are_newest_first_and_deduplicated(tmp_path):
    store = EmailStore(str(tmp_path / "email.db"), SecretBox(Fernet.generate_key().decode()))
    first = _gmail_message("m1")
    second = _gmail_message("m2", "3000")
    store.enqueue(parse_message(first))
    store.save_account(
        GmailAccountRecord(
            email="owner@example.com",
            access_token="access",
            refresh_token="refresh",
            token_expires_at=9_999_999_999,
            mode=EmailMonitoringMode.SELECTED,
            history_id="10",
            watch_expiration=9_999_999_999,
            labels=EmailLabels(scan="SCAN"),
            last_sync=1.0,
        )
    )
    gmail = _ImportGmail([first, second])
    service = EmailSecurityService(gmail=gmail, store=store, agent=StubEmailThreatAgent())

    preview = service.recent_messages(10, "current-page")
    gmail.fetched_ids.clear()
    result = service.import_selected(["m1", "m2", "m2"])

    assert [item.gmail_message_id for item in preview.items] == ["m2", "m1"]
    assert [item.already_imported for item in preview.items] == [False, True]
    assert preview.next_page_token == "older-page"
    assert result.scanned == 2
    assert result.imported == 1
    assert result.duplicates == 1
    assert gmail.requested == (None, 10, "current-page")
    assert gmail.fetched_ids == ["m2"]
    assert len(store.list_analyses().items) == 2


def test_selected_import_rejects_empty_and_malformed_message_ids():
    assert EmailImportRequest(message_ids=[], limit=10).limit == 10
    assert EmailImportRequest(message_ids=["gmail_id"], limit=None).message_ids == ["gmail_id"]
    with pytest.raises(ValidationError):
        EmailImportRequest(message_ids=[])
    with pytest.raises(ValidationError):
        EmailImportRequest(message_ids=["not a Gmail id"])
    with pytest.raises(ValidationError):
        EmailImportRequest(message_ids=["gmail_id"], limit=10)


def test_quick_import_does_not_download_existing_messages(tmp_path):
    store = EmailStore(str(tmp_path / "email.db"), SecretBox(Fernet.generate_key().decode()))
    first = _gmail_message("m1")
    second = _gmail_message("m2", "3000")
    store.enqueue(parse_message(first))
    store.save_account(
        GmailAccountRecord(
            email="owner@example.com",
            access_token="access",
            refresh_token="refresh",
            token_expires_at=9_999_999_999,
            mode=EmailMonitoringMode.ALL,
            history_id="10",
            watch_expiration=9_999_999_999,
            labels=EmailLabels(scan="SCAN"),
            last_sync=1.0,
        )
    )
    gmail = _ImportGmail([first, second])
    service = EmailSecurityService(gmail=gmail, store=store, agent=StubEmailThreatAgent())

    result = service.import_recent(10)

    assert result.scanned == 2
    assert result.imported == 1
    assert result.duplicates == 1
    assert gmail.fetched_ids == ["m2"]
