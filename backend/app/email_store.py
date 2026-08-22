"""Persistent single-account state for Gmail threat review."""

from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .models import (
    EmailAnalysisDetail,
    EmailAnalysisList,
    EmailAnalysisStatus,
    EmailAnalysisSummary,
    EmailLabels,
    EmailMonitoringMode,
    EmailPayload,
    EmailReviewDecision,
    EmailVerdict,
    ThreatReport,
)


@dataclass(frozen=True)
class GmailAccountRecord:
    email: str
    access_token: str
    refresh_token: str
    token_expires_at: float
    mode: EmailMonitoringMode
    history_id: str
    watch_expiration: float
    labels: EmailLabels
    last_sync: float | None


@dataclass(frozen=True)
class OAuthStateRecord:
    verifier: str
    return_to: str


class SecretBox:
    def __init__(self, key: str) -> None:
        if not key:
            raise ValueError("EMAIL_TOKEN_ENCRYPTION_KEY is required")
        try:
            self._fernet = Fernet(key.encode())
        except (TypeError, ValueError) as exc:
            raise ValueError("EMAIL_TOKEN_ENCRYPTION_KEY must be a Fernet key") from exc

    def encrypt(self, value: str) -> str:
        return self._fernet.encrypt(value.encode()).decode()

    def decrypt(self, value: str) -> str:
        try:
            return self._fernet.decrypt(value.encode()).decode()
        except InvalidToken as exc:
            raise ValueError("encrypted email data cannot be decrypted") from exc


class EmailStore:
    def __init__(self, path: str, secrets: SecretBox) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.secrets = secrets
        self._lock = threading.Lock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS gmail_account (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    email TEXT NOT NULL,
                    access_token TEXT NOT NULL,
                    refresh_token TEXT NOT NULL,
                    token_expires_at REAL NOT NULL,
                    mode TEXT NOT NULL,
                    history_id TEXT NOT NULL,
                    watch_expiration REAL NOT NULL,
                    labels_json TEXT NOT NULL,
                    last_sync REAL
                );
                CREATE TABLE IF NOT EXISTS email_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    gmail_message_id TEXT NOT NULL UNIQUE,
                    gmail_thread_id TEXT NOT NULL,
                    from_address TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    snippet TEXT NOT NULL,
                    received_at REAL NOT NULL,
                    status TEXT NOT NULL,
                    verdict TEXT,
                    risk_score INTEGER,
                    review_decision TEXT,
                    payload_ciphertext TEXT,
                    report_json TEXT,
                    devin_session_url TEXT,
                    error TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_email_analysis_status
                    ON email_analysis(status, received_at DESC);
                CREATE TABLE IF NOT EXISTS email_review (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER NOT NULL REFERENCES email_analysis(id) ON DELETE CASCADE,
                    decision TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS app_session (
                    token_hash TEXT PRIMARY KEY,
                    csrf_token TEXT NOT NULL,
                    expires_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS oauth_state (
                    state TEXT PRIMARY KEY,
                    verifier TEXT NOT NULL,
                    return_to TEXT NOT NULL,
                    expires_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY
                );
                INSERT OR IGNORE INTO schema_version(version) VALUES (1);
                UPDATE email_analysis SET status='QUEUED' WHERE status='ANALYZING';
                """
            )

    def save_account(self, account: GmailAccountRecord) -> None:
        values = (
            account.email,
            self.secrets.encrypt(account.access_token),
            self.secrets.encrypt(account.refresh_token),
            account.token_expires_at,
            account.mode.value,
            account.history_id,
            account.watch_expiration,
            account.labels.model_dump_json(),
            account.last_sync,
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO gmail_account (
                    singleton, email, access_token, refresh_token, token_expires_at,
                    mode, history_id, watch_expiration, labels_json, last_sync
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(singleton) DO UPDATE SET
                    email=excluded.email, access_token=excluded.access_token,
                    refresh_token=excluded.refresh_token,
                    token_expires_at=excluded.token_expires_at, mode=excluded.mode,
                    history_id=excluded.history_id,
                    watch_expiration=excluded.watch_expiration,
                    labels_json=excluded.labels_json, last_sync=excluded.last_sync
                """,
                values,
            )

    def get_account(self) -> GmailAccountRecord | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM gmail_account WHERE singleton=1").fetchone()
        if row is None:
            return None
        return GmailAccountRecord(
            email=str(row["email"]),
            access_token=self.secrets.decrypt(str(row["access_token"])),
            refresh_token=self.secrets.decrypt(str(row["refresh_token"])),
            token_expires_at=float(row["token_expires_at"]),
            mode=EmailMonitoringMode(str(row["mode"])),
            history_id=str(row["history_id"]),
            watch_expiration=float(row["watch_expiration"]),
            labels=EmailLabels.model_validate_json(str(row["labels_json"])),
            last_sync=float(row["last_sync"]) if row["last_sync"] is not None else None,
        )

    def delete_all(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM gmail_account")
            conn.execute("DELETE FROM email_analysis")
            conn.execute("DELETE FROM app_session")
            conn.execute("DELETE FROM oauth_state")

    def update_cursor(self, history_id: str, synced_at: float) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE gmail_account SET history_id=?, last_sync=? WHERE singleton=1",
                (history_id, synced_at),
            )

    def save_oauth_state(self, state: str, verifier: str, return_to: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM oauth_state WHERE expires_at < ?", (time.time(),))
            conn.execute(
                "INSERT INTO oauth_state VALUES (?, ?, ?, ?)",
                (state, verifier, return_to, time.time() + 600),
            )

    def consume_oauth_state(self, state: str) -> OAuthStateRecord | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM oauth_state WHERE state=? AND expires_at>=?", (state, time.time())
            ).fetchone()
            conn.execute("DELETE FROM oauth_state WHERE state=?", (state,))
        if row is None:
            return None
        return OAuthStateRecord(verifier=str(row["verifier"]), return_to=str(row["return_to"]))

    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def save_session(self, token: str, csrf_token: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM app_session WHERE expires_at < ?", (time.time(),))
            conn.execute(
                "INSERT OR REPLACE INTO app_session VALUES (?, ?, ?)",
                (self.hash_token(token), csrf_token, time.time() + 30 * 86400),
            )

    def session_csrf(self, token: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT csrf_token FROM app_session WHERE token_hash=? AND expires_at>=?",
                (self.hash_token(token), time.time()),
            ).fetchone()
        return str(row["csrf_token"]) if row is not None else None

    def enqueue(self, payload: EmailPayload) -> int | None:
        now = time.time()
        ciphertext = self.secrets.encrypt(payload.model_dump_json())
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO email_analysis (
                    gmail_message_id, gmail_thread_id, from_address, subject, snippet,
                    received_at, status, payload_ciphertext, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.gmail_message_id,
                    payload.gmail_thread_id,
                    payload.from_address,
                    payload.subject,
                    payload.snippet,
                    payload.received_at,
                    EmailAnalysisStatus.QUEUED.value,
                    ciphertext,
                    now,
                    now,
                ),
            )
            lastrowid = cursor.lastrowid
            return int(lastrowid) if cursor.rowcount and lastrowid is not None else None

    def existing_message_ids(self, message_ids: list[str]) -> set[str]:
        if not message_ids:
            return set()
        placeholders = ",".join("?" for _ in message_ids)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT gmail_message_id FROM email_analysis "
                f"WHERE gmail_message_id IN ({placeholders})",
                message_ids,
            ).fetchall()
        return {str(row["gmail_message_id"]) for row in rows}

    def claim_next(self) -> tuple[int, EmailPayload] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, payload_ciphertext FROM email_analysis
                WHERE status=? ORDER BY received_at LIMIT 1
                """,
                (EmailAnalysisStatus.QUEUED.value,),
            ).fetchone()
            if row is None:
                return None
            analysis_id = int(row["id"])
            updated = conn.execute(
                "UPDATE email_analysis SET status=?, updated_at=? WHERE id=? AND status=?",
                (
                    EmailAnalysisStatus.ANALYZING.value,
                    time.time(),
                    analysis_id,
                    EmailAnalysisStatus.QUEUED.value,
                ),
            )
            if updated.rowcount != 1:
                return None
        plaintext = self.secrets.decrypt(str(row["payload_ciphertext"]))
        return analysis_id, EmailPayload.model_validate_json(plaintext)

    def complete(self, analysis_id: int, report: ThreatReport, session_url: str | None) -> None:
        status = (
            EmailAnalysisStatus.CLEAR
            if report.verdict is EmailVerdict.CLEAR
            else EmailAnalysisStatus.PENDING_REVIEW
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE email_analysis SET status=?, verdict=?, risk_score=?, report_json=?,
                    devin_session_url=?, payload_ciphertext=NULL, error=NULL, updated_at=?
                WHERE id=?
                """,
                (
                    status.value,
                    report.verdict.value,
                    report.risk_score,
                    report.model_dump_json(),
                    session_url,
                    time.time(),
                    analysis_id,
                ),
            )

    def fail(self, analysis_id: int, error: str) -> None:
        report = ThreatReport(
            verdict=EmailVerdict.INCONCLUSIVE,
            risk_score=50,
            confidence=0.0,
            summary="Automated analysis failed; manual review required.",
            recommended_actions=["Review the message manually."],
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE email_analysis SET status=?, verdict=?, risk_score=?, report_json=?,
                    payload_ciphertext=NULL, error=?, updated_at=? WHERE id=?
                """,
                (
                    EmailAnalysisStatus.FAILED.value,
                    EmailVerdict.INCONCLUSIVE.value,
                    50,
                    report.model_dump_json(),
                    error[:1000],
                    time.time(),
                    analysis_id,
                ),
            )

    def review(self, analysis_id: int, decision: EmailReviewDecision) -> None:
        with self._lock, self._connect() as conn:
            updated = conn.execute(
                """
                UPDATE email_analysis SET status=?, review_decision=?, updated_at=? WHERE id=?
                """,
                (EmailAnalysisStatus.REVIEWED.value, decision.value, time.time(), analysis_id),
            )
            if updated.rowcount != 1:
                raise KeyError(analysis_id)
            conn.execute(
                "INSERT INTO email_review(analysis_id, decision, created_at) VALUES (?, ?, ?)",
                (analysis_id, decision.value, time.time()),
            )

    def _summary(self, row: sqlite3.Row) -> EmailAnalysisSummary:
        return EmailAnalysisSummary(
            id=int(row["id"]),
            gmail_message_id=str(row["gmail_message_id"]),
            from_address=str(row["from_address"]),
            subject=str(row["subject"]),
            snippet=str(row["snippet"]),
            received_at=float(row["received_at"]),
            status=EmailAnalysisStatus(str(row["status"])),
            verdict=EmailVerdict(str(row["verdict"])) if row["verdict"] else None,
            risk_score=int(row["risk_score"]) if row["risk_score"] is not None else None,
            review_decision=(
                EmailReviewDecision(str(row["review_decision"])) if row["review_decision"] else None
            ),
        )

    def list_analyses(self, cursor: int | None = None, limit: int = 50) -> EmailAnalysisList:
        sql = "SELECT * FROM email_analysis"
        params: list[int] = []
        if cursor is not None:
            sql += " WHERE id < ?"
            params.append(cursor)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit + 1)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        items = [self._summary(row) for row in rows[:limit]]
        next_cursor = items[-1].id if len(rows) > limit and items else None
        return EmailAnalysisList(items=items, next_cursor=next_cursor)

    def get_analysis(self, analysis_id: int) -> EmailAnalysisDetail | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM email_analysis WHERE id=?", (analysis_id,)).fetchone()
        if row is None:
            return None
        summary = self._summary(row)
        return EmailAnalysisDetail(
            **summary.model_dump(),
            report=(
                ThreatReport.model_validate_json(str(row["report_json"]))
                if row["report_json"]
                else None
            ),
            devin_session_url=(str(row["devin_session_url"]) if row["devin_session_url"] else None),
            error=str(row["error"]) if row["error"] else None,
        )

    def purge_old(self, retention_days: int) -> None:
        cutoff = time.time() - retention_days * 86400
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM email_analysis WHERE created_at < ?", (cutoff,))
