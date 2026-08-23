"""Durable normalized evidence, COMMAND assessments, and company reports."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections import defaultdict
from pathlib import Path

from .models import (
    CommandAssessmentSummary,
    CommandMetrics,
    CommandReport,
    CommandReportSummary,
    EvidenceProvenance,
    EvidenceSource,
    IntelligenceObservation,
)


class IntelligenceStore:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS intelligence_observation (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT NOT NULL UNIQUE,
                    occurred_ts REAL NOT NULL,
                    recorded_ts REAL NOT NULL,
                    source TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    risk_score INTEGER,
                    entities_json TEXT NOT NULL,
                    source_ref TEXT NOT NULL,
                    provenance TEXT NOT NULL,
                    evidence_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_intel_time
                    ON intelligence_observation(occurred_ts DESC);
                CREATE TABLE IF NOT EXISTS command_assessment (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    observation_id INTEGER NOT NULL UNIQUE,
                    created_ts REAL NOT NULL,
                    completed_ts REAL,
                    status TEXT NOT NULL,
                    decision TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL DEFAULT '',
                    report_id TEXT,
                    session_url TEXT,
                    error TEXT,
                    FOREIGN KEY(observation_id) REFERENCES intelligence_observation(id)
                );
                CREATE INDEX IF NOT EXISTS idx_assessment_status
                    ON command_assessment(status, created_ts);
                CREATE TABLE IF NOT EXISTS command_report (
                    id TEXT PRIMARY KEY,
                    created_ts REAL NOT NULL,
                    report_json TEXT NOT NULL
                );
                UPDATE command_assessment SET status='PENDING' WHERE status='RUNNING';
                """
            )

    def add_observation(
        self,
        observation: IntelligenceObservation,
        *,
        fingerprint: str,
        trigger: bool = True,
    ) -> tuple[int, bool]:
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO intelligence_observation (
                    fingerprint, occurred_ts, recorded_ts, source, event_type,
                    severity, title, summary, verdict, risk_score, entities_json,
                    source_ref, provenance, evidence_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fingerprint,
                    observation.occurred_ts,
                    observation.recorded_ts,
                    observation.source.value,
                    observation.event_type,
                    observation.severity.value,
                    observation.title,
                    observation.summary,
                    observation.verdict,
                    observation.risk_score,
                    observation.entities.model_dump_json(),
                    observation.source_ref,
                    observation.provenance.value,
                    json.dumps(observation.evidence, separators=(",", ":")),
                ),
            )
            inserted = cursor.rowcount == 1
            row = conn.execute(
                "SELECT id FROM intelligence_observation WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
            assert row is not None
            observation_id = int(row["id"])
            if inserted and trigger:
                conn.execute(
                    "INSERT INTO command_assessment(observation_id, created_ts, status) "
                    "VALUES (?, ?, 'PENDING')",
                    (observation_id, time.time()),
                )
        return observation_id, inserted

    @staticmethod
    def _observation(row: sqlite3.Row) -> IntelligenceObservation:
        return IntelligenceObservation(
            id=int(row["id"]),
            occurred_ts=float(row["occurred_ts"]),
            recorded_ts=float(row["recorded_ts"]),
            source=str(row["source"]),
            event_type=str(row["event_type"]),
            severity=str(row["severity"]),
            title=str(row["title"]),
            summary=str(row["summary"]),
            verdict=str(row["verdict"]),
            risk_score=int(row["risk_score"]) if row["risk_score"] is not None else None,
            entities=json.loads(str(row["entities_json"])),
            source_ref=str(row["source_ref"]),
            provenance=str(row["provenance"]),
            evidence=json.loads(str(row["evidence_json"])),
        )

    def observations(
        self, *, since: float = 0.0, limit: int = 500
    ) -> list[IntelligenceObservation]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM intelligence_observation WHERE occurred_ts>=? "
                "ORDER BY occurred_ts DESC, id DESC LIMIT ?",
                (since, limit),
            ).fetchall()
        return [self._observation(row) for row in rows]

    def metrics(self, now: float | None = None) -> CommandMetrics:
        end = now or time.time()
        current_start = end - 86400
        baseline_start = current_start - 7 * 86400
        observations = self.observations(since=baseline_start, limit=5000)
        current_email = [
            item
            for item in observations
            if item.source is EvidenceSource.INBOX and item.occurred_ts >= current_start
        ]
        baseline_email = [
            item
            for item in observations
            if item.source is EvidenceSource.INBOX and item.occurred_ts < current_start
        ]

        def flagged(items: list[IntelligenceObservation]) -> int:
            return sum(1 for item in items if item.verdict in {"FLAGGED", "INCONCLUSIVE"})

        current_flagged = flagged(current_email)
        baseline_flagged = flagged(baseline_email)
        current_rate = current_flagged / len(current_email) if current_email else 0.0
        baseline_rate = baseline_flagged / len(baseline_email) if baseline_email else 0.0
        entity_sources: dict[str, set[EvidenceSource]] = defaultdict(set)
        for item in observations:
            for values in item.entities.model_dump().values():
                for value in values:
                    entity_sources[str(value).casefold()].add(item.source)
        shared = sorted(entity for entity, sources in entity_sources.items() if len(sources) > 1)
        return CommandMetrics(
            window_end_ts=end,
            email_current_total=len(current_email),
            email_current_flagged=current_flagged,
            email_baseline_total=len(baseline_email),
            email_baseline_flagged=baseline_flagged,
            current_flagged_rate=current_rate,
            baseline_flagged_rate=baseline_rate,
            phishing_spike=(current_flagged >= 3 and current_rate >= max(0.25, baseline_rate * 2)),
            signal_incidents=sum(
                1
                for item in observations
                if item.source is EvidenceSource.SIGNAL and item.occurred_ts >= current_start
            ),
            malicious_scope_checks=sum(
                1
                for item in observations
                if item.source is EvidenceSource.SCOPE
                and item.occurred_ts >= current_start
                and item.verdict == "malicious"
            ),
            shared_entities=shared[:30],
        )

    def claim_pending(self, *, before: float, limit: int = 100) -> list[int]:
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT id FROM command_assessment WHERE status='PENDING' "
                "AND created_ts<=? ORDER BY id LIMIT ?",
                (before, limit),
            ).fetchall()
            ids = [int(row["id"]) for row in rows]
            if ids:
                marks = ",".join("?" for _ in ids)
                conn.execute(
                    f"UPDATE command_assessment SET status='RUNNING' WHERE id IN ({marks})",
                    ids,
                )
            conn.commit()
        return ids

    def complete_assessments(
        self,
        ids: list[int],
        *,
        decision: str,
        reason: str,
        report_id: str | None,
        session_url: str | None,
    ) -> None:
        if not ids:
            return
        marks = ",".join("?" for _ in ids)
        with self._lock, self._connect() as conn:
            conn.execute(
                f"UPDATE command_assessment SET status='COMPLETED', completed_ts=?, "
                f"decision=?, reason=?, report_id=?, session_url=? WHERE id IN ({marks})",
                [time.time(), decision, reason, report_id, session_url, *ids],
            )

    def fail_assessments(self, ids: list[int], error: str) -> None:
        if not ids:
            return
        marks = ",".join("?" for _ in ids)
        with self._lock, self._connect() as conn:
            conn.execute(
                f"UPDATE command_assessment SET status='FAILED', completed_ts=?, error=? "
                f"WHERE id IN ({marks})",
                [time.time(), error[:1000], *ids],
            )

    def assessments(self, limit: int = 20) -> list[CommandAssessmentSummary]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM command_assessment ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [
            CommandAssessmentSummary(
                id=int(row["id"]),
                created_ts=float(row["created_ts"]),
                completed_ts=(float(row["completed_ts"]) if row["completed_ts"] else None),
                status=str(row["status"]),
                decision=str(row["decision"]),
                reason=str(row["reason"]),
                report_id=str(row["report_id"]) if row["report_id"] else None,
                session_url=str(row["session_url"]) if row["session_url"] else None,
                error=str(row["error"]) if row["error"] else None,
            )
            for row in rows
        ]

    def save_report(self, report: CommandReport) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO command_report(id, created_ts, report_json) VALUES (?, ?, ?)",
                (report.id, report.created_ts, report.model_dump_json()),
            )

    def next_report_id(self, now: float | None = None) -> str:
        timestamp = now or time.time()
        day = time.strftime("%Y%m%d", time.gmtime(timestamp))
        prefix = f"CMD-{day}-"
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM command_report WHERE id LIKE ?", (f"{prefix}%",)
            ).fetchone()
        return f"{prefix}{int(row['n']) + 1:03d}"

    def reports(self, limit: int = 50) -> list[CommandReportSummary]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT report_json FROM command_report ORDER BY created_ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [CommandReport.model_validate_json(str(row["report_json"])) for row in rows]

    def report(self, report_id: str) -> CommandReport | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT report_json FROM command_report WHERE id=?", (report_id,)
            ).fetchone()
        return CommandReport.model_validate_json(str(row["report_json"])) if row else None

    def delete_demo(self) -> None:
        with self._lock, self._connect() as conn:
            demo_ids = [
                int(row["id"])
                for row in conn.execute(
                    "SELECT id FROM intelligence_observation WHERE provenance=?",
                    (EvidenceProvenance.DEMO.value,),
                ).fetchall()
            ]
            if demo_ids:
                marks = ",".join("?" for _ in demo_ids)
                conn.execute(
                    f"DELETE FROM command_assessment WHERE observation_id IN ({marks})", demo_ids
                )
                conn.execute(
                    f"DELETE FROM intelligence_observation WHERE id IN ({marks})", demo_ids
                )
            conn.execute(
                'DELETE FROM command_report WHERE report_json LIKE \'%"provenance":"DEMO"%\''
            )
