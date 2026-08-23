"""Append-only JSONL persistence for autonomous attack-response analytics.

One JSON object per line: O(1) append (no whole-file rewrite), streamable, and
trivial to analyse later (`jq`, pandas, replay). Distinct from the email SQLite
store — this is a low-volume, human-readable audit/memory of what the autonomous
loop did.
"""

from __future__ import annotations

import os
import threading
from hashlib import sha256
from pathlib import Path

from .models import AttackResponseLog

_WRITE_LOCK = threading.Lock()


def capture_sha256(frames: list[str]) -> str:
    """Hash a capture without persisting potentially sensitive raw frames."""
    return sha256("\n".join(frames).encode()).hexdigest()


def filter_sha256(filter_c_code: str) -> str:
    return sha256(filter_c_code.encode()).hexdigest()


def append_attack_response(path: Path, response: AttackResponseLog) -> None:
    """Append one response as a JSON line, durably (flush + fsync)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    line = response.model_dump_json() + "\n"
    with _WRITE_LOCK, open(path, "a", encoding="utf-8") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())


def read_attack_responses(path: Path) -> list[AttackResponseLog]:
    """Parse every response from the JSONL log (blank lines skipped).

    Validating through the model fills defaults for legacy lines written before
    a field existed (e.g. `agent_backend` -> "unknown").
    """
    if not path.exists():
        return []
    responses: list[AttackResponseLog] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line:
            responses.append(AttackResponseLog.model_validate_json(line))
    return responses
