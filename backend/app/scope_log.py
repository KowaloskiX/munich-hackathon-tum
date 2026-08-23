"""Append-only SCOPE scan history, including component calls and results."""

from __future__ import annotations

import os
import threading
from pathlib import Path

from .models import ScopeHistoryLog

_WRITE_LOCK = threading.Lock()


def append_scope_history(path: Path, record: ScopeHistoryLog) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with _WRITE_LOCK, open(path, "a", encoding="utf-8") as handle:
        handle.write(record.model_dump_json() + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def read_scope_history(path: Path) -> list[ScopeHistoryLog]:
    if not path.exists():
        return []
    return [
        ScopeHistoryLog.model_validate_json(line)
        for raw in path.read_text(encoding="utf-8").splitlines()
        if (line := raw.strip())
    ]
