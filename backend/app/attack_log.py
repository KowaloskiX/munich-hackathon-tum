"""Atomic JSON persistence for autonomous attack-response analytics."""

from __future__ import annotations

import json
import os
import tempfile
import threading
from hashlib import sha256
from pathlib import Path

from .models import AttackResponseArchive, AttackResponseLog

_WRITE_LOCK = threading.Lock()


def capture_sha256(frames: list[str]) -> str:
    """Hash a capture without persisting potentially sensitive raw frames."""
    return sha256("\n".join(frames).encode()).hexdigest()


def filter_sha256(filter_c_code: str) -> str:
    return sha256(filter_c_code.encode()).hexdigest()


def append_attack_response(path: Path, response: AttackResponseLog) -> None:
    """Append one response and atomically replace the valid JSON archive."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with _WRITE_LOCK:
        archive = (
            AttackResponseArchive.model_validate_json(path.read_text(encoding="utf-8"))
            if path.exists()
            else AttackResponseArchive()
        )
        archive.responses.append(response)
        payload = json.dumps(archive.model_dump(mode="json"), indent=2) + "\n"

        temp_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
            ) as temp:
                temp_name = temp.name
                temp.write(payload)
                temp.flush()
                os.fsync(temp.fileno())
            os.replace(temp_name, path)
        finally:
            if temp_name is not None:
                Path(temp_name).unlink(missing_ok=True)
