"""Persist each deployed filter as a real, inspectable artifact on disk.

Every filter the edge loads is written to a versioned tree so "deployed" leaves
something you can open, `file`, diff, and commit — not just an in-memory blob:

    <artifact_dir>/<node>/filter.c          # latest enforced source
    <artifact_dir>/<node>/filter.so         # the compiled native library
    <artifact_dir>/<node>/v<N>/filter.c     # this exact version, kept
    <artifact_dir>/<node>/manifest.json     # version, sha256, attack_class, when
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path


def persist_filter(
    artifact_dir: str,
    node_id: str,
    version: str,
    attack_class: str,
    code: str,
    so_path: str | None,
    so_sha: str,
    so_bytes: int,
    loaded_at: str,
) -> Path:
    """Write filter.c + copy filter.so + manifest for a node/version."""
    node_dir = Path(artifact_dir) / node_id
    version_dir = node_dir / version
    version_dir.mkdir(parents=True, exist_ok=True)

    (version_dir / "filter.c").write_text(code)
    (node_dir / "filter.c").write_text(code)  # convenience: the current one
    if so_path and Path(so_path).exists():
        shutil.copy(so_path, node_dir / "filter.so")

    manifest = {
        "node_id": node_id,
        "version": version,
        "attack_class": attack_class,
        "so_sha256_12": so_sha,
        "so_bytes": so_bytes,
        "loaded_at": loaded_at,
        "native": True,
    }
    (node_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return version_dir
