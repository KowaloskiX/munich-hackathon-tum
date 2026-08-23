"""Typed settings for the edge gateway (env / .env, EDGE_ prefix)."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class EdgeSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="EDGE_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # The real backend the edge forwards survivors to and pulls filters from.
    backend_url: str = "http://localhost:8000"
    # Port the ESP fleet posts frames to (point BACKEND_BASE_URL here).
    listen_port: int = 8100
    # How often to poll the backend for a newly deployed filter per node.
    poll_interval_s: float = 2.0
    # Where deployed filter artifacts (filter.c / filter.so / manifest) are written.
    artifact_dir: str = "deployed"


edge_settings = EdgeSettings()
