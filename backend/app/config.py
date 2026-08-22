"""Typed settings loaded from environment / .env (see .env.example).

Keeps all runtime knobs in one typed place instead of scattered os.environ reads.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Which agent backend the orchestrator talks to.
    agent: str = "stub"  # "stub" | "devin"

    # Devin external API (v1). Key looks like "cog_..." for service users.
    devin_api_key: str = ""
    devin_base_url: str = "https://api.devin.ai/v1"
    devin_poll_interval_s: float = 5.0
    devin_timeout_s: float = 900.0  # sessions run ~5-10 min

    # Langfuse (local instance is fine, e.g. http://localhost:3000).
    langfuse_public_key: str = ""
    langfuse_secret_key: str = ""
    langfuse_host: str = "http://localhost:3000"

    @property
    def langfuse_enabled(self) -> bool:
        return bool(self.langfuse_public_key and self.langfuse_secret_key)


settings = Settings()
