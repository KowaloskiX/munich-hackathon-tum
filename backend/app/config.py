"""Typed settings loaded from environment / .env (see .env.example).

Keeps all runtime knobs in one typed place instead of scattered os.environ reads.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Which agent backend the orchestrator talks to.
    agent: str = "stub"  # "stub" | "devin"
    # Which scout backs the web/link domain. "devin" runs a real browse+research
    # scout on any URL; "stub" is an offline host heuristic (default: cheap CI).
    link_agent: str = "stub"  # "stub" | "devin"

    # Devin external API (v3). PATs (cog_...) and service-user keys use v3;
    # the legacy v1 endpoints reject PATs with 403.
    devin_api_key: str = ""
    devin_base_url: str = "https://api.devin.ai/v3"
    devin_org_id: str = ""  # auto-discovered via GET /self when blank
    devin_poll_interval_s: float = 5.0
    devin_timeout_s: float = 900.0  # sessions can run several minutes
    # Cost / VM lifecycle. Devin bills in ACUs.
    devin_usd_per_acu: float = 0.0  # set a rate to also report USD (0 = off)
    devin_max_acu_limit: float = 10.0  # hard per-session ACU ceiling
    devin_resumable: bool = False  # False = disposable VM, torn down on stop
    devin_terminate_on_done: bool = True  # DELETE the session when finished (no idle VM)

    # Langfuse (local instance is fine, e.g. http://localhost:3000).
    langfuse_public_key: str = ""
    langfuse_secret_key: str = ""
    langfuse_host: str = "http://localhost:3000"

    @property
    def langfuse_enabled(self) -> bool:
        return bool(self.langfuse_public_key and self.langfuse_secret_key)


settings = Settings()
