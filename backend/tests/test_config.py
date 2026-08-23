"""Config defaults and credential-safe representation."""

from app.config import Settings


def test_default_origins_support_localhost_and_loopback() -> None:
    settings = Settings(_env_file=None)

    assert "http://localhost:5173" in settings.allowed_origins
    assert "http://127.0.0.1:5173" in settings.allowed_origins


def test_settings_repr_hides_secret_keys():
    settings = Settings(
        _env_file=None,
        devin_api_key="devin-secret",
        langfuse_secret_key="langfuse-secret",
    )

    rendered = repr(settings)
    assert "devin-secret" not in rendered
    assert "langfuse-secret" not in rendered
