"""Settings must not leak credentials through errors or debug output."""

from app.config import Settings


def test_settings_repr_hides_secret_keys():
    settings = Settings(
        _env_file=None,
        devin_api_key="devin-secret",
        langfuse_secret_key="langfuse-secret",
    )

    rendered = repr(settings)
    assert "devin-secret" not in rendered
    assert "langfuse-secret" not in rendered
