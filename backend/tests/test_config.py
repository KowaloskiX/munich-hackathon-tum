from app.config import Settings


def test_default_origins_support_localhost_and_loopback() -> None:
    settings = Settings(_env_file=None)

    assert "http://localhost:5173" in settings.allowed_origins
    assert "http://127.0.0.1:5173" in settings.allowed_origins
