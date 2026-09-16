import pytest

from sleep_api.database import database_url


def test_database_url_preserves_reserved_password_characters(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SLEEP_DATABASE_URL", raising=False)
    monkeypatch.setenv("SLEEP_DB_USER", "sleep-user")
    monkeypatch.setenv("SLEEP_DB_PASSWORD", "p@ss:/#%word")
    monkeypatch.setenv("SLEEP_DB_HOST", "postgres")
    monkeypatch.setenv("SLEEP_DB_PORT", "5432")
    monkeypatch.setenv("SLEEP_DB_NAME", "sleep")

    url = database_url()

    assert url.username == "sleep-user"
    assert url.password == "p@ss:/#%word"
    assert url.host == "postgres"
    assert url.database == "sleep"
