import pytest

from sleep_vulndb.config import (
    DEFAULT_OSV_ECOSYSTEMS,
    KNOWN_SOURCES,
    ConfigurationError,
    Settings,
    parse_ecosystems,
    parse_sources,
)


def test_sources_default_to_all() -> None:
    assert parse_sources("") == KNOWN_SOURCES


def test_sources_can_be_disabled() -> None:
    assert parse_sources("none") == ()


def test_sources_are_deduplicated() -> None:
    assert parse_sources(" kev, epss ,kev") == ("kev", "epss")


def test_unknown_source_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="nvd"):
        parse_sources("kev,nvd")


def test_ecosystems() -> None:
    assert parse_ecosystems("") == frozenset(DEFAULT_OSV_ECOSYSTEMS)
    assert parse_ecosystems("*") is None
    assert parse_ecosystems("Debian:12, Ubuntu:24.04:LTS") == frozenset({"Debian:12", "Ubuntu:24.04:LTS"})


def test_settings_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SLEEP_VULNDB_SOURCES", "osv-ubuntu,kev")
    monkeypatch.setenv("SLEEP_VULNDB_OSV_BASE_URL", "https://mirror.example/osv/")
    monkeypatch.setenv("SLEEP_VULNDB_KEV_INTERVAL_MINUTES", "30")
    monkeypatch.setenv("SLEEP_VULNDB_PROXY_URL", "http://proxy.example:3128")

    settings = Settings.from_env()

    assert settings.sources == ("osv-ubuntu", "kev")
    assert settings.osv_base_url == "https://mirror.example/osv"
    assert settings.interval_minutes["kev"] == 30
    assert settings.interval_minutes["osv-ubuntu"] == 60
    assert settings.proxy_url == "http://proxy.example:3128"


def test_invalid_number_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SLEEP_VULNDB_RETRY_MINUTES", "0")
    with pytest.raises(ConfigurationError):
        Settings.from_env()
