from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from sleep_vulndb.cli import main
from sleep_vulndb.config import DEFAULT_OSV_ECOSYSTEMS
from sleep_vulndb.scheduler import write_heartbeat
from sleep_vulndb.sources.osv import OSV_SOURCES, _insert

from conftest import load_record


@pytest.fixture(autouse=True)
def environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    for variable in ("SLEEP_VULNDB_SOURCES", "SLEEP_VULNDB_OSV_ECOSYSTEMS"):
        monkeypatch.delenv(variable, raising=False)
    heartbeat = tmp_path / "heartbeat"
    monkeypatch.setenv("SLEEP_VULNDB_HEARTBEAT_PATH", str(heartbeat))
    return heartbeat


def test_status_lists_every_source(sessions: sessionmaker[Session], capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["status"], sessions=sessions) == 0
    output = capsys.readouterr().out
    for source in ("osv-debian", "osv-ubuntu", "epss", "kev"):
        assert source in output
    assert "never" in output


def test_lookup_prints_findings(sessions: sessionmaker[Session], capsys: pytest.CaptureFixture[str]) -> None:
    advisory = OSV_SOURCES["osv-ubuntu"].parse(load_record("UBUNTU-CVE-2024-6387"), frozenset(DEFAULT_OSV_ECOSYSTEMS))
    assert advisory is not None
    with sessions() as session:
        _insert(session, [advisory])
        session.commit()

    arguments = ["lookup", "--ecosystem", "Ubuntu:22.04:LTS", "--package", "openssh", "--version"]
    assert main([*arguments, "1:8.9p1-3ubuntu0.6"], sessions=sessions) == 0
    assert "CVE-2024-6387" in capsys.readouterr().out

    assert main([*arguments, "1:8.9p1-3ubuntu0.10"], sessions=sessions) == 0
    assert "No known vulnerabilities" in capsys.readouterr().out

    assert main([*arguments, "not-a-version"], sessions=sessions) == 2


def test_health_requires_a_fresh_heartbeat(sessions: sessionmaker[Session], environment: Path) -> None:
    assert main(["health"], sessions=sessions) == 1
    write_heartbeat(str(environment))
    assert main(["health"], sessions=sessions) == 0


def test_configuration_errors_are_reported(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SLEEP_VULNDB_SOURCES", "nvd")
    assert main(["status"], sessions=sessions) == 2
    assert "nvd" in capsys.readouterr().err
