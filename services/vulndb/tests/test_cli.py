from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from sleep_vulndb.cli import main
from sleep_vulndb.config import DEFAULT_OSV_ECOSYSTEMS
from sleep_vulndb.db_models import SyncRunRecord
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
    assert "none yet" in output, "no runs are journaled yet"


def journal(sessions: sessionmaker[Session], *runs: SyncRunRecord) -> None:
    with sessions() as session:
        session.add_all(runs)
        session.commit()


def status_lines(capsys: pytest.CaptureFixture[str]) -> list[str]:
    output = capsys.readouterr().out
    return output.split("last run of each source:" if "last run" in output else "run journal, newest first:")[1].splitlines()


def test_status_shows_the_last_run_of_each_source(
    sessions: sessionmaker[Session], capsys: pytest.CaptureFixture[str]
) -> None:
    hour = timedelta(hours=1)
    now = datetime.now(UTC)
    journal(
        sessions,
        # Hourly OSV runs must not hide the last daily EPSS run.
        *(
            SyncRunRecord(source="osv-ubuntu", mode="incremental", status="succeeded", started_at=now - n * hour,
                          finished_at=now - n * hour + timedelta(seconds=42), records_written=n)
            for n in range(1, 30)
        ),
        SyncRunRecord(source="epss", mode="full", status="failed", started_at=now - 20 * hour,
                      finished_at=now - 20 * hour + timedelta(minutes=2, seconds=5),
                      error="FeedHttpError: https://epss.test/x.csv.gz: HTTP 503"),
        SyncRunRecord(source="kev", status="running", started_at=now - timedelta(minutes=3)),
    )

    assert main(["status"], sessions=sessions) == 0
    rows = [line.split() for line in status_lines(capsys)[2:]]

    assert [row[0] for row in rows] == ["osv-ubuntu", "epss", "kev"]
    osv, epss, kev = rows
    assert osv[4:9] == ["incremental", "succeeded", "42s", "1", "0"]
    assert epss[4:9] == ["full", "failed", "2m05s", "0", "0"] and "HTTP 503" in " ".join(epss)
    # A run in progress has no mode yet and counts its duration up to now.
    assert kev[4:6] == ["-", "running"] and kev[6].startswith("3m")


def test_status_can_show_recent_runs(sessions: sessionmaker[Session], capsys: pytest.CaptureFixture[str]) -> None:
    now = datetime.now(UTC)
    journal(
        sessions,
        *(
            SyncRunRecord(source="kev", mode="full", status="not_modified", started_at=now - timedelta(hours=n),
                          finished_at=now - timedelta(hours=n))
            for n in range(1, 6)
        ),
    )

    assert main(["status", "--runs", "3"], sessions=sessions) == 0
    rows = status_lines(capsys)[2:]

    assert len(rows) == 3 and all("not_modified" in row for row in rows)

    with pytest.raises(SystemExit):
        main(["status", "--runs", "0"], sessions=sessions)


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


def test_health_reports_a_stuck_sync(
    sessions: sessionmaker[Session], environment: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write_heartbeat(str(environment), syncing="osv-debian", since=datetime.now(UTC) - timedelta(hours=3))
    assert main(["health"], sessions=sessions) == 1
    assert "osv-debian" in capsys.readouterr().err


def test_configuration_errors_are_reported(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SLEEP_VULNDB_SOURCES", "nvd")
    assert main(["status"], sessions=sessions) == 2
    assert "nvd" in capsys.readouterr().err
