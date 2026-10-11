import os
import threading
import time
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from sleep_vulndb.config import Settings
from sleep_vulndb.database import Base, make_engine
from sleep_vulndb.db_models import KevEntryRecord, SyncRunRecord
from sleep_vulndb.http import FeedHttp
from sleep_vulndb.scheduler import heartbeat_is_fresh, is_due, run_forever, write_heartbeat

from conftest import KEV_URL, FakeFeeds, kev_entry, make_kev


NOW = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("last_attempt", "failures", "expected"),
    [
        (None, 0, True),
        (NOW - timedelta(minutes=59), 0, False),
        (NOW - timedelta(minutes=60), 0, True),
        # After a failure the source is retried sooner than its interval.
        (NOW - timedelta(minutes=14), 1, False),
        (NOW - timedelta(minutes=15), 3, True),
    ],
)
def test_is_due(last_attempt: datetime | None, failures: int, expected: bool) -> None:
    assert is_due(last_attempt, failures, interval_minutes=60, retry_minutes=15, now=NOW) is expected


def test_retry_never_waits_longer_than_the_interval() -> None:
    assert is_due(NOW - timedelta(minutes=5), 2, interval_minutes=5, retry_minutes=15, now=NOW)


def test_naive_timestamps_from_sqlite_are_treated_as_utc() -> None:
    assert not is_due(datetime(2026, 10, 11, 11, 30), 0, interval_minutes=60, retry_minutes=15, now=NOW)


def test_heartbeat(tmp_path: Path) -> None:
    path = str(tmp_path / "heartbeat")
    assert not heartbeat_is_fresh(path)
    write_heartbeat(path)
    assert heartbeat_is_fresh(path)
    old = time.time() - 600
    os.utime(path, (old, old))
    assert not heartbeat_is_fresh(path)


@pytest.fixture
def threaded_sessions(tmp_path: Path) -> Iterator[sessionmaker[Session]]:
    """The updater runs in another thread, so each thread needs its own SQLite
    connection; the shared in-memory connection of `sessions` is not thread-safe."""
    engine = make_engine(f"sqlite+pysqlite:///{tmp_path / 'scheduler.db'}", poolclass=NullPool)
    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine, expire_on_commit=False)
    engine.dispose()


def test_run_forever_syncs_due_sources_and_stops(
    threaded_sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    sessions = threaded_sessions
    feeds.serve(KEV_URL, make_kev([kev_entry("CVE-2021-44228")]))
    stop = threading.Event()
    worker = threading.Thread(
        target=run_forever,
        args=(replace(settings, sources=("kev",), tick_seconds=1), sessions, http, stop),
    )
    worker.start()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with sessions() as session:
            if session.scalar(select(KevEntryRecord.cve_id)):
                break
        time.sleep(0.05)
    stop.set()
    worker.join(timeout=10)

    assert not worker.is_alive()
    assert heartbeat_is_fresh(settings.heartbeat_path)
    with sessions() as session:
        statuses = list(session.scalars(select(SyncRunRecord.status)))
    assert statuses == ["succeeded"], "a source is not synced again before its interval"
