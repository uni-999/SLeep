"""End-to-end checks on a real PostgreSQL: schema, JSON columns, timestamps, locks."""

import os
import zlib
from collections.abc import Iterator
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from sleep_vulndb.config import Settings
from sleep_vulndb.database import make_engine
from sleep_vulndb.db_models import AffectedPackageRecord, FeedStateRecord, SyncRunRecord
from sleep_vulndb.http import FeedHttp
from sleep_vulndb.lookup import find_affecting
from sleep_vulndb.sync import mark_interrupted_runs, run_source

from conftest import OSV, FakeFeeds, load_record, make_zip
from test_migrations import run_alembic


pytestmark = pytest.mark.postgres


@pytest.fixture
def pg_sessions() -> Iterator[sessionmaker[Session]]:
    database_url = os.getenv("SLEEP_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("SLEEP_TEST_DATABASE_URL is not configured")
    run_alembic(database_url, "upgrade", "head")
    engine = make_engine(database_url)
    try:
        yield sessionmaker(bind=engine, expire_on_commit=False)
    finally:
        engine.dispose()
        run_alembic(database_url, "downgrade", "base")


def test_sync_and_lookup_on_postgres(
    pg_sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    feeds.serve(f"{OSV}/Ubuntu/all.zip", make_zip([load_record("UBUNTU-CVE-2024-6387")]), etag='"zip-1"')

    result = run_source("osv-ubuntu", sessions=pg_sessions, http=http, settings=settings)

    assert (result.status, result.written) == ("succeeded", 1)
    with pg_sessions() as session:
        binaries = session.scalar(
            select(AffectedPackageRecord.binaries).where(AffectedPackageRecord.ecosystem == "Ubuntu:22.04:LTS")
        )
        assert binaries == ["openssh-client", "openssh-server", "openssh-sftp-server"]
        state = session.get(FeedStateRecord, "osv-ubuntu")
        assert state is not None and state.cursor is not None and state.cursor.tzinfo is not None
        found = find_affecting(session, "Ubuntu:22.04:LTS", "openssh", "1:8.9p1-3ubuntu0.6")
        assert [item.cve_id for item in found] == ["CVE-2024-6387"]


def test_parallel_sync_of_the_same_source_is_refused(
    pg_sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    feeds.serve(f"{OSV}/Ubuntu/all.zip", make_zip([load_record("UBUNTU-CVE-2024-6387")]))
    key = zlib.crc32(b"sleep-vulndb:osv-ubuntu")

    with pg_sessions() as holder:
        holder.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})
        result = run_source("osv-ubuntu", sessions=pg_sessions, http=http, settings=settings)
        holder.rollback()

    assert result.status == "failed"
    assert "already running" in (result.error or "")
    with pg_sessions() as session:
        state = session.get(FeedStateRecord, "osv-ubuntu")
        assert state is not None and state.consecutive_failures == 0, "a busy source is not a failure"
        [run] = session.scalars(select(SyncRunRecord))
        assert (run.status, run.finished_at is not None) == ("failed", True), "a refused run is closed at once"
        assert not feeds.requests, "a refused run downloads nothing"


def test_only_runs_of_dead_processes_are_marked_interrupted(pg_sessions: sessionmaker[Session]) -> None:
    started = datetime.now(UTC)
    with pg_sessions() as session:
        session.add_all(
            [
                SyncRunRecord(id="kev-live", source="kev", status="running", started_at=started),
                SyncRunRecord(id="epss-dead", source="epss", status="running", started_at=started),
            ]
        )
        session.commit()

    # Another process is syncing KEV right now: it holds the KEV lock.
    engine = pg_sessions.kw["bind"]
    with engine.connect() as holder:
        holder.execute(text("SELECT pg_advisory_lock(:key)"), {"key": zlib.crc32(b"sleep-vulndb:kev")})
        assert mark_interrupted_runs(pg_sessions) == 1
        holder.execute(text("SELECT pg_advisory_unlock_all()"))
        holder.commit()

    with pg_sessions() as session:
        statuses = dict(session.execute(select(SyncRunRecord.id, SyncRunRecord.status)).tuples().all())
    assert statuses == {"kev-live": "running", "epss-dead": "failed"}


def test_no_transaction_is_open_while_a_feed_downloads(
    pg_sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    engine = pg_sessions.kw["bind"]
    archive = make_zip([load_record("UBUNTU-CVE-2024-6387")])
    seen: list[tuple[str, int]] = []

    def zip_feed(_request: httpx.Request) -> httpx.Response:
        with engine.connect() as probe:
            seen.extend(
                probe.execute(
                    text(
                        "SELECT a.state, (SELECT count(*) FROM pg_locks l"
                        "  WHERE l.pid = a.pid AND l.locktype = 'advisory') "
                        "FROM pg_stat_activity a "
                        "WHERE a.datname = current_database() AND a.pid <> pg_backend_pid() "
                        "AND a.backend_type = 'client backend'"
                    )
                ).tuples()
            )
        return httpx.Response(200, content=archive)

    feeds.routes[f"{OSV}/Ubuntu/all.zip"] = zip_feed

    result = run_source("osv-ubuntu", sessions=pg_sessions, http=http, settings=settings)

    assert result.status == "succeeded"
    # The lock is held for the whole run, by an idle connection, not a transaction.
    assert ("idle", 1) in seen
    assert not [state for state, _locks in seen if state.startswith("idle in transaction")]
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory'")) == 0
