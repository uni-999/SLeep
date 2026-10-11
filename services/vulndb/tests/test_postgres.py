"""End-to-end checks on a real PostgreSQL: schema, JSON columns, timestamps, locks."""

import os
import zlib
from collections.abc import Iterator

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from sleep_vulndb.config import Settings
from sleep_vulndb.database import make_engine
from sleep_vulndb.db_models import AffectedPackageRecord, FeedStateRecord
from sleep_vulndb.http import FeedHttp
from sleep_vulndb.lookup import find_affecting
from sleep_vulndb.sync import run_source

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
