"""Run one feed source and journal the attempt.

The data changes, the source state (cursor, HTTP validators) and the journal
entry are committed in a single transaction, so a failed or interrupted run
never leaves a half-applied feed: readers keep seeing the previous version.

That transaction starts only after the feed is downloaded: sources fetch first
and write afterwards, and the per-source lock lives on its own connection
outside any transaction. A slow feed therefore never keeps a transaction open.
"""

import logging
import zlib
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

from sqlalchemy import CursorResult, Engine, delete, select, text, update
from sqlalchemy.orm import Session, sessionmaker

from .config import Settings
from .db_models import FeedStateRecord, SyncRunRecord
from .http import FeedHttp
from .sources import SOURCES, SyncContext, SyncMode, SyncStatus


logger = logging.getLogger(__name__)

MAX_ERROR_LENGTH = 4000


class SourceBusyError(RuntimeError):
    pass


@dataclass(frozen=True)
class RunResult:
    source: str
    status: SyncStatus
    mode: SyncMode | None
    written: int = 0
    deleted: int = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status != SyncStatus.FAILED


def run_source(
    name: str,
    *,
    sessions: sessionmaker[Session],
    http: FeedHttp,
    settings: Settings,
    force_full: bool = False,
    now: datetime | None = None,
) -> RunResult:
    source = SOURCES[name]
    started_at = now or datetime.now(UTC)

    with sessions() as session, ExitStack() as held:
        # Take the source lock before journaling the run: a "running" entry then
        # always belongs to the process that holds the lock, which is how
        # mark_interrupted_runs tells a live run from one left by a dead process.
        # The lock is released after the final commit, so a second run cannot
        # start before this run's data is visible.
        busy: SourceBusyError | None = None
        try:
            held.enter_context(_source_lock(cast(Engine, session.get_bind()), name))
        except SourceBusyError as error:
            busy = error

        state = session.get(FeedStateRecord, name)
        if state is None:
            state = FeedStateRecord(source=name, consecutive_failures=0)
            session.add(state)
        state.last_attempt_at = started_at
        _prune_journal(session, name, before=started_at - timedelta(days=settings.run_retention_days))
        run = SyncRunRecord(source=name, status=SyncStatus.RUNNING, started_at=started_at)
        session.add(run)

        if busy is not None:
            # Journaled, but not counted as a failure of the source.
            message = _error_message(busy)
            logger.warning("%s: %s", name, busy)
            run.status = SyncStatus.FAILED
            run.error = message
            run.finished_at = datetime.now(UTC)
            session.commit()
            return RunResult(source=name, status=SyncStatus.FAILED, mode=None, error=message)

        session.commit()
        run_id = run.id
        logger.info("%s: sync started%s", name, " (forced full)" if force_full else "")
        try:
            outcome = source.sync(
                SyncContext(
                    session=session,
                    http=http,
                    settings=settings,
                    state=state,
                    now=started_at,
                    force_full=force_full,
                )
            )
            finished_at = datetime.now(UTC)
            state.last_success_at = finished_at
            state.consecutive_failures = 0
            state.last_error = None
            run.mode = outcome.mode
            run.status = outcome.status
            run.records_written = outcome.written
            run.records_deleted = outcome.deleted
            run.finished_at = finished_at
            session.commit()
        except Exception as error:
            session.rollback()
            message = _error_message(error)
            logger.exception("%s: sync failed", name)
            state = session.get(FeedStateRecord, name)
            run = session.get(SyncRunRecord, run_id)
            assert state is not None and run is not None
            state.consecutive_failures = (state.consecutive_failures or 0) + 1
            state.last_error = message
            run.status = SyncStatus.FAILED
            run.error = message
            run.finished_at = datetime.now(UTC)
            session.commit()
            return RunResult(source=name, status=SyncStatus.FAILED, mode=None, error=message)

    logger.info(
        "%s: %s %s, %d written, %d deleted",
        name, outcome.mode, outcome.status, outcome.written, outcome.deleted,
    )
    return RunResult(
        source=name,
        status=outcome.status,
        mode=outcome.mode,
        written=outcome.written,
        deleted=outcome.deleted,
    )


@contextmanager
def _source_lock(engine: Engine, name: str) -> Iterator[None]:
    """Allow one sync per source at a time (scheduler and a manual `sync`).

    A transaction-level lock would need a transaction open for the whole run,
    downloads included. Instead a session-level advisory lock is held on a
    separate autocommit connection: it lasts as long as the run, keeps no
    transaction open, and PostgreSQL drops it if the process dies.
    """
    if engine.dialect.name != "postgresql":
        yield
        return
    key = zlib.crc32(f"sleep-vulndb:{name}".encode())
    with engine.connect() as connection:
        connection.execution_options(isolation_level="AUTOCOMMIT")
        if not connection.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": key}):
            raise SourceBusyError(f"another sync of {name} is already running")
        try:
            yield
        finally:
            try:
                connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": key})
            except Exception:
                # The connection is gone, and the lock went with it.
                logger.warning("%s: could not release the sync lock explicitly", name, exc_info=True)


def _prune_journal(session: Session, name: str, *, before: datetime) -> None:
    """Delete this source's finished journal entries started before ``before``."""
    session.execute(
        delete(SyncRunRecord).where(
            SyncRunRecord.source == name,
            SyncRunRecord.status != SyncStatus.RUNNING,
            SyncRunRecord.started_at < before,
        )
    )


def mark_interrupted_runs(sessions: sessionmaker[Session]) -> int:
    """Close journal entries left "running" by a process that died mid-run.

    run_source journals a run only while it holds the source lock, so a
    "running" entry is stale exactly when the lock of its source is free. A
    source that is being synced right now, for example by a manual `sync`
    while the service restarts, keeps its entry; any stale entry of that
    source is closed on a later start.
    """
    closed = 0
    with sessions() as session:
        engine = cast(Engine, session.get_bind())
        running = select(SyncRunRecord.source).where(SyncRunRecord.status == SyncStatus.RUNNING).distinct()
        names = sorted(session.scalars(running))
        session.commit()
        for name in names:
            try:
                with _source_lock(engine, name):
                    statement = (
                        update(SyncRunRecord)
                        .where(SyncRunRecord.source == name, SyncRunRecord.status == SyncStatus.RUNNING)
                        .values(
                            status=SyncStatus.FAILED,
                            error="interrupted: the process stopped during the run",
                            finished_at=datetime.now(UTC),
                        )
                    )
                    closed += cast(CursorResult, session.execute(statement)).rowcount or 0
                    session.commit()
            except SourceBusyError:
                logger.info("%s: a sync is running right now; its journal entry stays open", name)
    return closed


def _error_message(error: Exception) -> str:
    return f"{type(error).__name__}: {error}"[:MAX_ERROR_LENGTH]
