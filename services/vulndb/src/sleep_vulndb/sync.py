"""Run one feed source and journal the attempt.

The data changes, the source state (cursor, HTTP validators) and the journal
entry are committed in a single transaction, so a failed or interrupted run
never leaves a half-applied feed: readers keep seeing the previous version.
"""

import logging
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from sqlalchemy import CursorResult, text, update
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

    with sessions() as session:
        state = session.get(FeedStateRecord, name)
        if state is None:
            state = FeedStateRecord(source=name, consecutive_failures=0)
            session.add(state)
        state.last_attempt_at = started_at
        run = SyncRunRecord(source=name, status=SyncStatus.RUNNING, started_at=started_at)
        session.add(run)
        session.commit()
        run_id = run.id

        logger.info("%s: sync started%s", name, " (forced full)" if force_full else "")
        try:
            _lock_source(session, name)
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
            message = f"{type(error).__name__}: {error}"[:MAX_ERROR_LENGTH]
            busy = isinstance(error, SourceBusyError)
            if busy:
                logger.warning("%s: %s", name, error)
            else:
                logger.exception("%s: sync failed", name)
            state = session.get(FeedStateRecord, name)
            run = session.get(SyncRunRecord, run_id)
            assert state is not None and run is not None
            if not busy:
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


def _lock_source(session: Session, name: str) -> None:
    """Allow one sync per source at a time (scheduler and a manual `sync`)."""
    if session.get_bind().dialect.name != "postgresql":
        return
    key = zlib.crc32(f"sleep-vulndb:{name}".encode())
    acquired = session.scalar(text("SELECT pg_try_advisory_xact_lock(:key)"), {"key": key})
    if not acquired:
        raise SourceBusyError(f"another sync of {name} is already running")


def mark_interrupted_runs(sessions: sessionmaker[Session]) -> int:
    """Close journal entries left 'running' by a process that was killed."""
    with sessions() as session:
        statement = (
            update(SyncRunRecord)
            .where(SyncRunRecord.status == SyncStatus.RUNNING)
            .values(
                status=SyncStatus.FAILED,
                error="interrupted: the process stopped during the run",
                finished_at=datetime.now(UTC),
            )
        )
        result = cast(CursorResult, session.execute(statement))
        session.commit()
        return result.rowcount or 0
