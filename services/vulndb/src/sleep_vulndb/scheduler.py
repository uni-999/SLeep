"""Long-running updater: polls each enabled source on its own interval."""

import logging
import os
import threading
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session, sessionmaker

from .config import Settings
from .db_models import FeedStateRecord
from .http import FeedHttp
from .sync import mark_interrupted_runs, run_source
from .timeutil import as_utc


logger = logging.getLogger(__name__)

HEARTBEAT_SECONDS = 30
HEARTBEAT_MAX_AGE_SECONDS = 120


def is_due(
    last_attempt_at: datetime | None,
    consecutive_failures: int,
    interval_minutes: int,
    retry_minutes: int,
    now: datetime,
) -> bool:
    """A source is due after its interval, or sooner after a failure."""
    last_attempt = as_utc(last_attempt_at)
    if last_attempt is None:
        return True
    wait = interval_minutes
    if consecutive_failures > 0:
        wait = min(interval_minutes, retry_minutes)
    return now >= last_attempt + timedelta(minutes=wait)


def run_forever(
    settings: Settings,
    sessions: sessionmaker[Session],
    http: FeedHttp,
    stop: threading.Event,
) -> None:
    interrupted = mark_interrupted_runs(sessions)
    if interrupted:
        logger.warning("Marked %d interrupted sync runs as failed", interrupted)
    if not settings.sources:
        logger.warning("No sources enabled (SLEEP_VULNDB_SOURCES=none); idling")
    logger.info("Updater started for sources: %s", ", ".join(settings.sources) or "none")

    heartbeat = threading.Thread(
        target=_heartbeat_loop, args=(settings.heartbeat_path, stop), name="heartbeat", daemon=True
    )
    heartbeat.start()

    while not stop.is_set():
        for name in settings.sources:
            if stop.is_set():
                break
            with sessions() as session:
                state = session.get(FeedStateRecord, name)
                last_attempt = state.last_attempt_at if state else None
                failures = state.consecutive_failures if state else 0
            if is_due(last_attempt, failures, settings.interval_minutes[name], settings.retry_minutes,
                      datetime.now(UTC)):
                run_source(name, sessions=sessions, http=http, settings=settings)
        stop.wait(settings.tick_seconds)
    logger.info("Updater stopped")


def _heartbeat_loop(path: str, stop: threading.Event) -> None:
    while not stop.is_set():
        write_heartbeat(path)
        stop.wait(HEARTBEAT_SECONDS)


def write_heartbeat(path: str) -> None:
    try:
        with open(path, "w", encoding="utf-8") as stream:
            stream.write(datetime.now(UTC).isoformat())
    except OSError:
        logger.exception("Cannot write heartbeat file %s", path)


def heartbeat_is_fresh(path: str, max_age_seconds: int = HEARTBEAT_MAX_AGE_SECONDS) -> bool:
    try:
        return time.time() - os.path.getmtime(path) <= max_age_seconds
    except OSError:
        return False
