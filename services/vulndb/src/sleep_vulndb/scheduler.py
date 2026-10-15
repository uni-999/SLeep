"""Long-running updater: polls each enabled source on its own interval.

The loop itself writes the heartbeat file that ``sleep-vulndb health`` checks:
"idle" between runs and "syncing <source> since <time>" during a run. A loop
that stopped or hangs therefore makes the container unhealthy, while a long but
healthy full download does not, as long as it fits into the sync time limit.
"""

import json
import logging
import os
import threading
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session, sessionmaker

from .config import Settings
from .db_models import FeedStateRecord
from .http import FeedHttp
from .sync import mark_interrupted_runs, run_source
from .timeutil import as_utc, parse_optional_timestamp


logger = logging.getLogger(__name__)

# An idle loop rewrites the heartbeat every tick; allow for one missed tick.
HEARTBEAT_IDLE_GRACE_SECONDS = 60


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
    write_heartbeat(settings.heartbeat_path)
    interrupted = mark_interrupted_runs(sessions)
    if interrupted:
        logger.warning("Marked %d interrupted sync runs as failed", interrupted)
    if not settings.sources:
        logger.warning("No sources enabled (SLEEP_VULNDB_SOURCES=none); idling")
    logger.info("Updater started for sources: %s", ", ".join(settings.sources) or "none")

    while not stop.is_set():
        write_heartbeat(settings.heartbeat_path)
        for name in settings.sources:
            if stop.is_set():
                break
            with sessions() as session:
                state = session.get(FeedStateRecord, name)
                last_attempt = state.last_attempt_at if state else None
                failures = state.consecutive_failures if state else 0
            now = datetime.now(UTC)
            if is_due(last_attempt, failures, settings.interval_minutes[name], settings.retry_minutes, now):
                write_heartbeat(settings.heartbeat_path, syncing=name, since=now)
                run_source(name, sessions=sessions, http=http, settings=settings)
                write_heartbeat(settings.heartbeat_path)
        stop.wait(settings.tick_seconds)
    logger.info("Updater stopped")


def write_heartbeat(path: str, *, syncing: str | None = None, since: datetime | None = None) -> None:
    """Atomically record what the loop is doing; the health check reads it."""
    payload = {
        "written_at": datetime.now(UTC).isoformat(),
        "syncing": syncing,
        "since": (since or datetime.now(UTC)).isoformat() if syncing else None,
    }
    temporary = f"{path}.tmp"
    try:
        with open(temporary, "w", encoding="utf-8") as stream:
            json.dump(payload, stream)
        os.replace(temporary, path)
    except OSError:
        logger.exception("Cannot write heartbeat file %s", path)


def heartbeat_problem(
    path: str,
    *,
    tick_seconds: int,
    max_sync_minutes: int,
    now: datetime | None = None,
) -> str | None:
    """Return why the updater loop looks dead or stuck, or None when it is healthy."""
    now = now or datetime.now(UTC)
    try:
        with open(path, encoding="utf-8") as stream:
            payload = json.load(stream)
        written_at = parse_optional_timestamp(payload.get("written_at"))
        syncing = payload.get("syncing")
        since = parse_optional_timestamp(payload.get("since"))
    except FileNotFoundError:
        return "the updater loop has not written a heartbeat yet"
    except (OSError, ValueError, AttributeError) as error:
        return f"the heartbeat file is unreadable: {error}"
    if written_at is None:
        return "the heartbeat file has no timestamp"

    if syncing:
        started = since or written_at
        if now - started > timedelta(minutes=max_sync_minutes):
            minutes = int((now - started).total_seconds() // 60)
            return f"the sync of {syncing} has been running for {minutes} min (limit {max_sync_minutes} min)"
        return None

    idle_limit = timedelta(seconds=tick_seconds + HEARTBEAT_IDLE_GRACE_SECONDS)
    if now - written_at > idle_limit:
        return f"the updater loop heartbeat is stale (last written {written_at.isoformat()})"
    return None
