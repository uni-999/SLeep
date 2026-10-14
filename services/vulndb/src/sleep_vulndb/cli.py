"""Command line: ``sleep-vulndb {run,sync,status,lookup,health}``."""

import argparse
import logging
import signal
import sys
import threading
from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import ColumnElement, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from .config import KNOWN_SOURCES, ConfigurationError, Settings
from .database import default_sessions
from .db_models import (
    AdvisoryRecord,
    AffectedPackageRecord,
    EpssScoreRecord,
    FeedStateRecord,
    KevEntryRecord,
    SyncRunRecord,
)
from .debversion import InvalidVersion
from .http import FeedHttp
from .lookup import find_affecting
from .scheduler import heartbeat_problem, run_forever
from .sync import run_source
from .timeutil import as_utc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sleep-vulndb", description="SLeep vulnerability knowledge base updater")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("run", help="keep the knowledge base up to date (service mode)")

    sync = commands.add_parser("sync", help="synchronize sources once and exit")
    sync.add_argument("--source", action="append", choices=KNOWN_SOURCES,
                      help="source to sync (repeatable); default: SLEEP_VULNDB_SOURCES")
    sync.add_argument("--full", action="store_true", help="ignore cursors and HTTP validators, reload everything")

    status = commands.add_parser("status", help="show the state of every source and its recent runs")
    status.add_argument("--runs", type=_positive_int, metavar="N",
                        help="show the N most recent journal entries instead of the last run of each source")

    lookup = commands.add_parser("lookup", help="list vulnerabilities affecting one package version")
    lookup.add_argument("--ecosystem", required=True, help='OSV ecosystem, e.g. "Ubuntu:22.04:LTS" or "Debian:12"')
    lookup.add_argument("--package", required=True, help="Debian source package name, e.g. openssh")
    lookup.add_argument("--version", required=True, help="installed version, e.g. 1:8.9p1-3ubuntu0.6")

    commands.add_parser("health", help="container healthcheck: heartbeat and database")
    return parser


def main(argv: Sequence[str] | None = None, sessions: sessionmaker[Session] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    arguments = build_parser().parse_args(argv)
    try:
        settings = Settings.from_env()
    except ConfigurationError as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        return 2
    sessions = sessions or default_sessions()

    match arguments.command:
        case "run":
            return _run(settings, sessions)
        case "sync":
            return _sync(settings, sessions, arguments.source or list(settings.sources), arguments.full)
        case "status":
            return _status(settings, sessions, arguments.runs)
        case "lookup":
            return _lookup(sessions, arguments.ecosystem, arguments.package, arguments.version)
        case "health":
            return _health(settings, sessions)
    return 2


def _run(settings: Settings, sessions: sessionmaker[Session]) -> int:
    stop = threading.Event()

    def request_stop(signum: int, _frame: object) -> None:
        logging.getLogger(__name__).info("Received signal %d, finishing the current step", signum)
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    with FeedHttp(settings) as http:
        run_forever(settings, sessions, http, stop)
    return 0


def _sync(settings: Settings, sessions: sessionmaker[Session], sources: list[str], full: bool) -> int:
    if not sources:
        print("No sources selected.", file=sys.stderr)
        return 2
    with FeedHttp(settings) as http:
        results = [run_source(name, sessions=sessions, http=http, settings=settings, force_full=full)
                   for name in sources]
    for result in results:
        line = f"{result.source:<11} {result.status:<13} written={result.written} deleted={result.deleted}"
        print(line + (f"  {result.error}" if result.error else ""))
    return 0 if all(result.ok for result in results) else 1


def _status(settings: Settings, sessions: sessionmaker[Session], recent: int | None = None) -> int:
    with sessions() as session:
        states = {state.source: state for state in session.scalars(select(FeedStateRecord))}
        counts = {
            "osv-debian": _count(session, AdvisoryRecord, AdvisoryRecord.source == "osv-debian"),
            "osv-ubuntu": _count(session, AdvisoryRecord, AdvisoryRecord.source == "osv-ubuntu"),
            "epss": _count(session, EpssScoreRecord),
            "kev": _count(session, KevEntryRecord),
        }
        affected = _count(session, AffectedPackageRecord)
        if recent is None:
            last_runs = [
                session.scalars(
                    select(SyncRunRecord).where(SyncRunRecord.source == name)
                    .order_by(SyncRunRecord.started_at.desc()).limit(1)
                ).first()
                for name in KNOWN_SOURCES
            ]
            runs = [run for run in last_runs if run is not None]
        else:
            runs = list(session.scalars(select(SyncRunRecord).order_by(SyncRunRecord.started_at.desc()).limit(recent)))

    print(f"{'source':<11} {'enabled':<8} {'records':>8}  {'last success':<20} {'cursor':<20} failures  last error")
    for name in KNOWN_SOURCES:
        state = states.get(name)
        print(
            f"{name:<11} {'yes' if name in settings.sources else 'no':<8} {counts[name]:>8}  "
            f"{_when(state.last_success_at if state else None):<20} {_when(state.cursor if state else None):<20} "
            f"{state.consecutive_failures if state else 0:>8}  {(state.last_error or '') if state else ''}"
        )
    print(f"\naffected package intervals: {affected}")

    print("\n" + ("last run of each source:" if recent is None else "run journal, newest first:"))
    if not runs:
        print("  none yet")
        return 0
    print(f"{'source':<11} {'started':<20} {'mode':<11} {'status':<13} {'duration':>8} {'written':>8} "
          f"{'deleted':>8}  error")
    now = datetime.now(UTC)
    for run in runs:
        print(
            f"{run.source:<11} {_when(run.started_at):<20} {run.mode or '-':<11} {run.status:<13} "
            f"{_duration(run.started_at, run.finished_at, now):>8} {run.records_written:>8} "
            f"{run.records_deleted:>8}  {_shorten(run.error)}"
        )
    return 0


def _lookup(sessions: sessionmaker[Session], ecosystem: str, package: str, version: str) -> int:
    try:
        with sessions() as session:
            found = find_affecting(session, ecosystem, package, version)
    except InvalidVersion as error:
        print(f"Invalid version: {error}", file=sys.stderr)
        return 2
    if not found:
        print(f"No known vulnerabilities for {package} {version} in {ecosystem}.")
        return 0
    for item in found:
        epss = f"{item.epss_probability:.3f}" if item.epss_probability is not None else "-"
        cvss = f"{item.cvss_score:.1f}" if item.cvss_score is not None else "-"
        kev = "KEV" if item.known_exploited else ""
        print(f"{item.cve_id:<16} {item.severity or '-':<8} cvss={cvss:<4} epss={epss:<6} {kev:<3} "
              f"fixed={item.fixed_version or 'none'}  {item.title}")
        print(f"{'':<16} {item.advisory_id}: {item.reason}")
    return 0


def _health(settings: Settings, sessions: sessionmaker[Session]) -> int:
    problem = heartbeat_problem(
        settings.heartbeat_path,
        tick_seconds=settings.tick_seconds,
        max_sync_minutes=settings.max_sync_minutes,
    )
    if problem:
        print(f"unhealthy: {problem}", file=sys.stderr)
        return 1
    try:
        with sessions() as session:
            session.execute(text("SELECT 1"))
    except Exception as error:
        print(f"unhealthy: database is unreachable: {error}", file=sys.stderr)
        return 1
    print("healthy")
    return 0


def _count(session: Session, model: type, *conditions: ColumnElement[bool]) -> int:
    return session.scalar(select(func.count()).select_from(model).where(*conditions)) or 0


def _duration(started_at: datetime, finished_at: datetime | None, now: datetime) -> str:
    """Run length; a run that is still going counts up to now."""
    started = as_utc(started_at)
    end = as_utc(finished_at) or now
    assert started is not None
    seconds = max(0, int((end - started).total_seconds()))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{seconds % 3600 // 60:02d}m"


def _shorten(text: str | None, limit: int = 100) -> str:
    if not text:
        return ""
    line = " ".join(text.split())
    return line if len(line) <= limit else line[: limit - 1] + "…"


def _positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError(f"must be positive, got {number}")
    return number


def _when(value: datetime | None) -> str:
    moment = as_utc(value)
    return moment.strftime("%Y-%m-%d %H:%M UTC") if moment else "never"
