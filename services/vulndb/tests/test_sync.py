from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import Engine, event, func, select
from sqlalchemy.orm import Session, sessionmaker

from sleep_vulndb.config import Settings
from sleep_vulndb.db_models import (
    AdvisoryRecord,
    AffectedPackageRecord,
    EpssScoreRecord,
    FeedStateRecord,
    KevEntryRecord,
    SyncRunRecord,
)
from sleep_vulndb.http import FeedHttp
from sleep_vulndb.sync import RunResult, mark_interrupted_runs, run_source
from sleep_vulndb.timeutil import as_utc

from conftest import (
    EPSS_URL,
    KEV_URL,
    OSV,
    FakeFeeds,
    kev_entry,
    load_record,
    make_epss,
    make_kev,
    make_zip,
    osv_record,
    with_changes,
)


UBUNTU_ZIP = f"{OSV}/Ubuntu/all.zip"
UBUNTU_CHANGES = f"{OSV}/Ubuntu/modified_id.csv"
NOW = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)

SUDO = osv_record(
    "UBUNTU-CVE-2026-1000",
    package="sudo",
    events=[{"introduced": "0"}],
    modified="2026-03-01T00:00:00Z",
    cvss="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
)
NOTICE = osv_record("USN-6859-1", package="openssh", modified="2026-09-30T00:00:00Z")
OLD_RELEASE = osv_record("UBUNTU-CVE-2026-1001", ecosystem="Ubuntu:16.04:LTS", modified="2026-09-01T00:00:00Z")


def sync(
    name: str,
    sessions: sessionmaker[Session],
    http: FeedHttp,
    settings: Settings,
    *,
    now: datetime = NOW,
    force_full: bool = False,
) -> RunResult:
    return run_source(name, sessions=sessions, http=http, settings=settings, now=now, force_full=force_full)


def count(sessions: sessionmaker[Session], model: type, *where: Any) -> int:
    with sessions() as session:
        return session.scalar(select(func.count()).select_from(model).where(*where)) or 0


def state_of(sessions: sessionmaker[Session], name: str) -> FeedStateRecord:
    with sessions() as session:
        state = session.get(FeedStateRecord, name)
        assert state is not None
        return state


def runs(sessions: sessionmaker[Session]) -> list[SyncRunRecord]:
    with sessions() as session:
        return list(session.scalars(select(SyncRunRecord).order_by(SyncRunRecord.started_at)))


def serve_ubuntu_zip(feeds: FakeFeeds, records: list[dict[str, Any]], etag: str = '"zip-1"') -> None:
    feeds.serve(UBUNTU_ZIP, make_zip(records), etag=etag)


def initial_ubuntu_sync(sessions: sessionmaker[Session], http: FeedHttp, settings: Settings,
                        feeds: FakeFeeds) -> None:
    serve_ubuntu_zip(feeds, [load_record("UBUNTU-CVE-2024-6387"), SUDO, NOTICE, OLD_RELEASE])
    assert sync("osv-ubuntu", sessions, http, settings).status == "succeeded"


# OSV: full synchronization ---------------------------------------------------


def test_full_sync_loads_relevant_records(
    sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    serve_ubuntu_zip(feeds, [load_record("UBUNTU-CVE-2024-6387"), SUDO, NOTICE, OLD_RELEASE])

    result = sync("osv-ubuntu", sessions, http, settings)

    assert (result.status, result.mode, result.written, result.deleted) == ("succeeded", "full", 2, 0)
    with sessions() as session:
        ids = set(session.scalars(select(AdvisoryRecord.id)))
        assert ids == {"UBUNTU-CVE-2024-6387", "UBUNTU-CVE-2026-1000"}
        sudo = session.get(AdvisoryRecord, "UBUNTU-CVE-2026-1000")
        assert sudo is not None and (sudo.cvss_score, sudo.severity) == (7.8, "high")
    assert count(sessions, AffectedPackageRecord) == 3

    state = state_of(sessions, "osv-ubuntu")
    assert state.etag == '"zip-1"'
    # The cursor is the newest record in the archive, including skipped ones.
    assert as_utc(state.cursor) == datetime(2026, 9, 30, tzinfo=UTC)
    assert as_utc(state.last_full_sync_at) == NOW
    assert state.consecutive_failures == 0

    [run] = runs(sessions)
    assert (run.source, run.mode, run.status, run.records_written) == ("osv-ubuntu", "full", "succeeded", 2)
    assert run.finished_at is not None


def test_full_sync_replaces_previous_records(
    sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    initial_ubuntu_sync(sessions, http, settings, feeds)
    serve_ubuntu_zip(feeds, [load_record("UBUNTU-CVE-2024-6387")], etag='"zip-2"')

    result = sync("osv-ubuntu", sessions, http, settings, force_full=True)

    assert (result.mode, result.written, result.deleted) == ("full", 1, 1)
    assert count(sessions, AdvisoryRecord) == 1
    assert count(sessions, AffectedPackageRecord) == 2


def test_full_sync_keeps_data_when_archive_is_unchanged(
    sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    initial_ubuntu_sync(sessions, http, settings, feeds)
    later = NOW + timedelta(days=8)  # weekly full resync is due

    result = sync("osv-ubuntu", sessions, http, settings, now=later)

    assert (result.mode, result.status) == ("full", "not_modified")
    assert feeds.requests[-1].headers["If-None-Match"] == '"zip-1"'
    assert count(sessions, AdvisoryRecord) == 2
    assert as_utc(state_of(sessions, "osv-ubuntu").last_full_sync_at) == later


def test_forced_full_sync_ignores_validators(
    sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    initial_ubuntu_sync(sessions, http, settings, feeds)

    result = sync("osv-ubuntu", sessions, http, settings, force_full=True)

    assert (result.mode, result.status) == ("full", "succeeded")
    assert "If-None-Match" not in feeds.requests[-1].headers


def test_broken_archive_keeps_existing_data(
    sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    initial_ubuntu_sync(sessions, http, settings, feeds)
    feeds.serve(UBUNTU_ZIP, b"this is not a zip archive", etag='"zip-broken"')

    result = sync("osv-ubuntu", sessions, http, settings, force_full=True)

    assert result.status == "failed"
    assert "not a valid ZIP" in (result.error or "")
    assert count(sessions, AdvisoryRecord) == 2, "the failed run must not delete anything"
    state = state_of(sessions, "osv-ubuntu")
    assert (state.consecutive_failures, state.etag) == (1, '"zip-1"')
    assert "not a valid ZIP" in (state.last_error or "")
    assert [run.status for run in runs(sessions)] == ["succeeded", "failed"]


def test_archive_without_usable_records_is_rejected(
    sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    initial_ubuntu_sync(sessions, http, settings, feeds)
    serve_ubuntu_zip(feeds, [NOTICE, OLD_RELEASE], etag='"zip-empty"')

    result = sync("osv-ubuntu", sessions, http, settings, force_full=True)

    assert result.status == "failed"
    assert count(sessions, AdvisoryRecord) == 2


def test_success_after_failure_resets_the_failure_counter(
    sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    feeds.serve(UBUNTU_ZIP, b"broken")
    assert sync("osv-ubuntu", sessions, http, settings).status == "failed"
    serve_ubuntu_zip(feeds, [SUDO])

    assert sync("osv-ubuntu", sessions, http, settings).status == "succeeded"
    state = state_of(sessions, "osv-ubuntu")
    assert (state.consecutive_failures, state.last_error) == (0, None)


def test_sources_do_not_touch_each_other(
    sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    initial_ubuntu_sync(sessions, http, settings, feeds)
    feeds.serve(f"{OSV}/Debian/all.zip", make_zip([load_record("DEBIAN-CVE-2024-6387")]))

    assert sync("osv-debian", sessions, http, settings).written == 1
    assert count(sessions, AdvisoryRecord, AdvisoryRecord.source == "osv-ubuntu") == 2
    assert count(sessions, AdvisoryRecord, AdvisoryRecord.cve_id == "CVE-2024-6387") == 2


# OSV: incremental synchronization -------------------------------------------


def test_incremental_sync_applies_only_changed_records(
    sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    initial_ubuntu_sync(sessions, http, settings, feeds)
    updated_sudo = with_changes(SUDO, modified="2026-10-10T08:00:00.123456789Z")
    updated_sudo["affected"][0]["ranges"][0]["events"] = [{"introduced": "0"}, {"fixed": "1.9.9-1ubuntu2.5"}]
    new_record = osv_record("UBUNTU-CVE-2026-2000", package="curl", modified="2026-10-10T07:00:00Z")
    feeds.serve(
        UBUNTU_CHANGES,
        "\n".join(
            [
                "2026-10-10T09:00:00Z,UBUNTU-CVE-2024-6387",
                "2026-10-10T08:30:00Z,USN-9999-1",
                "2026-10-10T08:00:00.123456789Z,UBUNTU-CVE-2026-1000",
                "2026-10-10T07:00:00Z,UBUNTU-CVE-2026-2000",
                "2026-09-30T00:00:00Z,USN-6859-1",
                "2026-01-01T00:00:00Z,UBUNTU-CVE-2000-0001",
            ]
        ),
    )
    feeds.serve_json(f"{OSV}/Ubuntu/UBUNTU-CVE-2026-1000.json", updated_sudo)
    feeds.serve_json(f"{OSV}/Ubuntu/UBUNTU-CVE-2026-2000.json", new_record)
    # UBUNTU-CVE-2024-6387.json is not served: the record was removed upstream (404).

    result = sync("osv-ubuntu", sessions, http, settings, now=NOW + timedelta(hours=1))

    assert (result.mode, result.status, result.written, result.deleted) == ("incremental", "succeeded", 2, 1)
    assert f"{OSV}/Ubuntu/USN-9999-1.json" not in feeds.urls()
    assert f"{OSV}/Ubuntu/UBUNTU-CVE-2000-0001.json" not in feeds.urls(), "reading stops at the cursor"
    with sessions() as session:
        assert set(session.scalars(select(AdvisoryRecord.id))) == {"UBUNTU-CVE-2026-1000", "UBUNTU-CVE-2026-2000"}
        fixed = session.scalar(
            select(AffectedPackageRecord.fixed).where(AffectedPackageRecord.advisory_id == "UBUNTU-CVE-2026-1000")
        )
        assert fixed == "1.9.9-1ubuntu2.5"
    assert as_utc(state_of(sessions, "osv-ubuntu").cursor) == datetime(2026, 10, 10, 9, 0, tzinfo=UTC)


def test_incremental_sync_without_changes(
    sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    initial_ubuntu_sync(sessions, http, settings, feeds)
    feeds.serve(UBUNTU_CHANGES, "2026-09-30T00:00:00Z,USN-6859-1\n2026-03-01T00:00:00Z,UBUNTU-CVE-2026-1000\n")

    result = sync("osv-ubuntu", sessions, http, settings, now=NOW + timedelta(hours=1))

    assert (result.mode, result.status) == ("incremental", "not_modified")
    assert count(sessions, AdvisoryRecord) == 2


def test_record_that_leaves_supported_releases_is_deleted(
    sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    initial_ubuntu_sync(sessions, http, settings, feeds)
    moved = with_changes(SUDO, modified="2026-10-10T00:00:00Z")
    moved["affected"][0]["package"]["ecosystem"] = "Ubuntu:14.04:LTS"
    feeds.serve(UBUNTU_CHANGES, "2026-10-10T00:00:00Z,UBUNTU-CVE-2026-1000\n")
    feeds.serve_json(f"{OSV}/Ubuntu/UBUNTU-CVE-2026-1000.json", moved)

    result = sync("osv-ubuntu", sessions, http, settings, now=NOW + timedelta(hours=1))

    assert (result.written, result.deleted) == (0, 1)
    assert count(sessions, AdvisoryRecord) == 1


def test_too_many_changes_fall_back_to_a_full_download(
    sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    initial_ubuntu_sync(sessions, http, settings, feeds)
    feeds.serve(
        UBUNTU_CHANGES,
        "\n".join(f"2026-10-10T00:00:{second:02d}Z,UBUNTU-CVE-2026-{3000 + second}" for second in range(5)),
    )
    serve_ubuntu_zip(feeds, [SUDO], etag='"zip-2"')

    limited = replace(settings, osv_incremental_limit=3)
    result = sync("osv-ubuntu", sessions, http, limited, now=NOW + timedelta(hours=1))

    assert (result.mode, result.written, result.deleted) == ("full", 1, 1)
    assert not any(url.endswith(".json") for url in feeds.urls())


def test_malformed_change_list_fails_the_run(
    sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    initial_ubuntu_sync(sessions, http, settings, feeds)
    feeds.serve(UBUNTU_CHANGES, "yesterday,UBUNTU-CVE-2026-1000\n")

    result = sync("osv-ubuntu", sessions, http, settings, now=NOW + timedelta(hours=1))

    assert result.status == "failed"
    assert count(sessions, AdvisoryRecord) == 2


# EPSS ------------------------------------------------------------------------


def test_epss_scores_are_loaded(
    sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    feeds.serve(EPSS_URL, make_epss([("CVE-2024-6387", 0.39108, 0.97268), ("CVE-2021-44228", 0.94358, 0.99965)]),
                etag='"epss-1"')

    result = sync("epss", sessions, http, settings)

    assert (result.status, result.written) == ("succeeded", 2)
    with sessions() as session:
        score = session.get(EpssScoreRecord, "CVE-2024-6387")
        assert score is not None
        assert (score.probability, score.percentile, score.model_version) == (0.39108, 0.97268, "v2025.03.14")
        assert score.score_date is not None and score.score_date.isoformat() == "2026-10-11"


def test_epss_file_replaces_previous_scores(
    sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    feeds.serve(EPSS_URL, make_epss([("CVE-2024-6387", 0.3, 0.9), ("CVE-2021-44228", 0.9, 0.99)]))
    sync("epss", sessions, http, settings)
    feeds.serve(EPSS_URL, make_epss([("CVE-2024-6387", 0.4, 0.95)], comment=False))

    result = sync("epss", sessions, http, settings)

    assert (result.written, result.deleted) == (1, 1)
    with sessions() as session:
        score = session.get(EpssScoreRecord, "CVE-2024-6387")
        assert score is not None and score.probability == 0.4 and score.model_version is None


def test_unchanged_epss_file_is_not_downloaded_again(
    sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    feeds.serve(EPSS_URL, make_epss([("CVE-2024-6387", 0.3, 0.9)]), etag='"epss-1"')
    sync("epss", sessions, http, settings)

    result = sync("epss", sessions, http, settings)

    assert result.status == "not_modified"
    assert count(sessions, EpssScoreRecord) == 1


def test_invalid_epss_file_keeps_previous_scores(
    sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    feeds.serve(EPSS_URL, make_epss([("CVE-2024-6387", 0.3, 0.9)]))
    sync("epss", sessions, http, settings)

    for broken in (b"not gzip", make_epss([("CVE-2024-6387", 1.7, 0.9)]), make_epss([])):
        feeds.serve(EPSS_URL, broken)
        assert sync("epss", sessions, http, settings).status == "failed"
        assert count(sessions, EpssScoreRecord) == 1


# KEV -------------------------------------------------------------------------


def test_kev_catalog_is_loaded(
    sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    feeds.serve(KEV_URL, make_kev([kev_entry("CVE-2021-44228", knownRansomwareCampaignUse="Known"),
                                   kev_entry("CVE-2024-6387", dueDate="")]))

    result = sync("kev", sessions, http, settings)

    assert (result.status, result.written) == ("succeeded", 2)
    with sessions() as session:
        log4shell = session.get(KevEntryRecord, "CVE-2021-44228")
        assert log4shell is not None and log4shell.known_ransomware_use is True
        regresshion = session.get(KevEntryRecord, "CVE-2024-6387")
        assert regresshion is not None and regresshion.due_date is None


def test_invalid_kev_catalog_is_rejected(
    sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    feeds.serve(KEV_URL, make_kev([kev_entry("CVE-2021-44228")]))
    sync("kev", sessions, http, settings)

    for broken in (b"{", make_kev([]), make_kev([kev_entry("not-a-cve")]), b'{"vulnerabilities": 1}'):
        feeds.serve(KEV_URL, broken)
        assert sync("kev", sessions, http, settings).status == "failed"
    assert count(sessions, KevEntryRecord) == 1


# Journal ---------------------------------------------------------------------


def test_network_failure_is_journaled(
    sessions: sessionmaker[Session], http: FeedHttp, settings: Settings
) -> None:
    result = sync("kev", sessions, http, settings)

    assert result.status == "failed"
    assert "HTTP 404" in (result.error or "")
    [run] = runs(sessions)
    assert (run.status, run.mode) == ("failed", None)
    assert as_utc(state_of(sessions, "kev").last_attempt_at) == NOW


def test_old_journal_entries_are_deleted(
    sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    retention = timedelta(days=settings.run_retention_days)
    with sessions() as session:
        session.add_all(
            [
                SyncRunRecord(id="kev-expired", source="kev", status="succeeded", started_at=NOW - retention - timedelta(hours=1)),
                SyncRunRecord(id="kev-recent", source="kev", status="failed", started_at=NOW - retention + timedelta(hours=1)),
                # Never touched: another source keeps its own history, and a
                # "running" entry is left to mark_interrupted_runs.
                SyncRunRecord(id="epss-expired", source="epss", status="succeeded", started_at=NOW - 2 * retention),
                SyncRunRecord(id="kev-stuck", source="kev", status="running", started_at=NOW - 2 * retention),
            ]
        )
        session.commit()
    feeds.serve(KEV_URL, make_kev([kev_entry("CVE-2021-44228")]))

    assert sync("kev", sessions, http, settings).status == "succeeded"

    with sessions() as session:
        remaining = set(session.scalars(select(SyncRunRecord.id).where(SyncRunRecord.started_at < NOW)))
    assert remaining == {"kev-recent", "epss-expired", "kev-stuck"}


def test_interrupted_runs_are_closed(sessions: sessionmaker[Session]) -> None:
    with sessions() as session:
        session.add(SyncRunRecord(source="kev", status="running", started_at=NOW))
        session.commit()

    assert mark_interrupted_runs(sessions) == 1
    [run] = runs(sessions)
    assert run.status == "failed"
    assert run.error is not None and run.error.startswith("interrupted")


# Transactions ----------------------------------------------------------------


class TransactionWatch:
    """Tracks open database transactions and the feed requests made inside one."""

    def __init__(self, engine: Engine) -> None:
        self.depth = 0
        self.requests = 0
        self.inside: list[str] = []
        event.listen(engine, "begin", self._begin)
        event.listen(engine, "commit", self._end)
        event.listen(engine, "rollback", self._end)

    def _begin(self, _connection: Any) -> None:
        self.depth += 1

    def _end(self, _connection: Any) -> None:
        self.depth = max(0, self.depth - 1)

    def request(self, request: httpx.Request) -> None:
        self.requests += 1
        if self.depth:
            self.inside.append(str(request.url))


def test_feeds_are_downloaded_outside_the_transaction(
    sessions: sessionmaker[Session], http: FeedHttp, settings: Settings, feeds: FakeFeeds
) -> None:
    watch = TransactionWatch(sessions.kw["bind"])
    feeds.observers.append(watch.request)

    initial_ubuntu_sync(sessions, http, settings, feeds)
    feeds.serve(
        UBUNTU_CHANGES,
        "2026-10-10T09:00:00Z,UBUNTU-CVE-2026-1000\n2026-10-10T08:00:00Z,UBUNTU-CVE-2026-2000\n",
    )
    feeds.serve_json(f"{OSV}/Ubuntu/UBUNTU-CVE-2026-1000.json", with_changes(SUDO, modified="2026-10-10T09:00:00Z"))
    # UBUNTU-CVE-2026-2000 answers 404: the record is deleted, also after the downloads.
    incremental = sync("osv-ubuntu", sessions, http, settings, now=NOW + timedelta(hours=1))
    feeds.serve(EPSS_URL, make_epss([("CVE-2024-6387", 0.39, 0.97)]))
    feeds.serve(KEV_URL, make_kev([kev_entry("CVE-2021-44228")]))
    epss, kev = sync("epss", sessions, http, settings), sync("kev", sessions, http, settings)

    assert (incremental.mode, incremental.status, incremental.written) == ("incremental", "succeeded", 1)
    assert (epss.status, kev.status) == ("succeeded", "succeeded")
    assert watch.requests >= 6
    assert watch.inside == [], "a feed was requested while a database transaction was open"
