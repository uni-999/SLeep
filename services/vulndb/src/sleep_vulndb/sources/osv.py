"""Debian and Ubuntu advisories from the OSV.dev bulk export.

OSV (https://ossf.github.io/osv-schema/) gives both distributions one JSON
format. Only per-CVE records are kept: ``DEBIAN-CVE-*`` and ``UBUNTU-CVE-*``.
They describe every supported release, including vulnerabilities without a
fix yet. Notice-style records (USN-*, DSA-*, DLA-*) repeat the same CVEs and
would create duplicate findings, so they are skipped.

Synchronization:

* full: download ``<Ecosystem>/all.zip`` (conditional request) and replace every
  advisory of the source in one transaction. The cursor becomes the newest
  ``modified`` timestamp found in the archive;
* incremental: read ``<Ecosystem>/modified_id.csv`` (newest first) down to the
  cursor and re-fetch only the changed records. A record that no longer exists
  (404) or no longer affects a configured release is deleted.

A full download runs on the first sync, when too many records changed since
the cursor, and at least every ``osv_full_sync_days`` days to repair drift.
"""

import json
import logging
import re
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, insert, select
from sqlalchemy.orm import Session

from ..cvss import VENDOR_SEVERITY, InvalidVector, base_score, severity_from_score
from ..db_models import AdvisoryRecord, AffectedPackageRecord
from ..timeutil import as_utc, parse_optional_timestamp, parse_timestamp
from .base import FeedDataError, SyncContext, SyncMode, SyncOutcome, SyncStatus, ensure_plausible_size


logger = logging.getLogger(__name__)

CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
RELEASE = re.compile(r"^\d+(\.\d+)?$")
BATCH_SIZE = 500
MAX_REFERENCES = 20
MAX_TITLE = 200


@dataclass(frozen=True)
class ParsedAffected:
    ecosystem: str
    distro: str
    release: str
    package: str
    introduced: str | None
    fixed: str | None
    last_affected: str | None
    binaries: tuple[str, ...]


@dataclass(frozen=True)
class ParsedAdvisory:
    id: str
    source: str
    cve_id: str
    title: str
    details: str
    severity: str | None
    cvss_vector: str | None
    cvss_score: float | None
    vendor_severity: str | None
    reference_urls: tuple[str, ...]
    published_at: datetime | None
    modified_at: datetime
    withdrawn_at: datetime | None
    affected: tuple[ParsedAffected, ...]


class OsvSource:
    def __init__(self, name: str, directory: str, id_prefix: str, distro: str) -> None:
        self.name = name
        self.directory = directory
        self.id_prefix = id_prefix
        self.distro = distro

    # Parsing ------------------------------------------------------------

    def parse(self, record: dict[str, Any], ecosystems: frozenset[str] | None) -> ParsedAdvisory | None:
        """Convert one OSV record. Returns None when it is irrelevant for SLeep."""
        record_id = record.get("id")
        if not isinstance(record_id, str) or not record_id.startswith(self.id_prefix):
            return None
        cve_id = _cve_id(record, record_id, self.id_prefix)
        if cve_id is None:
            return None
        modified_at = parse_optional_timestamp(record.get("modified"))
        if modified_at is None:
            raise FeedDataError(f"{record_id}: missing 'modified'")

        affected = tuple(
            item for entry in record.get("affected") or [] for item in self._parse_affected(entry, ecosystems)
        )
        if not affected:
            return None

        cvss_vector, cvss_score, vendor_severity = _severity_fields(record)
        severity = severity_from_score(cvss_score) if cvss_score is not None else None
        if severity is None and vendor_severity is not None:
            severity = VENDOR_SEVERITY.get(vendor_severity)

        details = str(record.get("details") or "").strip()
        title = str(record.get("summary") or "").strip() or _first_sentence(details) or cve_id

        return ParsedAdvisory(
            id=record_id,
            source=self.name,
            cve_id=cve_id,
            title=title,
            details=details,
            severity=severity,
            cvss_vector=cvss_vector,
            cvss_score=cvss_score,
            vendor_severity=vendor_severity,
            reference_urls=_references(record),
            published_at=parse_optional_timestamp(record.get("published")),
            modified_at=modified_at,
            withdrawn_at=parse_optional_timestamp(record.get("withdrawn")),
            affected=affected,
        )

    def _parse_affected(self, entry: dict[str, Any], ecosystems: frozenset[str] | None) -> list[ParsedAffected]:
        package = entry.get("package") or {}
        ecosystem = package.get("ecosystem")
        name = package.get("name")
        if not isinstance(ecosystem, str) or not isinstance(name, str):
            return []
        if not ecosystem.startswith(f"{self.directory}:"):
            return []
        if ecosystems is not None and ecosystem not in ecosystems:
            return []

        binaries = _binaries(entry)
        release = next((part for part in ecosystem.split(":")[1:] if RELEASE.match(part)), "")
        result = []
        for version_range in entry.get("ranges") or []:
            if version_range.get("type") != "ECOSYSTEM":
                continue
            for introduced, fixed, last_affected in _intervals(version_range.get("events") or []):
                result.append(
                    ParsedAffected(
                        ecosystem=ecosystem,
                        distro=self.distro,
                        release=release,
                        package=name,
                        introduced=introduced,
                        fixed=fixed,
                        last_affected=last_affected,
                        binaries=binaries,
                    )
                )
        return result

    # Synchronization ----------------------------------------------------

    def sync(self, context: SyncContext) -> SyncOutcome:
        if not self._needs_full_sync(context):
            changed = self._changed_since_cursor(context)
            if changed is not None:
                return self._apply_changes(context, changed)
            logger.info("%s: more than %d changed records, switching to a full download",
                        self.name, context.settings.osv_incremental_limit)
        return self._full_sync(context)

    def _needs_full_sync(self, context: SyncContext) -> bool:
        state = context.state
        last_full = as_utc(state.last_full_sync_at)
        if context.force_full or state.cursor is None or last_full is None:
            return True
        return context.now - last_full >= timedelta(days=context.settings.osv_full_sync_days)

    def _url(self, context: SyncContext, name: str) -> str:
        return f"{context.settings.osv_base_url}/{self.directory}/{name}"

    def _full_sync(self, context: SyncContext) -> SyncOutcome:
        state, session = context.state, context.session
        validators = {} if context.force_full else {"etag": state.etag, "last_modified": state.last_modified}
        with context.http.download(self._url(context, "all.zip"), **validators) as download:
            if download is None:
                state.last_full_sync_at = context.now
                return SyncOutcome(mode=SyncMode.FULL, status=SyncStatus.NOT_MODIFIED)

            previous_ids = set(session.scalars(select(AdvisoryRecord.id).where(AdvisoryRecord.source == self.name)))
            previous_relevant = self._count_relevant(session, context.settings.osv_ecosystems)
            self._delete_all(session)

            written_ids: set[str] = set()
            newest: datetime | None = None
            skipped_invalid = 0
            batch: list[ParsedAdvisory] = []
            try:
                archive = zipfile.ZipFile(download.path)
            except zipfile.BadZipFile as error:
                raise FeedDataError(f"{self.name}: all.zip is not a valid ZIP archive") from error
            with archive:
                for member in archive.infolist():
                    if member.is_dir() or not member.filename.endswith(".json"):
                        continue
                    try:
                        record = json.loads(archive.read(member))
                        modified = parse_optional_timestamp(record.get("modified"))
                        parsed = self.parse(record, context.settings.osv_ecosystems)
                    except (ValueError, TypeError, AttributeError) as error:
                        skipped_invalid += 1
                        logger.warning("%s: skipping %s: %s", self.name, member.filename, error)
                        continue
                    if modified is not None and (newest is None or modified > newest):
                        newest = modified
                    if parsed is None:
                        continue
                    batch.append(parsed)
                    written_ids.add(parsed.id)
                    if len(batch) >= BATCH_SIZE:
                        _insert(session, batch)
                        batch.clear()
            _insert(session, batch)

        if not written_ids:
            raise FeedDataError(
                f"{self.name}: the archive has no records for the configured releases; keeping existing data"
            )
        ensure_plausible_size(context, self.name, previous_relevant, len(written_ids))
        if skipped_invalid:
            logger.warning("%s: skipped %d invalid records", self.name, skipped_invalid)

        state.etag = download.etag
        state.last_modified = download.last_modified
        state.cursor = newest
        state.last_full_sync_at = context.now
        return SyncOutcome(
            mode=SyncMode.FULL,
            status=SyncStatus.SUCCEEDED,
            written=len(written_ids),
            deleted=len(previous_ids - written_ids),
        )

    def _changed_since_cursor(self, context: SyncContext) -> dict[str, datetime] | None:
        """Record ids modified after the cursor, newest timestamp per id.
        Returns None when there are more than the incremental limit."""
        cursor = as_utc(context.state.cursor)
        assert cursor is not None
        changed: dict[str, datetime] = {}
        with context.http.lines(self._url(context, "modified_id.csv")) as lines:
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                timestamp_text, _, record_id = line.partition(",")
                try:
                    timestamp = parse_timestamp(timestamp_text)
                except ValueError as error:
                    raise FeedDataError(f"{self.name}: malformed modified_id.csv line {line!r}") from error
                # The file is sorted newest first, so everything below is already applied.
                if timestamp <= cursor:
                    break
                if not record_id.startswith(self.id_prefix):
                    continue
                changed.setdefault(record_id, timestamp)
                if len(changed) > context.settings.osv_incremental_limit:
                    return None
        return changed

    def _apply_changes(self, context: SyncContext, changed: dict[str, datetime]) -> SyncOutcome:
        if not changed:
            return SyncOutcome(mode=SyncMode.INCREMENTAL, status=SyncStatus.NOT_MODIFIED)

        # Download and parse every changed record before touching the database:
        # up to osv_incremental_limit sequential requests (with retries) must
        # not run inside the transaction. None means "delete": the record is
        # gone (404) or no longer affects a configured release.
        fetched: dict[str, ParsedAdvisory | None] = {}
        skipped_invalid = 0
        for record_id in changed:
            try:
                record = context.http.get_json(self._url(context, f"{record_id}.json"))
                fetched[record_id] = (
                    self.parse(record, context.settings.osv_ecosystems) if record is not None else None
                )
            except (ValueError, TypeError, AttributeError) as error:
                # The same rule as in _full_sync: one broken record must not stop
                # the others, or every retry would fail on it until the next full
                # download. The record is left out of `fetched`, so its previous
                # version, if any, stays. Network failures are not caught here
                # (FeedHttpError is not a ValueError): they fail the run and keep
                # the cursor, so the record is fetched again next time.
                skipped_invalid += 1
                logger.warning("%s: skipping %s: %s", self.name, record_id, error)
        if skipped_invalid:
            logger.warning("%s: skipped %d invalid records", self.name, skipped_invalid)
        advisories = [item for item in fetched.values() if item is not None]

        session = context.session
        ids = list(fetched)
        existing = set(session.scalars(select(AdvisoryRecord.id).where(AdvisoryRecord.id.in_(ids))))
        self._delete_ids(session, ids)
        for start in range(0, len(advisories), BATCH_SIZE):
            _insert(session, advisories[start : start + BATCH_SIZE])

        context.state.cursor = max(changed.values())
        return SyncOutcome(
            mode=SyncMode.INCREMENTAL,
            status=SyncStatus.SUCCEEDED,
            written=len(advisories),
            deleted=len(existing - {item.id for item in advisories}),
        )

    def _count_relevant(self, session: Session, ecosystems: frozenset[str] | None) -> int:
        """Advisories of this source that affect a configured release.

        The size check compares the new archive with these only: after the
        list of releases is narrowed, records of the dropped releases are
        expected to disappear and must not look like a truncated feed.
        """
        query = (
            select(func.count(func.distinct(AffectedPackageRecord.advisory_id)))
            .join(AdvisoryRecord, AdvisoryRecord.id == AffectedPackageRecord.advisory_id)
            .where(AdvisoryRecord.source == self.name)
        )
        if ecosystems is not None:
            query = query.where(AffectedPackageRecord.ecosystem.in_(ecosystems))
        return session.scalar(query) or 0

    def _delete_all(self, session: Session) -> None:
        source_ids = select(AdvisoryRecord.id).where(AdvisoryRecord.source == self.name)
        session.execute(delete(AffectedPackageRecord).where(AffectedPackageRecord.advisory_id.in_(source_ids)))
        session.execute(delete(AdvisoryRecord).where(AdvisoryRecord.source == self.name))

    @staticmethod
    def _delete_ids(session: Session, ids: list[str]) -> None:
        session.execute(delete(AffectedPackageRecord).where(AffectedPackageRecord.advisory_id.in_(ids)))
        session.execute(delete(AdvisoryRecord).where(AdvisoryRecord.id.in_(ids)))
        session.flush()


def _insert(session: Session, advisories: list[ParsedAdvisory]) -> None:
    if not advisories:
        return
    session.execute(
        insert(AdvisoryRecord),
        [
            {
                "id": item.id,
                "source": item.source,
                "cve_id": item.cve_id,
                "title": item.title,
                "details": item.details,
                "severity": item.severity,
                "cvss_vector": item.cvss_vector,
                "cvss_score": item.cvss_score,
                "vendor_severity": item.vendor_severity,
                "reference_urls": list(item.reference_urls),
                "published_at": item.published_at,
                "modified_at": item.modified_at,
                "withdrawn_at": item.withdrawn_at,
            }
            for item in advisories
        ],
    )
    session.execute(
        insert(AffectedPackageRecord),
        [
            {
                "advisory_id": item.id,
                "ecosystem": affected.ecosystem,
                "distro": affected.distro,
                "release": affected.release,
                "package": affected.package,
                "introduced": affected.introduced,
                "fixed": affected.fixed,
                "last_affected": affected.last_affected,
                "binaries": list(affected.binaries),
            }
            for item in advisories
            for affected in item.affected
        ],
    )


def _cve_id(record: dict[str, Any], record_id: str, prefix: str) -> str | None:
    candidates = [*(record.get("upstream") or []), *(record.get("aliases") or [])]
    if prefix.endswith("CVE-"):
        # DEBIAN-CVE-2024-6387 -> CVE-2024-6387, for records without upstream/aliases.
        candidates.append("CVE-" + record_id.removeprefix(prefix))
    return next((item for item in candidates if isinstance(item, str) and CVE_ID.match(item)), None)


def _first_sentence(details: str, limit: int = MAX_TITLE) -> str:
    """Ubuntu and Debian records rarely have a summary; use the first sentence of the details."""
    first_line = details.strip().splitlines()[0] if details.strip() else ""
    sentence = re.split(r"(?<=[.!?])\s", first_line, maxsplit=1)[0]
    return sentence if len(sentence) <= limit else sentence[: limit - 1].rstrip() + "…"


def _intervals(events: list[dict[str, str]]) -> list[tuple[str | None, str | None, str | None]]:
    """Turn OSV range events into (introduced, fixed, last_affected) intervals.
    An introduced version of "0" means "from the very first version" and is stored as None."""
    intervals: list[tuple[str | None, str | None, str | None]] = []
    introduced: str | None = None
    open_interval = False
    for event in events:
        if "introduced" in event:
            if open_interval:
                intervals.append((introduced, None, None))
            value = event["introduced"]
            introduced = None if value in ("0", "") else value
            open_interval = True
        elif "fixed" in event and open_interval:
            intervals.append((introduced, event["fixed"], None))
            open_interval = False
        elif "last_affected" in event and open_interval:
            intervals.append((introduced, None, event["last_affected"]))
            open_interval = False
    if open_interval:
        intervals.append((introduced, None, None))
    return intervals


def _severity_fields(record: dict[str, Any]) -> tuple[str | None, float | None, str | None]:
    vector_v3: str | None = None
    vector_other: str | None = None
    vendor: str | None = None
    for item in record.get("severity") or []:
        kind, score = item.get("type"), item.get("score")
        if not isinstance(score, str):
            continue
        if kind == "CVSS_V3" and vector_v3 is None:
            vector_v3 = score
        elif kind in ("CVSS_V4", "CVSS_V2") and vector_other is None:
            vector_other = score
        elif kind in ("Ubuntu", "Debian") and vendor is None:
            vendor = score.strip().lower()

    if vector_v3 is not None:
        try:
            return vector_v3, base_score(vector_v3), vendor
        except InvalidVector:
            logger.warning("%s: invalid CVSS vector %r", record.get("id"), vector_v3)
    # CVSS v4 scores need the full lookup tables; keep the vector for later.
    return vector_v3 or vector_other, None, vendor


def _references(record: dict[str, Any]) -> tuple[str, ...]:
    urls = [item.get("url") for item in record.get("references") or []]
    return tuple(dict.fromkeys(url for url in urls if isinstance(url, str)))[:MAX_REFERENCES]


def _binaries(entry: dict[str, Any]) -> tuple[str, ...]:
    specific = entry.get("ecosystem_specific") or {}
    names = []
    for item in specific.get("binaries") or []:
        if isinstance(item, dict) and isinstance(item.get("binary_name"), str):
            names.append(item["binary_name"])
        elif isinstance(item, str):
            names.append(item)
    return tuple(sorted(set(names)))


OSV_SOURCES = {
    "osv-debian": OsvSource("osv-debian", "Debian", "DEBIAN-CVE-", "debian"),
    "osv-ubuntu": OsvSource("osv-ubuntu", "Ubuntu", "UBUNTU-CVE-", "ubuntu"),
}
