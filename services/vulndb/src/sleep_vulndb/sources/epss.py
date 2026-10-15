"""EPSS: the probability that a CVE is exploited in the next 30 days (FIRST.org).

The feed is one gzip CSV per day that covers every published CVE::

    #model_version:v2025.03.14,score_date:2025-03-16T00:00:00+0000
    cve,epss,percentile
    CVE-1999-0001,0.01141,0.77913

Each new file replaces the whole table in one transaction.
"""

import csv
import gzip
import zlib

from sqlalchemy import delete, insert, select
from sqlalchemy.orm import Session

from ..db_models import EpssScoreRecord
from ..timeutil import parse_date
from .base import FeedDataError, SyncContext, SyncMode, SyncOutcome, SyncStatus, ensure_plausible_size
from .osv import CVE_ID


BATCH_SIZE = 10_000


class EpssSource:
    name = "epss"

    def sync(self, context: SyncContext) -> SyncOutcome:
        state = context.state
        validators = {} if context.force_full else {"etag": state.etag, "last_modified": state.last_modified}
        with context.http.download(context.settings.epss_url, **validators) as download:
            if download is None:
                return SyncOutcome(mode=SyncMode.FULL, status=SyncStatus.NOT_MODIFIED)
            previous_ids = set(context.session.scalars(select(EpssScoreRecord.cve_id)))
            context.session.execute(delete(EpssScoreRecord))
            try:
                written_ids = _load(context.session, download.path)
            except (OSError, EOFError, zlib.error, UnicodeDecodeError) as error:
                raise FeedDataError(f"epss: cannot read the gzip CSV: {error}") from error
            ensure_plausible_size(context, self.name, len(previous_ids), len(written_ids))

        state.etag = download.etag
        state.last_modified = download.last_modified
        return SyncOutcome(
            mode=SyncMode.FULL,
            status=SyncStatus.SUCCEEDED,
            written=len(written_ids),
            deleted=len(previous_ids - written_ids),
        )


def _load(session: Session, path: str) -> set[str]:
    with gzip.open(path, "rt", encoding="utf-8", newline="") as stream:
        first = stream.readline()
        model_version = score_date = None
        if first.startswith("#"):
            metadata = dict(part.split(":", 1) for part in first[1:].strip().split(",") if ":" in part)
            model_version = metadata.get("model_version")
            score_date = parse_date(metadata.get("score_date"))
            header_line = stream.readline()
        else:
            header_line = first
        header = [column.strip() for column in header_line.split(",")]
        if header[:3] != ["cve", "epss", "percentile"]:
            raise FeedDataError(f"epss: unexpected header {header_line.strip()!r}")

        written: set[str] = set()
        batch: list[dict[str, object]] = []
        for row in csv.reader(stream):
            if not row:
                continue
            if len(row) < 3 or not CVE_ID.match(row[0]):
                raise FeedDataError(f"epss: malformed row {row!r}")
            try:
                probability, percentile = float(row[1]), float(row[2])
            except ValueError as error:
                raise FeedDataError(f"epss: malformed row {row!r}") from error
            if not (0 <= probability <= 1 and 0 <= percentile <= 1):
                raise FeedDataError(f"epss: value out of range in {row!r}")
            if row[0] in written:
                continue
            written.add(row[0])
            batch.append(
                {
                    "cve_id": row[0],
                    "probability": probability,
                    "percentile": percentile,
                    "score_date": score_date,
                    "model_version": model_version,
                }
            )
            if len(batch) >= BATCH_SIZE:
                session.execute(insert(EpssScoreRecord), batch)
                batch.clear()
        if batch:
            session.execute(insert(EpssScoreRecord), batch)

    if not written:
        raise FeedDataError("epss: the file has no scores; keeping existing data")
    return written
