"""CISA Known Exploited Vulnerabilities (KEV) catalog.

A CVE in KEV has confirmed exploitation in the wild, which is the strongest
single signal for prioritizing a fix. The catalog is one JSON document and
replaces the whole table on every change.
"""

import json
from typing import Any

from sqlalchemy import delete, insert, select

from ..db_models import KevEntryRecord
from ..timeutil import parse_date
from .base import FeedDataError, SyncContext, SyncMode, SyncOutcome, SyncStatus, ensure_plausible_size
from .osv import CVE_ID


class KevSource:
    name = "kev"

    def sync(self, context: SyncContext) -> SyncOutcome:
        state = context.state
        validators = {} if context.force_full else {"etag": state.etag, "last_modified": state.last_modified}
        with context.http.download(context.settings.kev_url, **validators) as download:
            if download is None:
                return SyncOutcome(mode=SyncMode.FULL, status=SyncStatus.NOT_MODIFIED)
            try:
                with open(download.path, encoding="utf-8") as stream:
                    document = json.load(stream)
            except (ValueError, UnicodeDecodeError) as error:
                raise FeedDataError(f"kev: invalid JSON: {error}") from error

        rows = parse_catalog(document)
        session = context.session
        previous_ids = set(session.scalars(select(KevEntryRecord.cve_id)))
        ensure_plausible_size(context, self.name, len(previous_ids), len(rows))
        session.execute(delete(KevEntryRecord))
        session.execute(insert(KevEntryRecord), rows)

        state.etag = download.etag
        state.last_modified = download.last_modified
        written_ids = {row["cve_id"] for row in rows}
        return SyncOutcome(
            mode=SyncMode.FULL,
            status=SyncStatus.SUCCEEDED,
            written=len(written_ids),
            deleted=len(previous_ids - written_ids),
        )


def parse_catalog(document: Any) -> list[dict[str, Any]]:
    if not isinstance(document, dict) or not isinstance(document.get("vulnerabilities"), list):
        raise FeedDataError("kev: the document has no 'vulnerabilities' list")

    rows: dict[str, dict[str, Any]] = {}
    for item in document["vulnerabilities"]:
        cve_id = item.get("cveID") if isinstance(item, dict) else None
        if not isinstance(cve_id, str) or not CVE_ID.match(cve_id):
            raise FeedDataError(f"kev: entry without a valid cveID: {item!r}")
        date_added = parse_date(item.get("dateAdded"))
        if date_added is None:
            raise FeedDataError(f"kev: {cve_id} has no dateAdded")
        rows[cve_id] = {
            "cve_id": cve_id,
            "vendor_project": str(item.get("vendorProject") or "")[:255],
            "product": str(item.get("product") or "")[:255],
            "name": str(item.get("vulnerabilityName") or "")[:500],
            "short_description": str(item.get("shortDescription") or ""),
            "required_action": str(item.get("requiredAction") or ""),
            "date_added": date_added,
            "due_date": parse_date(item.get("dueDate")),
            "known_ransomware_use": str(item.get("knownRansomwareCampaignUse") or "").lower() == "known",
        }
    if not rows:
        raise FeedDataError("kev: the catalog is empty; keeping existing data")
    return list(rows.values())
