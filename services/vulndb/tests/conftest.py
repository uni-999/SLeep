import copy
import gzip
import io
import json
import zipfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from sleep_vulndb import db_models  # noqa: F401
from sleep_vulndb.config import Settings
from sleep_vulndb.database import Base, make_engine
from sleep_vulndb.http import FeedHttp


FIXTURES = Path(__file__).parent / "fixtures"
OSV = "https://osv.test"
EPSS_URL = "https://epss.test/epss_scores-current.csv.gz"
KEV_URL = "https://kev.test/known_exploited_vulnerabilities.json"


def load_record(record_id: str) -> dict[str, Any]:
    return json.loads((FIXTURES / f"{record_id}.json").read_text(encoding="utf-8"))


def osv_record(
    record_id: str,
    *,
    package: str = "sudo",
    ecosystem: str = "Ubuntu:22.04:LTS",
    events: list[dict[str, str]] | None = None,
    modified: str = "2026-01-01T00:00:00Z",
    cvss: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": record_id,
        "details": f"Synthetic test record {record_id}.",
        "modified": modified,
        "affected": [
            {
                "package": {"ecosystem": ecosystem, "name": package},
                "ranges": [{"type": "ECOSYSTEM", "events": events or [{"introduced": "0"}]}],
            }
        ],
        **extra,
    }
    if cvss:
        record["severity"] = [{"type": "CVSS_V3", "score": cvss}]
    return record


def with_changes(record: dict[str, Any], **changes: Any) -> dict[str, Any]:
    updated = copy.deepcopy(record)
    updated.update(changes)
    return updated


def make_zip(records: list[dict[str, Any]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for record in records:
            archive.writestr(f"{record['id']}.json", json.dumps(record))
    return buffer.getvalue()


def make_epss(rows: list[tuple[str, float, float]], *, comment: bool = True) -> bytes:
    lines = []
    if comment:
        lines.append("#model_version:v2025.03.14,score_date:2026-10-11T00:00:00+0000")
    lines.append("cve,epss,percentile")
    lines.extend(f"{cve},{probability},{percentile}" for cve, probability, percentile in rows)
    return gzip.compress(("\n".join(lines) + "\n").encode())


def make_kev(entries: list[dict[str, Any]]) -> bytes:
    return json.dumps(
        {"title": "CISA Catalog of Known Exploited Vulnerabilities", "count": len(entries),
         "vulnerabilities": entries}
    ).encode()


def kev_entry(cve_id: str, **changes: Any) -> dict[str, Any]:
    entry = {
        "cveID": cve_id,
        "vendorProject": "Example",
        "product": "Example Server",
        "vulnerabilityName": f"Example vulnerability {cve_id}",
        "dateAdded": "2026-03-02",
        "shortDescription": "Synthetic test entry.",
        "requiredAction": "Apply mitigations per vendor instructions.",
        "dueDate": "2026-03-23",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "",
        "cwes": ["CWE-364"],
    }
    entry.update(changes)
    return entry


@dataclass
class FakeFeeds:
    """In-memory HTTP server for feed URLs; records every request."""

    routes: dict[str, Callable[[httpx.Request], httpx.Response]] = field(default_factory=dict)
    requests: list[httpx.Request] = field(default_factory=list)
    # Called on every request, before it is answered.
    observers: list[Callable[[httpx.Request], None]] = field(default_factory=list)

    def serve(self, url: str, body: bytes | str, *, etag: str | None = None, status: int = 200) -> None:
        content = body.encode() if isinstance(body, str) else body

        def handler(request: httpx.Request) -> httpx.Response:
            if etag is not None and request.headers.get("If-None-Match") == etag:
                return httpx.Response(304)
            headers = {"ETag": etag} if etag else {}
            return httpx.Response(status, content=content, headers=headers)

        self.routes[url] = handler

    def serve_json(self, url: str, document: Any) -> None:
        self.serve(url, json.dumps(document))

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        for observer in self.observers:
            observer(request)
        handler = self.routes.get(str(request.url))
        return handler(request) if handler else httpx.Response(404)

    def urls(self) -> list[str]:
        return [str(request.url) for request in self.requests]


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        osv_base_url=OSV,
        epss_url=EPSS_URL,
        kev_url=KEV_URL,
        http_retries=2,
        http_backoff_seconds=0,
        heartbeat_path=str(tmp_path / "heartbeat"),
    )


@pytest.fixture
def feeds() -> FakeFeeds:
    return FakeFeeds()


@pytest.fixture
def http(settings: Settings, feeds: FakeFeeds) -> Iterator[FeedHttp]:
    client = FeedHttp(settings, transport=httpx.MockTransport(feeds.handle), sleep=lambda _seconds: None)
    yield client
    client.close()


@pytest.fixture
def sessions() -> Iterator[sessionmaker[Session]]:
    engine = make_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine, expire_on_commit=False)
    engine.dispose()
