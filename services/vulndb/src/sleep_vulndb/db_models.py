from datetime import UTC, date, datetime
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from .database import SCHEMA, Base


SEVERITIES = ("critical", "high", "medium", "low", "info")
ADVISORY_SOURCES = ("osv-debian", "osv-ubuntu")
FEED_SOURCES = ("osv-debian", "osv-ubuntu", "epss", "kev")


def new_id() -> str:
    return str(uuid4())


def now_utc() -> datetime:
    return datetime.now(UTC)


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(value) for value in values)})"


class AdvisoryRecord(Base):
    """One distribution advisory for one CVE (an OSV record such as UBUNTU-CVE-2024-6387)."""

    __tablename__ = "advisories"
    __table_args__ = (
        CheckConstraint(_in("source", ADVISORY_SOURCES), name="ck_advisories_source"),
        CheckConstraint(f"severity IS NULL OR {_in('severity', SEVERITIES)}", name="ck_advisories_severity"),
        CheckConstraint("cvss_score IS NULL OR cvss_score BETWEEN 0 AND 10", name="ck_advisories_cvss_score"),
        Index("ix_advisories_source", "source"),
        Index("ix_advisories_cve_id", "cve_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source: Mapped[str] = mapped_column(String(32))
    cve_id: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(500))
    details: Mapped[str] = mapped_column(Text)
    severity: Mapped[str | None] = mapped_column(String(16))
    cvss_vector: Mapped[str | None] = mapped_column(String(255))
    cvss_score: Mapped[float | None] = mapped_column(Float)
    vendor_severity: Mapped[str | None] = mapped_column(String(32))
    reference_urls: Mapped[list[str]] = mapped_column(JSON, default=list)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class AffectedPackageRecord(Base):
    """A vulnerable version interval of one source package in one release."""

    __tablename__ = "affected_packages"
    __table_args__ = (
        CheckConstraint("fixed IS NULL OR last_affected IS NULL", name="ck_affected_packages_single_upper_bound"),
        Index("ix_affected_packages_lookup", "ecosystem", "package"),
        Index("ix_affected_packages_advisory_id", "advisory_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    advisory_id: Mapped[str] = mapped_column(ForeignKey(f"{SCHEMA}.advisories.id", ondelete="CASCADE"))
    ecosystem: Mapped[str] = mapped_column(String(64))
    distro: Mapped[str] = mapped_column(String(16))
    release: Mapped[str] = mapped_column(String(32))
    package: Mapped[str] = mapped_column(String(255))
    # NULL introduced means "every version before the upper bound".
    introduced: Mapped[str | None] = mapped_column(String(255))
    # Exactly one of fixed / last_affected, or neither when no fix exists yet.
    fixed: Mapped[str | None] = mapped_column(String(255))
    last_affected: Mapped[str | None] = mapped_column(String(255))
    binaries: Mapped[list[str]] = mapped_column(JSON, default=list)


class EpssScoreRecord(Base):
    __tablename__ = "epss_scores"
    __table_args__ = (
        CheckConstraint("probability BETWEEN 0 AND 1", name="ck_epss_scores_probability"),
        CheckConstraint("percentile BETWEEN 0 AND 1", name="ck_epss_scores_percentile"),
    )

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    probability: Mapped[float] = mapped_column(Float)
    percentile: Mapped[float] = mapped_column(Float)
    score_date: Mapped[date | None] = mapped_column(Date)
    model_version: Mapped[str | None] = mapped_column(String(64))


class KevEntryRecord(Base):
    """CISA Known Exploited Vulnerabilities catalog entry."""

    __tablename__ = "kev_entries"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    vendor_project: Mapped[str] = mapped_column(String(255))
    product: Mapped[str] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(500))
    short_description: Mapped[str] = mapped_column(Text)
    required_action: Mapped[str] = mapped_column(Text)
    date_added: Mapped[date] = mapped_column(Date)
    due_date: Mapped[date | None] = mapped_column(Date)
    known_ransomware_use: Mapped[bool] = mapped_column(Boolean, default=False)


class FeedStateRecord(Base):
    """Per-source synchronization state: HTTP validators, cursor, last outcome."""

    __tablename__ = "feed_state"
    __table_args__ = (
        CheckConstraint(_in("source", FEED_SOURCES), name="ck_feed_state_source"),
        CheckConstraint("consecutive_failures >= 0", name="ck_feed_state_consecutive_failures"),
    )

    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    etag: Mapped[str | None] = mapped_column(String(255))
    last_modified: Mapped[str | None] = mapped_column(String(64))
    cursor: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_full_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)


class SyncRunRecord(Base):
    """Journal of synchronization runs, one row per attempt."""

    __tablename__ = "sync_runs"
    __table_args__ = (
        CheckConstraint(_in("source", FEED_SOURCES), name="ck_sync_runs_source"),
        CheckConstraint(f"mode IS NULL OR {_in('mode', ('full', 'incremental'))}", name="ck_sync_runs_mode"),
        CheckConstraint(
            _in("status", ("running", "succeeded", "not_modified", "failed")), name="ck_sync_runs_status"
        ),
        CheckConstraint("records_written >= 0 AND records_deleted >= 0", name="ck_sync_runs_counters"),
        Index("ix_sync_runs_source_started_at", "source", "started_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source: Mapped[str] = mapped_column(String(32))
    # Known only after the source decided between a full and an incremental sync.
    mode: Mapped[str | None] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    records_written: Mapped[int] = mapped_column(Integer, default=0)
    records_deleted: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
