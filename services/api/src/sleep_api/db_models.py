from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def new_id() -> str:
    return str(uuid4())


def now_utc() -> datetime:
    return datetime.now(UTC)


class OrganizationRecord(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class UserRecord(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("organization_id", "email"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    email: Mapped[str] = mapped_column(String(320))
    display_name: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class DeviceRecord(Base):
    __tablename__ = "devices"
    __table_args__ = (
        UniqueConstraint("organization_id", "external_id"),
        UniqueConstraint("organization_id", "id"),
        CheckConstraint("status IN ('online', 'degraded', 'offline')", name="ck_devices_status"),
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="ck_devices_risk_score"),
        CheckConstraint("cve_count >= 0", name="ck_devices_cve_count"),
        CheckConstraint("critical_cve_count >= 0", name="ck_devices_critical_cve_count"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    external_id: Mapped[str] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(255))
    platform: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(255))
    address: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32))
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    cve_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_cve_count: Mapped[int] = mapped_column(Integer, default=0)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)


class InventorySnapshotRecord(Base):
    __tablename__ = "inventory_snapshots"
    __table_args__ = (
        UniqueConstraint("device_id", "content_hash"),
        ForeignKeyConstraint(
            ["organization_id", "device_id"],
            ["devices.organization_id", "devices.id"],
            ondelete="CASCADE",
        ),
        CheckConstraint("schema_version >= 1", name="ck_inventory_snapshots_schema_version"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(String(64), index=True)
    device_id: Mapped[str] = mapped_column(String(36), index=True)
    content_hash: Mapped[str] = mapped_column(String(64))
    schema_version: Mapped[int] = mapped_column(Integer, default=1)
    inventory: Mapped[dict[str, object]] = mapped_column(JSON)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class CveFindingRecord(Base):
    __tablename__ = "cve_findings"
    __table_args__ = (
        UniqueConstraint("device_id", "cve_id"),
        UniqueConstraint("organization_id", "id"),
        UniqueConstraint("organization_id", "device_id", "id"),
        ForeignKeyConstraint(
            ["organization_id", "device_id"],
            ["devices.organization_id", "devices.id"],
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name="ck_cve_findings_severity",
        ),
        CheckConstraint("cvss_score BETWEEN 0 AND 10", name="ck_cve_findings_cvss_score"),
        CheckConstraint("epss_probability BETWEEN 0 AND 1", name="ck_cve_findings_epss_probability"),
        CheckConstraint("confidence BETWEEN 0 AND 1", name="ck_cve_findings_confidence"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(String(64), index=True)
    device_id: Mapped[str] = mapped_column(String(36), index=True)
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(500))
    component: Mapped[str] = mapped_column(String(255))
    installed_version: Mapped[str] = mapped_column(String(255))
    fixed_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    cvss_score: Mapped[float] = mapped_column(Float)
    epss_probability: Mapped[float] = mapped_column(Float)
    exposure: Mapped[str] = mapped_column(String(500))
    confidence: Mapped[float] = mapped_column(Float)
    evidence: Mapped[list[dict[str, str]]] = mapped_column(JSON, default=list)
    recommended_action: Mapped[str] = mapped_column(String(1000))
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)


class SecurityEventRecord(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        UniqueConstraint("organization_id", "external_id"),
        ForeignKeyConstraint(
            ["organization_id", "device_id"],
            ["devices.organization_id", "devices.id"],
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "event_type IN ('auth', 'process', 'network', 'package', 'service')",
            name="ck_security_events_event_type",
        ),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name="ck_security_events_severity",
        ),
        CheckConstraint("record_count >= 1", name="ck_security_events_record_count"),
        CheckConstraint("last_seen_at >= first_seen_at", name="ck_security_events_seen_range"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(String(64), index=True)
    device_id: Mapped[str] = mapped_column(String(36), index=True)
    external_id: Mapped[str] = mapped_column(String(64))
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    title: Mapped[str] = mapped_column(String(500))
    summary: Mapped[str] = mapped_column(String(2000))
    actor: Mapped[str | None] = mapped_column(String(500), nullable=True)
    correlation_key: Mapped[str] = mapped_column(String(1000), index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    record_count: Mapped[int] = mapped_column(Integer, default=1)
    raw_record_refs: Mapped[list[str]] = mapped_column(JSON, default=list)


class ProbeJobRecord(Base):
    __tablename__ = "probe_jobs"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "device_id", "cve_finding_id"],
            ["cve_findings.organization_id", "cve_findings.device_id", "cve_findings.id"],
            ondelete="CASCADE",
        ),
        CheckConstraint("probe = 'safe'", name="ck_probe_jobs_probe"),
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled')",
            name="ck_probe_jobs_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(64), index=True)
    device_id: Mapped[str] = mapped_column(String(36), index=True)
    cve_finding_id: Mapped[str] = mapped_column(String(36), index=True)
    probe: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
