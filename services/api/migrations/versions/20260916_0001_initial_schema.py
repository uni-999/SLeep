"""Create the initial multi-tenant product schema.

Revision ID: 20260916_0001
Revises:
Create Date: 2026-09-16
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260916_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("organization_id", "email"),
    )
    op.create_index("ix_users_organization_id", "users", ["organization_id"])

    op.create_table(
        "devices",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("platform", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=255), nullable=False),
        sa.Column("address", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("cve_count", sa.Integer(), nullable=False),
        sa.Column("critical_cve_count", sa.Integer(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("organization_id", "external_id"),
    )
    op.create_index("ix_devices_organization_id", "devices", ["organization_id"])

    op.create_table(
        "inventory_snapshots",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("inventory", sa.JSON(), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="inventory_snapshots_organization_id_fkey",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
            name="inventory_snapshots_device_id_fkey",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("device_id", "content_hash"),
    )
    op.create_index("ix_inventory_snapshots_organization_id", "inventory_snapshots", ["organization_id"])
    op.create_index("ix_inventory_snapshots_device_id", "inventory_snapshots", ["device_id"])

    op.create_table(
        "cve_findings",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("component", sa.String(length=255), nullable=False),
        sa.Column("installed_version", sa.String(length=255), nullable=False),
        sa.Column("fixed_version", sa.String(length=255), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=False),
        sa.Column("epss_probability", sa.Float(), nullable=False),
        sa.Column("exposure", sa.String(length=500), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("recommended_action", sa.String(length=1000), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="cve_findings_organization_id_fkey",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
            name="cve_findings_device_id_fkey",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("device_id", "cve_id"),
    )
    op.create_index("ix_cve_findings_organization_id", "cve_findings", ["organization_id"])
    op.create_index("ix_cve_findings_device_id", "cve_findings", ["device_id"])
    op.create_index("ix_cve_findings_cve_id", "cve_findings", ["cve_id"])
    op.create_index("ix_cve_findings_severity", "cve_findings", ["severity"])

    op.create_table(
        "security_events",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("external_id", sa.String(length=64), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("summary", sa.String(length=2000), nullable=False),
        sa.Column("actor", sa.String(length=500), nullable=True),
        sa.Column("correlation_key", sa.String(length=1000), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_count", sa.Integer(), nullable=False),
        sa.Column("raw_record_refs", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="security_events_organization_id_fkey",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
            name="security_events_device_id_fkey",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("organization_id", "external_id"),
    )
    op.create_index("ix_security_events_organization_id", "security_events", ["organization_id"])
    op.create_index("ix_security_events_device_id", "security_events", ["device_id"])
    op.create_index("ix_security_events_event_type", "security_events", ["event_type"])
    op.create_index("ix_security_events_severity", "security_events", ["severity"])
    op.create_index("ix_security_events_correlation_key", "security_events", ["correlation_key"])

    op.create_table(
        "probe_jobs",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("cve_finding_id", sa.String(length=36), nullable=False),
        sa.Column("probe", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="probe_jobs_organization_id_fkey",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
            name="probe_jobs_device_id_fkey",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["cve_finding_id"],
            ["cve_findings.id"],
            name="probe_jobs_cve_finding_id_fkey",
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_probe_jobs_organization_id", "probe_jobs", ["organization_id"])
    op.create_index("ix_probe_jobs_device_id", "probe_jobs", ["device_id"])
    op.create_index("ix_probe_jobs_cve_finding_id", "probe_jobs", ["cve_finding_id"])
    op.create_index("ix_probe_jobs_status", "probe_jobs", ["status"])


def downgrade() -> None:
    op.drop_table("probe_jobs")
    op.drop_table("security_events")
    op.drop_table("cve_findings")
    op.drop_table("inventory_snapshots")
    op.drop_table("devices")
    op.drop_table("users")
    op.drop_table("organizations")
