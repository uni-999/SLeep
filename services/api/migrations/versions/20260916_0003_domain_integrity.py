"""Enforce product-domain integrity constraints.

Revision ID: 20260916_0003
Revises: 20260916_0002
Create Date: 2026-09-16
"""

from collections.abc import Sequence

from alembic import op


revision: str = "20260916_0003"
down_revision: str | None = "20260916_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("devices") as batch:
        batch.create_check_constraint("ck_devices_status", "status IN ('online', 'degraded', 'offline')")
        batch.create_check_constraint("ck_devices_risk_score", "risk_score BETWEEN 0 AND 100")
        batch.create_check_constraint("ck_devices_cve_count", "cve_count >= 0")
        batch.create_check_constraint("ck_devices_critical_cve_count", "critical_cve_count >= 0")

    with op.batch_alter_table("inventory_snapshots") as batch:
        batch.create_check_constraint("ck_inventory_snapshots_schema_version", "schema_version >= 1")

    with op.batch_alter_table("cve_findings") as batch:
        batch.create_unique_constraint(
            "uq_cve_findings_tenant_device_internal",
            ["organization_id", "device_id", "id"],
        )
        batch.create_check_constraint(
            "ck_cve_findings_severity",
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
        )
        batch.create_check_constraint("ck_cve_findings_cvss_score", "cvss_score BETWEEN 0 AND 10")
        batch.create_check_constraint(
            "ck_cve_findings_epss_probability",
            "epss_probability BETWEEN 0 AND 1",
        )
        batch.create_check_constraint("ck_cve_findings_confidence", "confidence BETWEEN 0 AND 1")

    with op.batch_alter_table("security_events") as batch:
        batch.create_check_constraint(
            "ck_security_events_event_type",
            "event_type IN ('auth', 'process', 'network', 'package', 'service')",
        )
        batch.create_check_constraint(
            "ck_security_events_severity",
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
        )
        batch.create_check_constraint("ck_security_events_record_count", "record_count >= 1")
        batch.create_check_constraint("ck_security_events_seen_range", "last_seen_at >= first_seen_at")

    with op.batch_alter_table("probe_jobs") as batch:
        batch.drop_constraint("fk_probe_jobs_tenant_cve", type_="foreignkey")
        batch.drop_constraint("fk_probe_jobs_tenant_device", type_="foreignkey")
        batch.create_foreign_key(
            "fk_probe_jobs_tenant_device_cve",
            "cve_findings",
            ["organization_id", "device_id", "cve_finding_id"],
            ["organization_id", "device_id", "id"],
            ondelete="CASCADE",
        )
        batch.create_check_constraint("ck_probe_jobs_probe", "probe = 'safe'")
        batch.create_check_constraint(
            "ck_probe_jobs_status",
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled')",
        )


def downgrade() -> None:
    with op.batch_alter_table("probe_jobs") as batch:
        batch.drop_constraint("ck_probe_jobs_status", type_="check")
        batch.drop_constraint("ck_probe_jobs_probe", type_="check")
        batch.drop_constraint("fk_probe_jobs_tenant_device_cve", type_="foreignkey")
        batch.create_foreign_key(
            "fk_probe_jobs_tenant_device",
            "devices",
            ["organization_id", "device_id"],
            ["organization_id", "id"],
            ondelete="CASCADE",
        )
        batch.create_foreign_key(
            "fk_probe_jobs_tenant_cve",
            "cve_findings",
            ["organization_id", "cve_finding_id"],
            ["organization_id", "id"],
            ondelete="CASCADE",
        )

    with op.batch_alter_table("security_events") as batch:
        batch.drop_constraint("ck_security_events_seen_range", type_="check")
        batch.drop_constraint("ck_security_events_record_count", type_="check")
        batch.drop_constraint("ck_security_events_severity", type_="check")
        batch.drop_constraint("ck_security_events_event_type", type_="check")

    with op.batch_alter_table("cve_findings") as batch:
        batch.drop_constraint("ck_cve_findings_confidence", type_="check")
        batch.drop_constraint("ck_cve_findings_epss_probability", type_="check")
        batch.drop_constraint("ck_cve_findings_cvss_score", type_="check")
        batch.drop_constraint("ck_cve_findings_severity", type_="check")
        batch.drop_constraint("uq_cve_findings_tenant_device_internal", type_="unique")

    with op.batch_alter_table("inventory_snapshots") as batch:
        batch.drop_constraint("ck_inventory_snapshots_schema_version", type_="check")

    with op.batch_alter_table("devices") as batch:
        batch.drop_constraint("ck_devices_critical_cve_count", type_="check")
        batch.drop_constraint("ck_devices_cve_count", type_="check")
        batch.drop_constraint("ck_devices_risk_score", type_="check")
        batch.drop_constraint("ck_devices_status", type_="check")
