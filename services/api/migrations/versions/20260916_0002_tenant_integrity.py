"""Enforce tenant ownership in resource relationships.

Revision ID: 20260916_0002
Revises: 20260916_0001
Create Date: 2026-09-16
"""

from collections.abc import Sequence

from alembic import op


revision: str = "20260916_0002"
down_revision: str | None = "20260916_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("devices") as batch:
        batch.create_unique_constraint("uq_devices_tenant_internal", ["organization_id", "id"])

    with op.batch_alter_table("cve_findings") as batch:
        batch.create_unique_constraint("uq_cve_findings_tenant_internal", ["organization_id", "id"])

    with op.batch_alter_table("inventory_snapshots") as batch:
        batch.drop_constraint("inventory_snapshots_organization_id_fkey", type_="foreignkey")
        batch.drop_constraint("inventory_snapshots_device_id_fkey", type_="foreignkey")
        batch.create_foreign_key(
            "fk_inventory_snapshots_tenant_device",
            "devices",
            ["organization_id", "device_id"],
            ["organization_id", "id"],
            ondelete="CASCADE",
        )

    with op.batch_alter_table("cve_findings") as batch:
        batch.drop_constraint("cve_findings_organization_id_fkey", type_="foreignkey")
        batch.drop_constraint("cve_findings_device_id_fkey", type_="foreignkey")
        batch.create_foreign_key(
            "fk_cve_findings_tenant_device",
            "devices",
            ["organization_id", "device_id"],
            ["organization_id", "id"],
            ondelete="CASCADE",
        )

    with op.batch_alter_table("security_events") as batch:
        batch.drop_constraint("security_events_organization_id_fkey", type_="foreignkey")
        batch.drop_constraint("security_events_device_id_fkey", type_="foreignkey")
        batch.create_foreign_key(
            "fk_security_events_tenant_device",
            "devices",
            ["organization_id", "device_id"],
            ["organization_id", "id"],
            ondelete="CASCADE",
        )

    with op.batch_alter_table("probe_jobs") as batch:
        batch.drop_constraint("probe_jobs_organization_id_fkey", type_="foreignkey")
        batch.drop_constraint("probe_jobs_device_id_fkey", type_="foreignkey")
        batch.drop_constraint("probe_jobs_cve_finding_id_fkey", type_="foreignkey")
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


def downgrade() -> None:
    with op.batch_alter_table("probe_jobs") as batch:
        batch.drop_constraint("fk_probe_jobs_tenant_cve", type_="foreignkey")
        batch.drop_constraint("fk_probe_jobs_tenant_device", type_="foreignkey")
        batch.create_foreign_key(
            "probe_jobs_organization_id_fkey",
            "organizations",
            ["organization_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch.create_foreign_key(
            "probe_jobs_device_id_fkey",
            "devices",
            ["device_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch.create_foreign_key(
            "probe_jobs_cve_finding_id_fkey",
            "cve_findings",
            ["cve_finding_id"],
            ["id"],
            ondelete="CASCADE",
        )

    with op.batch_alter_table("security_events") as batch:
        batch.drop_constraint("fk_security_events_tenant_device", type_="foreignkey")
        batch.create_foreign_key(
            "security_events_organization_id_fkey",
            "organizations",
            ["organization_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch.create_foreign_key(
            "security_events_device_id_fkey",
            "devices",
            ["device_id"],
            ["id"],
            ondelete="CASCADE",
        )

    with op.batch_alter_table("cve_findings") as batch:
        batch.drop_constraint("fk_cve_findings_tenant_device", type_="foreignkey")
        batch.create_foreign_key(
            "cve_findings_organization_id_fkey",
            "organizations",
            ["organization_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch.create_foreign_key(
            "cve_findings_device_id_fkey",
            "devices",
            ["device_id"],
            ["id"],
            ondelete="CASCADE",
        )

    with op.batch_alter_table("inventory_snapshots") as batch:
        batch.drop_constraint("fk_inventory_snapshots_tenant_device", type_="foreignkey")
        batch.create_foreign_key(
            "inventory_snapshots_organization_id_fkey",
            "organizations",
            ["organization_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch.create_foreign_key(
            "inventory_snapshots_device_id_fkey",
            "devices",
            ["device_id"],
            ["id"],
            ondelete="CASCADE",
        )

    with op.batch_alter_table("cve_findings") as batch:
        batch.drop_constraint("uq_cve_findings_tenant_internal", type_="unique")
    with op.batch_alter_table("devices") as batch:
        batch.drop_constraint("uq_devices_tenant_internal", type_="unique")
