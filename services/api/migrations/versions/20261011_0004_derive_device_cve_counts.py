"""Derive device CVE counters from cve_findings instead of storing them.

Revision ID: 20261011_0004
Revises: 20260916_0003
Create Date: 2026-10-11
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20261011_0004"
down_revision: str | None = "20260916_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("devices") as batch:
        batch.drop_constraint("ck_devices_critical_cve_count", type_="check")
        batch.drop_constraint("ck_devices_cve_count", type_="check")
        batch.drop_column("critical_cve_count")
        batch.drop_column("cve_count")


def downgrade() -> None:
    with op.batch_alter_table("devices") as batch:
        batch.add_column(sa.Column("cve_count", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("critical_cve_count", sa.Integer(), nullable=False, server_default="0"))

    op.execute(
        """
        UPDATE devices SET
            cve_count = (
                SELECT count(*) FROM cve_findings
                WHERE cve_findings.device_id = devices.id
            ),
            critical_cve_count = (
                SELECT count(*) FROM cve_findings
                WHERE cve_findings.device_id = devices.id
                  AND cve_findings.severity = 'critical'
            )
        """
    )

    with op.batch_alter_table("devices") as batch:
        batch.alter_column("cve_count", server_default=None)
        batch.alter_column("critical_cve_count", server_default=None)
        batch.create_check_constraint("ck_devices_cve_count", "cve_count >= 0")
        batch.create_check_constraint("ck_devices_critical_cve_count", "critical_cve_count >= 0")
