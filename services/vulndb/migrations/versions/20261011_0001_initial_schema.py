"""Create the vulnerability knowledge base schema.

Revision ID: 20261011_0001
Revises:
Create Date: 2026-10-11
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20261011_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCHEMA = "vulndb"
SEVERITY = "'critical', 'high', 'medium', 'low', 'info'"
FEED_SOURCES = "'osv-debian', 'osv-ubuntu', 'epss', 'kev'"


def upgrade() -> None:
    op.create_table(
        "advisories",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("details", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(16), nullable=True),
        sa.Column("cvss_vector", sa.String(255), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("vendor_severity", sa.String(32), nullable=True),
        sa.Column("reference_urls", sa.JSON(), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("withdrawn_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("source IN ('osv-debian', 'osv-ubuntu')", name="ck_advisories_source"),
        sa.CheckConstraint(f"severity IS NULL OR severity IN ({SEVERITY})", name="ck_advisories_severity"),
        sa.CheckConstraint("cvss_score IS NULL OR cvss_score BETWEEN 0 AND 10", name="ck_advisories_cvss_score"),
        schema=SCHEMA,
    )
    op.create_index("ix_advisories_source", "advisories", ["source"], schema=SCHEMA)
    op.create_index("ix_advisories_cve_id", "advisories", ["cve_id"], schema=SCHEMA)

    op.create_table(
        "affected_packages",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "advisory_id",
            sa.String(64),
            sa.ForeignKey(f"{SCHEMA}.advisories.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("ecosystem", sa.String(64), nullable=False),
        sa.Column("distro", sa.String(16), nullable=False),
        sa.Column("release", sa.String(32), nullable=False),
        sa.Column("package", sa.String(255), nullable=False),
        sa.Column("introduced", sa.String(255), nullable=True),
        sa.Column("fixed", sa.String(255), nullable=True),
        sa.Column("last_affected", sa.String(255), nullable=True),
        sa.Column("binaries", sa.JSON(), nullable=False),
        sa.CheckConstraint("fixed IS NULL OR last_affected IS NULL", name="ck_affected_packages_single_upper_bound"),
        schema=SCHEMA,
    )
    op.create_index("ix_affected_packages_lookup", "affected_packages", ["ecosystem", "package"], schema=SCHEMA)
    op.create_index("ix_affected_packages_advisory_id", "affected_packages", ["advisory_id"], schema=SCHEMA)

    op.create_table(
        "epss_scores",
        sa.Column("cve_id", sa.String(32), primary_key=True),
        sa.Column("probability", sa.Float(), nullable=False),
        sa.Column("percentile", sa.Float(), nullable=False),
        sa.Column("score_date", sa.Date(), nullable=True),
        sa.Column("model_version", sa.String(64), nullable=True),
        sa.CheckConstraint("probability BETWEEN 0 AND 1", name="ck_epss_scores_probability"),
        sa.CheckConstraint("percentile BETWEEN 0 AND 1", name="ck_epss_scores_percentile"),
        schema=SCHEMA,
    )

    op.create_table(
        "kev_entries",
        sa.Column("cve_id", sa.String(32), primary_key=True),
        sa.Column("vendor_project", sa.String(255), nullable=False),
        sa.Column("product", sa.String(255), nullable=False),
        sa.Column("name", sa.String(500), nullable=False),
        sa.Column("short_description", sa.Text(), nullable=False),
        sa.Column("required_action", sa.Text(), nullable=False),
        sa.Column("date_added", sa.Date(), nullable=False),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("known_ransomware_use", sa.Boolean(), nullable=False),
        schema=SCHEMA,
    )

    op.create_table(
        "feed_state",
        sa.Column("source", sa.String(32), primary_key=True),
        sa.Column("etag", sa.String(255), nullable=True),
        sa.Column("last_modified", sa.String(64), nullable=True),
        sa.Column("cursor", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_full_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.CheckConstraint(f"source IN ({FEED_SOURCES})", name="ck_feed_state_source"),
        sa.CheckConstraint("consecutive_failures >= 0", name="ck_feed_state_consecutive_failures"),
        schema=SCHEMA,
    )

    op.create_table(
        "sync_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("mode", sa.String(16), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("records_written", sa.Integer(), nullable=False),
        sa.Column("records_deleted", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.CheckConstraint(f"source IN ({FEED_SOURCES})", name="ck_sync_runs_source"),
        sa.CheckConstraint("mode IS NULL OR mode IN ('full', 'incremental')", name="ck_sync_runs_mode"),
        sa.CheckConstraint(
            "status IN ('running', 'succeeded', 'not_modified', 'failed')", name="ck_sync_runs_status"
        ),
        sa.CheckConstraint("records_written >= 0 AND records_deleted >= 0", name="ck_sync_runs_counters"),
        schema=SCHEMA,
    )
    op.create_index("ix_sync_runs_source_started_at", "sync_runs", ["source", "started_at"], schema=SCHEMA)


def downgrade() -> None:
    op.drop_index("ix_sync_runs_source_started_at", table_name="sync_runs", schema=SCHEMA)
    op.drop_table("sync_runs", schema=SCHEMA)
    op.drop_table("feed_state", schema=SCHEMA)
    op.drop_table("kev_entries", schema=SCHEMA)
    op.drop_table("epss_scores", schema=SCHEMA)
    op.drop_index("ix_affected_packages_advisory_id", table_name="affected_packages", schema=SCHEMA)
    op.drop_index("ix_affected_packages_lookup", table_name="affected_packages", schema=SCHEMA)
    op.drop_table("affected_packages", schema=SCHEMA)
    op.drop_index("ix_advisories_cve_id", table_name="advisories", schema=SCHEMA)
    op.drop_index("ix_advisories_source", table_name="advisories", schema=SCHEMA)
    op.drop_table("advisories", schema=SCHEMA)
