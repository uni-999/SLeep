import os
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect


SERVICE_ROOT = Path(__file__).resolve().parents[1]


def run_alembic(database_url: str, *arguments: str) -> None:
    environment = os.environ.copy()
    environment["SLEEP_DATABASE_URL"] = database_url
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", "alembic.ini", *arguments],
        cwd=SERVICE_ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"alembic {' '.join(arguments)} failed:\n{result.stdout}\n{result.stderr}")


def test_migration_chain_on_sqlite(tmp_path: Path) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'migrations.db'}"

    run_alembic(database_url, "upgrade", "head")
    run_alembic(database_url, "check")
    run_alembic(database_url, "downgrade", "base")


@pytest.mark.postgres
def test_migration_chain_on_postgres() -> None:
    database_url = os.getenv("SLEEP_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("SLEEP_TEST_DATABASE_URL is not configured")

    run_alembic(database_url, "upgrade", "head")
    run_alembic(database_url, "check")

    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names(schema="vulndb"))
        assert {"advisories", "affected_packages", "epss_scores", "kev_entries", "feed_state", "sync_runs",
                "alembic_version"} <= tables
        # The knowledge base never writes into the API's schema.
        assert not {"advisories", "alembic_version"} & set(inspector.get_table_names(schema="public"))
    finally:
        engine.dispose()

    run_alembic(database_url, "downgrade", "base")
