import os
from pathlib import Path
import subprocess
import sys

import pytest


SERVICE_ROOT = Path(__file__).resolve().parents[1]


def run_alembic(database_url: str, *arguments: str) -> None:
    environment = os.environ.copy()
    environment["SLEEP_DATABASE_URL"] = database_url
    subprocess.run(
        [sys.executable, "-m", "alembic", "-c", "alembic.ini", *arguments],
        cwd=SERVICE_ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )


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
