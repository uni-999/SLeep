import os
from pathlib import Path
import subprocess
import sys

import pytest
from sqlalchemy import create_engine, text


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


def test_cve_counter_downgrade_restores_values(tmp_path: Path) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'counters.db'}"
    run_alembic(database_url, "upgrade", "head")

    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(
            text("INSERT INTO organizations (id, name, created_at) VALUES ('org-a', 'A', CURRENT_TIMESTAMP)")
        )
        connection.execute(
            text(
                "INSERT INTO devices (id, organization_id, external_id, name, platform, role, address,"
                " status, risk_score, last_seen_at, created_at, updated_at)"
                " VALUES ('device-1', 'org-a', 'web-01', 'web-01', 'Ubuntu', 'web', '10.0.0.1',"
                " 'online', 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
        )
        for index, severity in enumerate(["critical", "high", "critical"]):
            connection.execute(
                text(
                    "INSERT INTO cve_findings (id, organization_id, device_id, cve_id, title, component,"
                    " installed_version, fixed_version, severity, cvss_score, epss_probability, exposure,"
                    " confidence, evidence, recommended_action, detected_at, updated_at)"
                    " VALUES (:id, 'org-a', 'device-1', :cve_id, 'title', 'component', '1.0', NULL,"
                    " :severity, 5.0, 0.1, 'internal', 0.9, '[]', 'update', CURRENT_TIMESTAMP,"
                    " CURRENT_TIMESTAMP)"
                ),
                {"id": f"finding-{index}", "cve_id": f"CVE-2026-000{index}", "severity": severity},
            )
    engine.dispose()

    run_alembic(database_url, "downgrade", "20260916_0003")

    with engine.connect() as connection:
        counters = connection.execute(
            text("SELECT cve_count, critical_cve_count FROM devices WHERE id = 'device-1'")
        ).one()
    engine.dispose()
    assert tuple(counters) == (3, 2)


@pytest.mark.postgres
def test_migration_chain_on_postgres() -> None:
    database_url = os.getenv("SLEEP_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("SLEEP_TEST_DATABASE_URL is not configured")

    run_alembic(database_url, "upgrade", "head")
    run_alembic(database_url, "check")
    run_alembic(database_url, "downgrade", "base")
