"""The least-privileged database role of vulndb (deploy/postgres/vulndb-role.sql).

The Compose stack runs that script as the database owner before vulndb starts.
These tests run it the same way, with psql, against SLEEP_TEST_DATABASE_URL.
"""

import os
import shutil
import subprocess
from collections.abc import Iterator

import pytest
from sqlalchemy import URL, create_engine, make_url, text
from sqlalchemy.exc import DBAPIError

from test_migrations import SERVICE_ROOT, run_alembic


pytestmark = pytest.mark.postgres

ROLE_SCRIPT = SERVICE_ROOT.parents[1] / "deploy" / "postgres" / "vulndb-role.sql"
ROLE = "sleep_vulndb_test"
PASSWORD = "it's a 'quoted' password"


def run_role_script(admin: URL, role: str = ROLE, password: str = PASSWORD) -> subprocess.CompletedProcess[str]:
    psql = shutil.which("psql")
    if psql is None:
        pytest.skip("psql is not installed")
    environment = {
        **os.environ,
        "PGHOST": admin.host or "localhost",
        "PGPORT": str(admin.port or 5432),
        "PGUSER": admin.username or "",
        "PGPASSWORD": admin.password or "",
        "PGDATABASE": admin.database or "",
        "VULNDB_DB_USER": role,
        "VULNDB_DB_PASSWORD": password,
    }
    return subprocess.run(
        [psql, "--no-psqlrc", "--quiet", "-v", "ON_ERROR_STOP=1", "-f", str(ROLE_SCRIPT)],
        env=environment,
        capture_output=True,
        text=True,
    )


def apply_role_script(admin: URL) -> None:
    result = run_role_script(admin)
    if result.returncode != 0:
        pytest.fail(f"vulndb-role.sql failed:\n{result.stdout}\n{result.stderr}")


def scalar(url: URL, query: str) -> object:
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            return connection.scalar(text(query))
    finally:
        engine.dispose()


def execute(url: URL, statement: str) -> None:
    engine = create_engine(url)
    try:
        with engine.begin() as connection:
            connection.execute(text(statement))
    finally:
        engine.dispose()


def owners(admin: URL) -> set[str]:
    """Owners of the vulndb schema and of every table and sequence in it."""
    engine = create_engine(admin)
    try:
        with engine.connect() as connection:
            return set(
                connection.scalars(
                    text(
                        "SELECT pg_get_userbyid(c.relowner) FROM pg_class c "
                        "JOIN pg_namespace n ON n.oid = c.relnamespace "
                        "WHERE n.nspname = 'vulndb' AND c.relkind IN ('r', 'S') "
                        "UNION SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'vulndb'"
                    )
                )
            )
    finally:
        engine.dispose()


def clean(admin: URL) -> None:
    execute(admin, "DROP SCHEMA IF EXISTS vulndb CASCADE")
    execute(admin, "DROP TABLE IF EXISTS public.vulndb_role_probe")
    if scalar(admin, f"SELECT 1 FROM pg_roles WHERE rolname = '{ROLE}'"):
        execute(admin, f'DROP OWNED BY "{ROLE}"')
        execute(admin, f'DROP ROLE "{ROLE}"')


@pytest.fixture
def admin() -> Iterator[URL]:
    database_url = os.getenv("SLEEP_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("SLEEP_TEST_DATABASE_URL is not configured")
    url = make_url(database_url)
    clean(url)
    # A table of the API, which the vulndb role must not be able to read.
    execute(url, "CREATE TABLE public.vulndb_role_probe (id integer)")
    yield url
    clean(url)


def as_role(admin: URL) -> URL:
    return admin.set(username=ROLE, password=PASSWORD)


def test_fresh_database(admin: URL) -> None:
    apply_role_script(admin)
    role = as_role(admin)

    # The service migrates its own schema without any right to create schemas.
    run_alembic(role.render_as_string(hide_password=False), "upgrade", "head")
    run_alembic(role.render_as_string(hide_password=False), "check")

    assert owners(admin) == {ROLE}
    assert scalar(
        admin, f"SELECT rolsuper OR rolcreatedb OR rolcreaterole FROM pg_roles WHERE rolname = '{ROLE}'"
    ) is False
    assert scalar(role, "SELECT count(*) FROM vulndb.feed_state") == 0
    for forbidden in (
        "SELECT count(*) FROM public.vulndb_role_probe",
        "CREATE TABLE public.vulndb_role_intruder (id integer)",
        "CREATE SCHEMA vulndb_role_intruder",
    ):
        with pytest.raises(DBAPIError, match="permission denied"):
            execute(role, forbidden)

    run_alembic(role.render_as_string(hide_password=False), "downgrade", "base")


def test_existing_installation_is_handed_over(admin: URL) -> None:
    # Before this role existed, vulndb migrated its schema as the owner.
    run_alembic(admin.render_as_string(hide_password=False), "upgrade", "head")
    assert owners(admin) == {admin.username}

    apply_role_script(admin)
    apply_role_script(admin)  # every stack start runs it again

    assert owners(admin) == {ROLE}
    role = as_role(admin)
    run_alembic(role.render_as_string(hide_password=False), "check")
    run_alembic(role.render_as_string(hide_password=False), "downgrade", "base")


def test_the_owner_role_is_never_demoted(admin: URL) -> None:
    result = run_role_script(admin, role=admin.username or "")

    assert result.returncode != 0
    assert "must differ from the database owner" in result.stderr
    assert scalar(admin, "SELECT rolsuper FROM pg_roles WHERE rolname = current_user") is True
