# SLeep API

The API exposes tenant-scoped devices, inventory snapshots, CVE findings,
clustered events, and safe probe jobs. Product state is stored in PostgreSQL via
SQLAlchemy, and schema changes are managed with Alembic.

The main Compose stack keeps PostgreSQL on an internal network. For local API
development, start only the database with the development override, which
publishes it on `127.0.0.1:5432` (set `POSTGRES_DEV_PORT` to change the port):

```bash
# from the repository root, with .env created from .env.example
docker compose -f compose.yaml -f compose.dev.yaml up -d postgres
```

Then run the API on the host:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
export SLEEP_DATABASE_URL='postgresql+psycopg://sleep:sleep@localhost:5432/sleep'
alembic upgrade head
python -m sleep_api.seed
uvicorn sleep_api.main:app --reload
```

The container entrypoint applies migrations automatically. Demo seed data is
created only when `SLEEP_SEED_DEMO=true`; seeding is idempotent and disabled by
default. Compose passes database credentials as separate environment variables,
so reserved URL characters are safe in generated passwords. A manually supplied
`SLEEP_DATABASE_URL` must still be a valid, percent-encoded URL. Disabling the
seed does not remove demo records that were created previously.

Every tenant-owned route currently requires `X-Organization-ID`. This is a
development boundary only; production authentication will derive the tenant and
role from verified identity claims instead of trusting a client-provided header.

Device `cve_count` and `critical_cve_count` are computed from `cve_findings` on
every read; they are not stored on the device row.

Run the unit and SQLite migration checks with `pytest`. To include the PostgreSQL
migration check, provide an empty disposable database, for example one created
in the development container:

```bash
docker compose -f compose.yaml -f compose.dev.yaml exec postgres createdb -U sleep sleep_test
SLEEP_TEST_DATABASE_URL='postgresql+psycopg://sleep:sleep@localhost:5432/sleep_test' pytest
```
