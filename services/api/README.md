# SLeep API

The API exposes tenant-scoped devices, inventory snapshots, CVE findings,
clustered events, and safe probe jobs. Product state is stored in PostgreSQL via
SQLAlchemy, and schema changes are managed with Alembic.

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

Run the unit and SQLite migration checks with `pytest`. To include the PostgreSQL
migration check, provide an empty disposable database:

```bash
SLEEP_TEST_DATABASE_URL='postgresql+psycopg://user:password@localhost/test_db' pytest
```
