# SLeep vulnerability knowledge base

`sleep-vulndb` keeps a global vulnerability knowledge base up to date in the
PostgreSQL schema `vulndb`. It is the only SLeep service with outbound internet
access; it accepts no inbound connections. The design is described in
[`docs/vulnerability-database.md`](../../docs/vulnerability-database.md).

| Source | Feed | Refresh |
|---|---|---|
| `osv-debian` | OSV.dev `Debian/` export, `DEBIAN-CVE-*` records | hourly, incremental |
| `osv-ubuntu` | OSV.dev `Ubuntu/` export, `UBUNTU-CVE-*` records | hourly, incremental |
| `epss` | FIRST EPSS daily scores (`epss_scores-current.csv.gz`) | daily |
| `kev` | CISA Known Exploited Vulnerabilities catalog | every 6 hours |

The knowledge base is reference data shared by all organizations; it holds no
tenant data. The API will read it to turn inventory snapshots into CVE findings.

## Commands

```bash
sleep-vulndb run        # service mode: sync every source on its own interval
sleep-vulndb sync       # sync all enabled sources once (--source NAME, --full)
sleep-vulndb status     # last success, cursor, failures, record counts, last run of each source
sleep-vulndb status --runs 20   # the 20 most recent entries of the run journal
sleep-vulndb lookup --ecosystem Ubuntu:22.04:LTS --package openssh --version 1:8.9p1-3ubuntu0.6
sleep-vulndb health     # container healthcheck: loop heartbeat, stuck syncs, database
```

In the Compose stack:

```bash
docker compose exec vulndb sleep-vulndb status
docker compose exec vulndb sleep-vulndb sync --source kev
```

`lookup` expects the Debian **source** package name (`openssh`, not
`openssh-server`); on a host it is `dpkg-query -W -f='${source:Package} ${Version}\n'`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SLEEP_VULNDB_SOURCES` | all | Comma-separated sources; `none` keeps the service idle. |
| `SLEEP_VULNDB_OSV_ECOSYSTEMS` | Debian 11–13, Ubuntu 20.04/22.04/24.04 LTS | OSV ecosystems to keep, e.g. `Debian:12,Ubuntu:22.04:LTS`; `*` keeps all. |
| `SLEEP_VULNDB_PROXY_URL` | — | HTTP(S) proxy for the feeds. |
| `SLEEP_VULNDB_<SOURCE>_INTERVAL_MINUTES` | 60 / 60 / 1440 / 360 | Refresh interval, e.g. `SLEEP_VULNDB_KEV_INTERVAL_MINUTES`. |
| `SLEEP_VULNDB_RETRY_MINUTES` | 15 | Retry delay after a failed run. |
| `SLEEP_VULNDB_MAX_SYNC_MINUTES` | 120 | A single run longer than this makes `health` report a stuck sync. |
| `SLEEP_VULNDB_RUN_RETENTION_DAYS` | 90 | Finished entries of the run journal (`vulndb.sync_runs`) older than this are deleted. |
| `SLEEP_VULNDB_OSV_FULL_SYNC_DAYS` | 7 | A full OSV download runs at least this often. |
| `SLEEP_VULNDB_OSV_INCREMENTAL_LIMIT` | 2000 | More changed records than this triggers a full download. |
| `SLEEP_VULNDB_OSV_BASE_URL`, `SLEEP_VULNDB_EPSS_URL`, `SLEEP_VULNDB_KEV_URL` | public feeds | Alternative URLs, for example a mirror. |

Database settings are the same as the API's: `SLEEP_DATABASE_URL`, or
`SLEEP_DB_HOST`, `SLEEP_DB_PORT`, `SLEEP_DB_NAME`, `SLEEP_DB_USER`,
`SLEEP_DB_PASSWORD`. In the Compose stack the service connects as its own
least-privileged role `sleep_vulndb` (`VULNDB_DB_USER`, `VULNDB_DB_PASSWORD` in
`.env`), which owns only the `vulndb` schema. The one-shot `vulndb-init`
service creates that role with
[`deploy/postgres/vulndb-role.sql`](../../deploy/postgres/vulndb-role.sql)
before the updater starts.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest                                   # SQLite; feeds are faked in-process
SLEEP_TEST_DATABASE_URL='postgresql+psycopg://sleep:sleep@localhost:5432/sleep_test' pytest
```

The PostgreSQL tests need a superuser connection, and `tests/test_role.py`
also needs the `psql` client to run the role script.

Migrations have their own Alembic history: on PostgreSQL every table, including
`vulndb.alembic_version`, lives in the `vulndb` schema, so it never interferes
with the API's history in `public`. File names follow the API convention
(`YYYYMMDD_NNNN_short_name.py`).

To try a real sync against the development database (internet access needed):

```bash
export SLEEP_DATABASE_URL='postgresql+psycopg://sleep:sleep@localhost:5432/sleep'
alembic upgrade head
sleep-vulndb sync --source kev --source epss
SLEEP_VULNDB_OSV_ECOSYSTEMS=Ubuntu:22.04:LTS sleep-vulndb sync --source osv-ubuntu
```
