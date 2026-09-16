# SLeep API

The first API slice fixes tenant-scoped contracts for devices, CVE findings,
clustered events, and safe probe jobs. It uses an in-memory repository until the
PostgreSQL schema and ingestion pipeline land.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
uvicorn sleep_api.main:app --reload
```

Every tenant-owned route currently requires `X-Organization-ID`. This is a
development boundary only; production authentication will derive the tenant and
role from verified identity claims instead of trusting a client-provided header.
