# Self-hosting SLeep

SLeep no longer requires ChatGPT Sites, Vinext, Wrangler, or Cloudflare Workers.
The web client is a static Vite application, the API is a FastAPI service,
PostgreSQL stores product state, and Caddy is the only public entry point.

## Local launch

```bash
cp .env.example .env
docker compose up --build -d
```

Open `http://localhost:8080` and sign in as `analyst` / `sleep-local` (the local
credentials from `.env.example`). The API health endpoint is available at
`http://localhost:8080/api/health`, and its OpenAPI UI is at
`http://localhost:8080/api/docs`; both are behind the same login, for example
`curl -u analyst:sleep-local http://localhost:8080/api/health`.

The stack refuses to start when `.env` does not define `POSTGRES_PASSWORD`,
`VULNDB_DB_PASSWORD`, `BASIC_AUTH_USER`, or `BASIC_AUTH_HASH`. An `.env`
created before the vulnerability database got its own role lacks
`VULNDB_DB_PASSWORD`: copy that line from `.env.example`.

Set `SLEEP_SEED_DEMO=true` in `.env` before the first start when sample devices,
events, and CVE findings are useful. With the default `false`, the database starts
empty and waits for real inventory data. Changing the flag to `false` later only
stops future seeding; it does not delete demo records that already exist.

Stop the stack without deleting its TLS state:

```bash
docker compose down
```

## Production host

The initial deployment needs a Linux VM with Docker Engine, the Compose plugin,
and inbound TCP ports 80 and 443. UDP 443 is optional but enables HTTP/3.

1. Point the domain's A and, if used, AAAA records to the VM.
2. Copy the repository to the VM and create `.env` from `.env.example`.
3. Set the public hostname, standard ports, and new secrets:

```dotenv
APP_HOST=app.example.by
HTTP_PORT=80
HTTPS_PORT=443
POSTGRES_PASSWORD=replace-with-a-long-random-secret
VULNDB_DB_PASSWORD=replace-with-another-long-random-secret
BASIC_AUTH_USER=replace-with-a-login
BASIC_AUTH_HASH='$2a$14$...'
```

   Generate the password hash with Caddy and keep it in single quotes, because
   Compose would otherwise treat the `$` characters as variable references:

```bash
docker run --rm caddy:2-alpine caddy hash-password --plaintext 'your-password'
```

   Never reuse the local `.env.example` values on a public host.

4. Start the stack:

```bash
docker compose up --build -d
```

Caddy obtains and renews the public TLS certificate automatically. The API is
published under the same origin at `/api`; its container and PostgreSQL are not
exposed directly. Alembic migrations run before every API start and PostgreSQL
data is retained in the `postgres_data` Docker volume.

## Troubleshooting the web image build

`pnpm install` inside the web image downloads about 440 packages from
`registry.npmjs.org`. On an unstable connection a single request can fail with
`ETIMEDOUT`. The build already retries with long timeouts and keeps downloaded
packages in a BuildKit cache, so running the same command again continues from
where it stopped:

```bash
docker compose build web
```

If downloads keep timing out, check that containers reach the registry:

```bash
docker run --rm node:22-alpine npm view pnpm@10.34.5 version
```

When they do not, route Docker Desktop through your VPN or proxy
(Settings → Resources → Proxies), or set `NPM_REGISTRY` in `.env` to an
npm-compatible mirror. The lockfile pins integrity hashes, so a mirror cannot
substitute package contents.

## Vulnerability knowledge base updater

The `vulndb` service downloads Debian and Ubuntu advisories (OSV.dev), EPSS
scores, and the CISA KEV catalog into the PostgreSQL schema `vulndb`. It is the
only container with outbound internet access (the `egress` network); it needs
HTTPS access to `osv-vulnerabilities.storage.googleapis.com`,
`epss.empiricalsecurity.com`, and `www.cisa.gov`. The first full download takes
a few minutes; after that only changes are fetched.

```bash
docker compose exec vulndb sleep-vulndb status        # freshness and last run of every source
docker compose exec vulndb sleep-vulndb status --runs 20   # recent run journal
docker compose exec vulndb sleep-vulndb sync --full   # reload everything now
docker compose logs -f vulndb
```

The updater connects to PostgreSQL as its own role `sleep_vulndb`, with the
password `VULNDB_DB_PASSWORD`. The role owns the `vulndb` schema and nothing
else: it is not a superuser and cannot read the API's tables. The one-shot
`vulndb-init` service creates or updates the role as the database owner
(`deploy/postgres/vulndb-role.sql`) on every start, before `vulndb` starts, so
the owner's password never reaches the internet-facing container. On an
existing installation it also hands over the `vulndb` tables that earlier
versions created as the owner. Changing `VULNDB_DB_PASSWORD` in `.env` takes
effect on the next `docker compose up -d`.

If the feeds are reachable only through a proxy, set `SLEEP_VULNDB_PROXY_URL`
in `.env`. `SLEEP_VULNDB_SOURCES=none` keeps the service idle, for example on a
host without internet access. A feed that is temporarily unreachable does not
make the container unhealthy; check `sleep-vulndb status` instead. All options
are listed in [`services/vulndb/README.md`](../services/vulndb/README.md).

## Access boundary

The API does not authenticate users yet: it trusts the `X-Organization-ID`
header to select the tenant. HTTP basic authentication in Caddy therefore guards
the whole site, including `/api`, so anonymous clients cannot read any tenant's
data. Everyone who knows the shared login can still choose any organization, so
this is suitable for a single-team demo only. Real authentication will derive the
tenant and role from verified identity claims and replace this boundary.

## Current boundary

The local stack seeds a demo organization when `SLEEP_SEED_DEMO=true`. Disable
it before production deployment. Demo
seeding is disabled by default; enable it explicitly only for a local preview. The
event queue, object storage, authentication, and separate agent mTLS gateway
belong to the next backend slices. The future `ingest` endpoint should be
deployed as a separate service and hostname instead of sharing the user-facing
API boundary.
