# Self-hosting SLeep

SLeep no longer requires ChatGPT Sites, Vinext, Wrangler, or Cloudflare Workers.
The web client is a static Vite application, the API is a FastAPI service, and
Caddy is the only public entry point.

## Local launch

```bash
cp .env.example .env
docker compose up --build -d
```

Open `http://localhost:8080`. The API health endpoint is available at
`http://localhost:8080/api/health`, and its OpenAPI UI is at
`http://localhost:8080/api/docs`.

Stop the stack without deleting its TLS state:

```bash
docker compose down
```

## Production host

The initial deployment needs a Linux VM with Docker Engine, the Compose plugin,
and inbound TCP ports 80 and 443. UDP 443 is optional but enables HTTP/3.

1. Point the domain's A and, if used, AAAA records to the VM.
2. Copy the repository to the VM and create `.env` from `.env.example`.
3. Set the public hostname and standard ports:

```dotenv
APP_HOST=app.example.by
HTTP_PORT=80
HTTPS_PORT=443
```

4. Start the stack:

```bash
docker compose up --build -d
```

Caddy obtains and renews the public TLS certificate automatically. The API is
published under the same origin at `/api`; its container is not exposed directly.

## Current boundary

The API still uses the demo in-memory repository. PostgreSQL, the event queue,
object storage, authentication, and the separate agent mTLS gateway belong to
the next backend slices. The future `ingest` endpoint should be deployed as a
separate service and hostname instead of sharing the user-facing API boundary.

The old `chatgpt.site` deployment is independent from this stack. It can remain
as a private design preview and be removed after the first external deployment
is verified.
