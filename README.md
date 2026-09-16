# SLeep

SLeep is a multi-tenant security posture platform for collecting host facts,
matching applicable CVEs, clustering security-relevant activity, and producing
explainable remediation plans.

## Repository layout

- `apps/web`: SOC analyst workspace built with React, TypeScript, and Vite.
- `services/api`: tenant-scoped FastAPI contracts for devices, CVEs, events, and safe probes.
- `docs/product-plan.md`: accepted product decisions, MVP boundary, and deferred work.
- `compose.yaml`: provider-neutral self-hosted web and API stack behind Caddy.

The current slice uses representative data while the agent and ingestion pipeline
are being implemented.

## Run the full stack

```bash
cp .env.example .env
docker compose up --build -d
```

Open `http://localhost:8080`. Deployment and custom-domain instructions are in
[`docs/self-hosting.md`](docs/self-hosting.md).
