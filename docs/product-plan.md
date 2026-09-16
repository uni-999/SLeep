# SLeep product plan

## Product goal

SLeep is a cloud, multi-tenant workspace for SOC analysts. It collects system
facts from Linux and Windows servers, matches applicable CVEs, explains possible
exploitation paths, estimates risk and remediation cost, and produces a plan for
specialists. It never receives general-purpose remote control of customer hosts.

## Accepted architecture

- A low-load Go service collects packages, SBOM, ports, processes, configuration,
  network relationships, logs, accounts, and permissions.
- The agent initiates outbound mTLS connections to the cloud gateway.
- Raw logs and snapshots are stored in a Data Lake.
- Python workers normalize records, cluster events, build graphs, match CVEs,
  calculate risk, optimize remediation, and prepare reports.
- FastAPI exposes tenant-scoped product APIs.
- React and TypeScript provide the analyst workspace.
- PostgreSQL stores normalized product state; object storage keeps raw snapshots
  and generated reports.

Graph computation never runs inside the agent. The cloud maintains a slowly
changing asset graph and builds a focused graph for each clustered event.

## Device workspace

The first device view has two active tabs:

- `CVE`: applicable findings, evidence, exposure, confidence, and remediation.
- `Events`: security-relevant activity grouped from raw records.

The CVE snapshot is recalculated when device inventory changes and when the
global vulnerability knowledge base receives new information.

## Event model

The MVP uses two levels:

```text
Raw record -> Event
```

Event clustering is deterministic and type-specific. Authentication, process,
network, package, and service/configuration events each use their own correlation
key, inactivity gap, and maximum time window. Every event retains references to
its raw evidence.

## Risk and verification

The calculation engine remains deterministic and explainable:

```text
expected risk = exploitation probability * impact
remediation value = risk reduction - remediation cost - regression risk
```

The system evaluates 30-day, quarterly, and annual horizons and produces quick,
budget-optimal, and maximum-risk-reduction plans.

The MVP supports safe network probes and confirmation of vulnerable behavior
without obtaining access. The platform sends declarative, allowlisted probe jobs,
never arbitrary shell commands. Local and cloud probes provide internal and
external perspectives.

## MVP boundary

- Tenant-scoped organizations and basic roles.
- Go agent for Ubuntu/Debian, RHEL-compatible distributions, and Windows Server.
- mTLS enrollment and telemetry delivery.
- Inventory snapshots and changes.
- CVE matching with evidence and confidence.
- Deterministic clustering for five initial event types.
- Device workspace with `CVE` and `Events` tabs.
- Safe verification jobs.
- Explainable risk score and remediation report.

## Deferred note: Incident

`Incident` intentionally stays outside the MVP. It will later represent an
analyst-owned investigation that joins multiple Events, CVEs, attack paths,
evidence, decisions, comments, and tasks:

```text
Raw record -> Event -> Incident
```

Adding it also requires ownership, collaboration, SLA, decision history, and
closure workflows. Until those features exist, Events remain independent and do
not imitate a partial incident-management system.
