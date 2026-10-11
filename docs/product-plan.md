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
- A separate updater service (`services/vulndb`) keeps a global vulnerability
  knowledge base in the PostgreSQL schema `vulndb`: Debian and Ubuntu advisories
  from OSV.dev, EPSS scores, and the CISA KEV catalog. It is the only service
  with outbound internet access and holds no tenant data. See
  [`vulnerability-database.md`](vulnerability-database.md).
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

The MVP uses three levels:

```text
Raw record -> Event -> Incident
```

Event clustering is deterministic and type-specific. Authentication, process,
network, package, and service/configuration events each use their own correlation
key, inactivity gap, and maximum time window. Every event retains references to
its raw evidence.

## Incident investigation

An `Incident` is an analyst-owned investigation. The MVP keeps it deliberately
small:

- An analyst creates an Incident from one or more Events, possibly from several
  devices of the same organization.
- CVE findings are linked as a probable `entry_point` or as `context`.
- The timeline is assembled on read from linked Events, CVE detection times,
  safe probe jobs, and analyst notes, so it always reflects the current scope.
- Deterministic, explainable rules suggest related Events (same actor, same
  device within the time window, shared entity) and CVE findings (component
  matches the event, external exposure).
- The lifecycle is `open -> investigating -> closed`; closing requires a verdict
  and a written conclusion, and every change is journaled.

The full specification (data model, timeline, suggestion rules, API, UI, and the
demo scenario) is in [`incident-investigation.md`](incident-investigation.md).

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
- Simplified incident investigation: Events and CVE findings grouped into an
  Incident, automatic timeline, suggestions, notes, verdict, and conclusion.
- Safe verification jobs.
- Explainable risk score and remediation report.

## Deferred: full incident management

The MVP Incident is a single-analyst investigation record, not a full
incident-management system. The following stay outside the MVP:

- ownership by several analysts, SLA, escalations, and notifications;
- comment threads, tasks, and decision history beyond the change journal;
- attack paths built from the asset graph inside an Incident;
- automatic Incident creation from correlation rules;
- playbooks and any automated response on customer hosts;
- integration with external ticketing systems.
