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
  with outbound internet access and holds no tenant data. It connects to
  PostgreSQL under its own role that owns only the `vulndb` schema, so a flaw
  in parsing external feeds cannot reach tenant data. See
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

## Vulnerability matching

The agent reports every installed package with both its binary and its Debian
source package name and version, together with the fields of `/etc/os-release`.
The cloud maps the OS release to its OSV ecosystem (for example
`Ubuntu:22.04:LTS`), so the mapping can be fixed without updating agents, and
matching uses the source package name and source version. A separate matcher
process in the cloud recalculates findings; the API only stores incoming
snapshots. The knowledge base answers which CVEs affect that version in that
release. Versions are compared with the dpkg algorithm, and every answer carries
its reason (`1:8.9p1-3ubuntu0.6 < 1:8.9p1-3ubuntu0.10`), the distribution's
fixed version, the CVSS v3.1 base score, the EPSS probability, and the KEV flag.
The matcher turns these answers into `cve_findings` whose evidence names the OSV
record, the vulnerable interval, and the reason. EPSS and KEV feed the
exploitation-probability side of the risk formula below, and CVSS feeds the
impact side.

The knowledge base covers Debian and Ubuntu today. RHEL-compatible
distributions need RPM version comparison and their own OSV feeds; Windows
Server needs a separate source such as the Microsoft Security Update Guide.

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

## Delivery phases

The MVP boundary below is delivered in phases. Each phase ends with a working
end-to-end scenario, not with partially built parts of every component.

1. **CVE workspace (current).** Linux agent for Debian and Ubuntu (OS release
   and dpkg packages), snapshot ingestion authenticated by a per-device token,
   matching against the vulnerability knowledge base, recalculation on new
   snapshots and on knowledge-base updates, an explainable priority score, and
   the `CVE` tab of the analyst workspace backed by the API. Scope, decisions,
   contracts, and acceptance criteria are in
   [`cve-minimum.md`](cve-minimum.md) (in Russian).
2. **Incident investigation.** As specified in
   [`incident-investigation.md`](incident-investigation.md); starts only after
   phase 1 is accepted.
3. **Remaining MVP scope.** Log collection and event clustering beyond seed
   data, RHEL-compatible and Windows agents, mTLS enrollment, execution of
   safe probes, network exposure, the remediation plan with horizons, and
   analyst authentication.

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
