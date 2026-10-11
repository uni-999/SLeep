"""Which known vulnerabilities affect a given package version.

This is the knowledge-base half of CVE matching: the future matcher will call
it for every package in a device inventory snapshot. Package names are Debian
*source* package names (``openssh``, not ``openssh-server``); an agent gets
them from ``dpkg-query -W -f='${source:Package}'``.
"""

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db_models import AdvisoryRecord, AffectedPackageRecord, EpssScoreRecord, KevEntryRecord
from .debversion import DebianVersion, InvalidVersion


@dataclass(frozen=True)
class AffectingVulnerability:
    cve_id: str
    advisory_id: str
    source: str
    title: str
    ecosystem: str
    package: str
    installed_version: str
    fixed_version: str | None
    severity: str | None
    cvss_score: float | None
    cvss_vector: str | None
    epss_probability: float | None
    epss_percentile: float | None
    known_exploited: bool
    reason: str


def is_affected(version: DebianVersion, introduced: str | None, fixed: str | None, last_affected: str | None) -> bool:
    if introduced is not None and version < DebianVersion(introduced):
        return False
    if fixed is not None:
        return version < DebianVersion(fixed)
    if last_affected is not None:
        return version <= DebianVersion(last_affected)
    return True


def _reason(installed: str, introduced: str | None, fixed: str | None, last_affected: str | None) -> str:
    lower = f"{introduced} <= " if introduced else ""
    if fixed is not None:
        return f"{lower}{installed} < {fixed} (fixed version)"
    if last_affected is not None:
        return f"{lower}{installed} <= {last_affected} (last affected version)"
    return f"{lower}{installed}; no fixed version published yet"


def find_affecting(session: Session, ecosystem: str, package: str, version: str) -> list[AffectingVulnerability]:
    installed = DebianVersion(version)
    rows = session.execute(
        select(AffectedPackageRecord, AdvisoryRecord, EpssScoreRecord, KevEntryRecord)
        .join(AdvisoryRecord, AdvisoryRecord.id == AffectedPackageRecord.advisory_id)
        .outerjoin(EpssScoreRecord, EpssScoreRecord.cve_id == AdvisoryRecord.cve_id)
        .outerjoin(KevEntryRecord, KevEntryRecord.cve_id == AdvisoryRecord.cve_id)
        .where(
            AffectedPackageRecord.ecosystem == ecosystem,
            AffectedPackageRecord.package == package,
            AdvisoryRecord.withdrawn_at.is_(None),
        )
    ).all()

    found: dict[str, AffectingVulnerability] = {}
    for affected, advisory, epss, kev in rows:
        if advisory.id in found:
            continue
        try:
            if not is_affected(installed, affected.introduced, affected.fixed, affected.last_affected):
                continue
        except InvalidVersion:
            # A malformed bound in the feed must not hide the other advisories.
            continue
        found[advisory.id] = AffectingVulnerability(
            cve_id=advisory.cve_id,
            advisory_id=advisory.id,
            source=advisory.source,
            title=advisory.title,
            ecosystem=affected.ecosystem,
            package=affected.package,
            installed_version=version,
            fixed_version=affected.fixed,
            severity=advisory.severity,
            cvss_score=advisory.cvss_score,
            cvss_vector=advisory.cvss_vector,
            epss_probability=epss.probability if epss else None,
            epss_percentile=epss.percentile if epss else None,
            known_exploited=kev is not None,
            reason=_reason(version, affected.introduced, affected.fixed, affected.last_affected),
        )

    return sorted(
        found.values(),
        key=lambda item: (not item.known_exploited, -(item.cvss_score or 0), item.cve_id),
    )
