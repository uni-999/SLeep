"""Which known vulnerabilities affect a given package version.

This is the knowledge-base half of CVE matching. Package names are Debian
*source* package names (``openssh``, not ``openssh-server``); an agent gets
them from ``dpkg-query -W -f='${source:Package}'``.

``find_affecting_many`` answers for a whole inventory snapshot with one query
per ``LOOKUP_BATCH_SIZE`` package names; ``find_affecting`` is the same
answer for a single package (the ``sleep-vulndb lookup`` command).
"""

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from .db_models import AdvisoryRecord, AffectedPackageRecord, EpssScoreRecord, KevEntryRecord
from .debversion import DebianVersion, InvalidVersion


# Package names per query. Keeps the number of bind parameters far below the
# limits of PostgreSQL (65535) and old SQLite builds (999).
LOOKUP_BATCH_SIZE = 500


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


@dataclass(frozen=True)
class BatchLookup:
    """Result of ``find_affecting_many``.

    ``affected`` maps ``(package, version)`` exactly as given to the
    vulnerabilities of that version; versions without any are absent.
    ``invalid_versions`` lists the pairs whose version dpkg would reject: they
    were not checked, which is not the same as "not vulnerable".
    """

    affected: dict[tuple[str, str], list[AffectingVulnerability]] = field(default_factory=dict)
    invalid_versions: list[tuple[str, str]] = field(default_factory=list)


def is_affected(version: DebianVersion, introduced: str | None, fixed: str | None, last_affected: str | None) -> bool:
    return _in_interval(
        version,
        DebianVersion(introduced) if introduced is not None else None,
        DebianVersion(fixed) if fixed is not None else None,
        DebianVersion(last_affected) if last_affected is not None else None,
    )


def find_affecting(session: Session, ecosystem: str, package: str, version: str) -> list[AffectingVulnerability]:
    """Vulnerabilities of one package version. Raises InvalidVersion for a malformed version."""
    DebianVersion(version)
    return find_affecting_many(session, ecosystem, [(package, version)]).affected.get((package, version), [])


def find_affecting_many(session: Session, ecosystem: str, packages: Iterable[tuple[str, str]]) -> BatchLookup:
    """Vulnerabilities of many ``(source package, version)`` pairs of one release.

    One package may be listed with several versions (for example, a few
    installed kernels built from the ``linux`` source package); each version
    is answered separately.
    """
    installed: dict[str, list[tuple[str, DebianVersion]]] = {}
    result = BatchLookup()
    for package, version in dict.fromkeys(packages):
        try:
            parsed = DebianVersion(version)
        except InvalidVersion:
            result.invalid_versions.append((package, version))
            continue
        installed.setdefault(package, []).append((version, parsed))

    bounds = _BoundCache()
    seen: set[tuple[str, str, str]] = set()
    names = sorted(installed)
    for start in range(0, len(names), LOOKUP_BATCH_SIZE):
        for row in session.execute(_query(ecosystem, names[start : start + LOOKUP_BATCH_SIZE])):
            try:
                introduced, fixed, last_affected = (
                    bounds.get(row.introduced),
                    bounds.get(row.fixed),
                    bounds.get(row.last_affected),
                )
            except InvalidVersion:
                # A malformed bound in the feed must not hide the other advisories.
                continue
            for version, parsed in installed[row.package]:
                key = (row.package, version, row.advisory_id)
                if key in seen or not _in_interval(parsed, introduced, fixed, last_affected):
                    continue
                seen.add(key)
                result.affected.setdefault((row.package, version), []).append(
                    AffectingVulnerability(
                        cve_id=row.cve_id,
                        advisory_id=row.advisory_id,
                        source=row.source,
                        title=row.title,
                        ecosystem=row.ecosystem,
                        package=row.package,
                        installed_version=version,
                        fixed_version=row.fixed,
                        severity=row.severity,
                        cvss_score=row.cvss_score,
                        cvss_vector=row.cvss_vector,
                        epss_probability=row.epss_probability,
                        epss_percentile=row.epss_percentile,
                        known_exploited=row.kev_cve_id is not None,
                        reason=_reason(version, row.introduced, row.fixed, row.last_affected),
                    )
                )

    for vulnerabilities in result.affected.values():
        vulnerabilities.sort(key=lambda item: (not item.known_exploited, -(item.cvss_score or 0), item.cve_id))
    return result


def _query(ecosystem: str, names: list[str]) -> Select[Any]:
    return (
        select(
            AffectedPackageRecord.package,
            AffectedPackageRecord.ecosystem,
            AffectedPackageRecord.introduced,
            AffectedPackageRecord.fixed,
            AffectedPackageRecord.last_affected,
            AdvisoryRecord.id.label("advisory_id"),
            AdvisoryRecord.cve_id,
            AdvisoryRecord.source,
            AdvisoryRecord.title,
            AdvisoryRecord.severity,
            AdvisoryRecord.cvss_score,
            AdvisoryRecord.cvss_vector,
            EpssScoreRecord.probability.label("epss_probability"),
            EpssScoreRecord.percentile.label("epss_percentile"),
            KevEntryRecord.cve_id.label("kev_cve_id"),
        )
        .join(AdvisoryRecord, AdvisoryRecord.id == AffectedPackageRecord.advisory_id)
        .outerjoin(EpssScoreRecord, EpssScoreRecord.cve_id == AdvisoryRecord.cve_id)
        .outerjoin(KevEntryRecord, KevEntryRecord.cve_id == AdvisoryRecord.cve_id)
        .where(
            AffectedPackageRecord.ecosystem == ecosystem,
            AffectedPackageRecord.package.in_(names),
            AdvisoryRecord.withdrawn_at.is_(None),
        )
        # A stable order makes the answer deterministic when one advisory has
        # several intervals for the same package.
        .order_by(AffectedPackageRecord.id)
    )


class _BoundCache:
    """Parse every interval bound once per call: a snapshot has ~1500 packages
    and popular bounds repeat across them."""

    def __init__(self) -> None:
        self._parsed: dict[str, DebianVersion | InvalidVersion] = {}

    def get(self, text: str | None) -> DebianVersion | None:
        if text is None:
            return None
        parsed = self._parsed.get(text)
        if parsed is None:
            try:
                parsed = DebianVersion(text)
            except InvalidVersion as error:
                parsed = error
            self._parsed[text] = parsed
        if isinstance(parsed, InvalidVersion):
            raise InvalidVersion(str(parsed))
        return parsed


def _in_interval(
    version: DebianVersion,
    introduced: DebianVersion | None,
    fixed: DebianVersion | None,
    last_affected: DebianVersion | None,
) -> bool:
    if introduced is not None and version < introduced:
        return False
    if fixed is not None:
        return version < fixed
    if last_affected is not None:
        return version <= last_affected
    return True


def _reason(installed: str, introduced: str | None, fixed: str | None, last_affected: str | None) -> str:
    lower = f"{introduced} <= " if introduced else ""
    if fixed is not None:
        return f"{lower}{installed} < {fixed} (fixed version)"
    if last_affected is not None:
        return f"{lower}{installed} <= {last_affected} (last affected version)"
    return f"{lower}{installed}; no fixed version published yet"
