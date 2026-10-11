from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session, sessionmaker

from sleep_vulndb.config import DEFAULT_OSV_ECOSYSTEMS
from sleep_vulndb.db_models import EpssScoreRecord, KevEntryRecord
from sleep_vulndb.debversion import DebianVersion, InvalidVersion
from sleep_vulndb.lookup import find_affecting, is_affected
from sleep_vulndb.sources.osv import OSV_SOURCES, _insert

from conftest import load_record, osv_record


SUPPORTED = frozenset(DEFAULT_OSV_ECOSYSTEMS)
JAMMY = "Ubuntu:22.04:LTS"


@pytest.fixture
def knowledge(sessions: sessionmaker[Session]) -> sessionmaker[Session]:
    ubuntu, debian = OSV_SOURCES["osv-ubuntu"], OSV_SOURCES["osv-debian"]
    advisories = [
        ubuntu.parse(load_record("UBUNTU-CVE-2024-6387"), SUPPORTED),
        debian.parse(load_record("DEBIAN-CVE-2024-6387"), SUPPORTED),
        ubuntu.parse(
            osv_record("UBUNTU-CVE-2026-1000", package="openssh", events=[{"introduced": "1:8.9p1-3ubuntu0.8"}],
                       cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            SUPPORTED,
        ),
        ubuntu.parse(
            osv_record("UBUNTU-CVE-2026-1001", package="openssh", withdrawn="2026-05-01T00:00:00Z"), SUPPORTED
        ),
    ]
    with sessions() as session:
        _insert(session, [advisory for advisory in advisories if advisory is not None])
        session.add(EpssScoreRecord(cve_id="CVE-2024-6387", probability=0.39, percentile=0.97))
        session.add(
            KevEntryRecord(
                cve_id="CVE-2026-1000", vendor_project="OpenBSD", product="OpenSSH", name="Synthetic",
                short_description="Synthetic", required_action="Update",
                date_added=datetime(2026, 3, 2, tzinfo=UTC).date(), known_ransomware_use=False,
            )
        )
        session.commit()
    return sessions


def test_vulnerable_version_is_reported_with_context(knowledge: sessionmaker[Session]) -> None:
    with knowledge() as session:
        found = find_affecting(session, JAMMY, "openssh", "1:8.9p1-3ubuntu0.6")

    assert [item.cve_id for item in found] == ["CVE-2024-6387"]
    [item] = found
    assert item.advisory_id == "UBUNTU-CVE-2024-6387"
    assert (item.fixed_version, item.severity, item.cvss_score) == ("1:8.9p1-3ubuntu0.10", "high", 8.1)
    assert (item.epss_probability, item.known_exploited) == (0.39, False)
    assert item.reason == "1:8.9p1-3ubuntu0.6 < 1:8.9p1-3ubuntu0.10 (fixed version)"


def test_known_exploited_vulnerabilities_come_first(knowledge: sessionmaker[Session]) -> None:
    with knowledge() as session:
        found = find_affecting(session, JAMMY, "openssh", "1:8.9p1-3ubuntu0.9")

    assert [(item.cve_id, item.known_exploited) for item in found] == [
        ("CVE-2026-1000", True),
        ("CVE-2024-6387", False),
    ]
    assert found[0].reason == "1:8.9p1-3ubuntu0.8 <= 1:8.9p1-3ubuntu0.9; no fixed version published yet"


def test_fixed_version_is_not_affected(knowledge: sessionmaker[Session]) -> None:
    with knowledge() as session:
        found = find_affecting(session, JAMMY, "openssh", "1:8.9p1-3ubuntu0.10")
    assert [item.cve_id for item in found] == ["CVE-2026-1000"]


def test_lookup_is_scoped_to_the_release(knowledge: sessionmaker[Session]) -> None:
    with knowledge() as session:
        assert [item.advisory_id for item in find_affecting(session, "Debian:12", "openssh", "1:9.2p1-2+deb12u2")] == [
            "DEBIAN-CVE-2024-6387"
        ]
        assert find_affecting(session, "Debian:12", "openssh", "1:9.2p1-2+deb12u3") == []
        assert find_affecting(session, "Debian:11", "openssh", "1:8.4p1-5") == []
        assert find_affecting(session, JAMMY, "openssh-server", "1:8.9p1-3ubuntu0.6") == []


def test_invalid_installed_version_is_rejected(knowledge: sessionmaker[Session]) -> None:
    with knowledge() as session, pytest.raises(InvalidVersion):
        find_affecting(session, JAMMY, "openssh", "latest")


@pytest.mark.parametrize(
    ("version", "introduced", "fixed", "last_affected", "expected"),
    [
        ("1.0", None, None, None, True),
        ("1.0", None, "1.1", None, True),
        ("1.1", None, "1.1", None, False),
        ("0.9", "1.0", "1.1", None, False),
        ("1.0", "1.0", "1.1", None, True),
        ("1.4", "1.0", None, "1.4", True),
        ("1.5", "1.0", None, "1.4", False),
    ],
)
def test_interval_membership(
    version: str, introduced: str | None, fixed: str | None, last_affected: str | None, expected: bool
) -> None:
    assert is_affected(DebianVersion(version), introduced, fixed, last_affected) is expected
