from datetime import UTC, datetime

import pytest

from sleep_vulndb.config import DEFAULT_OSV_ECOSYSTEMS
from sleep_vulndb.sources.osv import OSV_SOURCES, _intervals

from conftest import load_record, osv_record


UBUNTU = OSV_SOURCES["osv-ubuntu"]
DEBIAN = OSV_SOURCES["osv-debian"]
SUPPORTED = frozenset(DEFAULT_OSV_ECOSYSTEMS)


def test_ubuntu_record_is_normalized() -> None:
    advisory = UBUNTU.parse(load_record("UBUNTU-CVE-2024-6387"), SUPPORTED)

    assert advisory is not None
    assert advisory.id == "UBUNTU-CVE-2024-6387"
    assert advisory.source == "osv-ubuntu"
    assert advisory.cve_id == "CVE-2024-6387"
    assert advisory.cvss_vector == "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert advisory.cvss_score == 8.1
    assert advisory.severity == "high"
    assert advisory.vendor_severity == "high"
    # No summary in Ubuntu records: the title is the first sentence of the details.
    assert advisory.title == "A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd)."
    assert advisory.modified_at == datetime(2026, 2, 4, 10, 12, 31, 523671, tzinfo=UTC)
    # Duplicate reference URLs are collapsed.
    assert advisory.reference_urls == (
        "https://ubuntu.com/security/CVE-2024-6387",
        "https://ubuntu.com/security/notices/USN-6859-1",
    )

    # Ubuntu Pro 18.04 is not in the configured releases.
    assert [(item.ecosystem, item.release, item.fixed) for item in advisory.affected] == [
        ("Ubuntu:22.04:LTS", "22.04", "1:8.9p1-3ubuntu0.10"),
        ("Ubuntu:24.04:LTS", "24.04", "1:9.6p1-3ubuntu13.3"),
    ]
    jammy = advisory.affected[0]
    assert jammy.package == "openssh"
    assert jammy.distro == "ubuntu"
    assert jammy.introduced is None
    assert jammy.binaries == ("openssh-client", "openssh-server", "openssh-sftp-server")


def test_all_releases_are_kept_without_a_filter() -> None:
    advisory = UBUNTU.parse(load_record("UBUNTU-CVE-2024-6387"), None)

    assert advisory is not None
    pro = advisory.affected[-1]
    assert (pro.ecosystem, pro.release, pro.fixed) == ("Ubuntu:Pro:18.04:LTS", "18.04", None)


def test_debian_record_is_normalized() -> None:
    advisory = DEBIAN.parse(load_record("DEBIAN-CVE-2024-6387"), SUPPORTED)

    assert advisory is not None
    assert advisory.source == "osv-debian"
    assert advisory.cve_id == "CVE-2024-6387"
    assert advisory.vendor_severity is None
    assert advisory.severity == "high"
    # Debian 14 (forky) is outside the default release list.
    assert [(item.ecosystem, item.release, item.fixed) for item in advisory.affected] == [
        ("Debian:12", "12", "1:9.2p1-2+deb12u3"),
        ("Debian:13", "13", "1:9.7p1-7"),
    ]
    assert advisory.affected[0].binaries == ()


def test_notice_records_are_skipped() -> None:
    notice = osv_record("USN-6859-1", upstream=["CVE-2024-6387"])
    assert UBUNTU.parse(notice, SUPPORTED) is None


def test_records_of_other_distributions_are_skipped() -> None:
    record = osv_record("UBUNTU-CVE-2026-0001", ecosystem="Debian:12")
    assert UBUNTU.parse(record, None) is None


def test_records_without_supported_releases_are_skipped() -> None:
    record = osv_record("UBUNTU-CVE-2026-0001", ecosystem="Ubuntu:16.04:LTS")
    assert UBUNTU.parse(record, SUPPORTED) is None


def test_cve_id_falls_back_to_the_record_id() -> None:
    advisory = UBUNTU.parse(osv_record("UBUNTU-CVE-2026-12345"), SUPPORTED)
    assert advisory is not None
    assert advisory.cve_id == "CVE-2026-12345"


def test_vendor_priority_is_used_without_cvss() -> None:
    record = osv_record("UBUNTU-CVE-2026-0002", severity=[{"type": "Ubuntu", "score": "negligible"}])
    advisory = UBUNTU.parse(record, SUPPORTED)
    assert advisory is not None
    assert (advisory.severity, advisory.cvss_score, advisory.vendor_severity) == ("info", None, "negligible")


def test_cvss_v4_vector_is_kept_without_a_score() -> None:
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    record = osv_record("UBUNTU-CVE-2026-0003", severity=[{"type": "CVSS_V4", "score": vector}])
    advisory = UBUNTU.parse(record, SUPPORTED)
    assert advisory is not None
    assert (advisory.cvss_vector, advisory.cvss_score, advisory.severity) == (vector, None, None)


def test_withdrawn_record_keeps_the_withdrawal_time() -> None:
    record = osv_record("UBUNTU-CVE-2026-0004", withdrawn="2026-05-01T00:00:00Z")
    advisory = UBUNTU.parse(record, SUPPORTED)
    assert advisory is not None
    assert advisory.withdrawn_at == datetime(2026, 5, 1, tzinfo=UTC)


def test_non_ecosystem_ranges_are_ignored() -> None:
    record = osv_record("UBUNTU-CVE-2026-0005")
    record["affected"][0]["ranges"] = [{"type": "GIT", "repo": "https://example.test", "events": [{"introduced": "0"}]}]
    assert UBUNTU.parse(record, SUPPORTED) is None


@pytest.mark.parametrize(
    ("events", "expected"),
    [
        ([{"introduced": "0"}], [(None, None, None)]),
        ([{"introduced": "0"}, {"fixed": "1.2-1"}], [(None, "1.2-1", None)]),
        ([{"introduced": "1.0"}, {"last_affected": "1.4"}], [("1.0", None, "1.4")]),
        (
            [{"introduced": "1.0"}, {"fixed": "1.2"}, {"introduced": "2.0"}, {"fixed": "2.1"}],
            [("1.0", "1.2", None), ("2.0", "2.1", None)],
        ),
        ([{"introduced": "1.0"}, {"introduced": "2.0"}, {"fixed": "2.1"}], [("1.0", None, None), ("2.0", "2.1", None)]),
        ([{"fixed": "1.0"}], []),
        ([{"introduced": "0"}, {"limit": "3.0"}], [(None, None, None)]),
    ],
)
def test_range_events_become_intervals(
    events: list[dict[str, str]], expected: list[tuple[str | None, str | None, str | None]]
) -> None:
    assert _intervals(events) == expected


def test_long_first_sentence_is_shortened() -> None:
    record = osv_record("UBUNTU-CVE-2026-0006", details="word " * 100)
    advisory = UBUNTU.parse(record, SUPPORTED)
    assert advisory is not None
    assert len(advisory.title) == 200 and advisory.title.endswith("…")


def test_summary_is_preferred_as_title() -> None:
    advisory = UBUNTU.parse(osv_record("UBUNTU-CVE-2026-0007", summary="sudo: heap overflow"), SUPPORTED)
    assert advisory is not None and advisory.title == "sudo: heap overflow"
