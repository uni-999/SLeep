import pytest

from sleep_vulndb.cvss import InvalidVector, base_score, severity_from_score


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        # CVE-2024-6387 (regreSSHion)
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
        # CVE-2021-44228 (Log4Shell)
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        # Typical reflected XSS
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        # CVE-2021-3156 (sudo Baron Samedit)
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        # Temporal metrics are ignored by the base score.
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O", 8.1),
    ],
)
def test_base_score(vector: str, score: float) -> None:
    assert base_score(vector) == score


@pytest.mark.parametrize(
    "vector",
    [
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ],
)
def test_invalid_vectors(vector: str) -> None:
    with pytest.raises(InvalidVector):
        base_score(vector)


@pytest.mark.parametrize(
    ("score", "severity"),
    [(10.0, "critical"), (9.0, "critical"), (8.9, "high"), (7.0, "high"), (6.9, "medium"),
     (4.0, "medium"), (3.9, "low"), (0.1, "low"), (0.0, "info")],
)
def test_severity_bands(score: float, severity: str) -> None:
    assert severity_from_score(score) == severity
