import pytest

from sleep_vulndb.debversion import DebianVersion, InvalidVersion, compare_versions


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("1.0", "1.0", 0),
        ("1.0", "1.0-0", 0),
        ("0:1.0", "1.0", 0),
        ("1.2.3", "1.2.10", -1),
        ("1.0~rc1", "1.0", -1),
        ("1.0~~", "1.0~", -1),
        ("1.0~rc1", "1.0~rc2", -1),
        ("1.0a", "1.0", 1),
        ("1.0+b1", "1.0", 1),
        ("1.0+dfsg", "1.0a", 1),
        ("1:1.0", "2.0", 1),
        ("2.0", "10.0", -1),
        ("1.0-1", "1.0-1ubuntu1", -1),
        ("1:8.9p1-3ubuntu0.6", "1:8.9p1-3ubuntu0.10", -1),
        ("1:9.2p1-2+deb12u2", "1:9.2p1-2+deb12u3", -1),
        ("2.35-0ubuntu3.8", "2.35-0ubuntu3.10", -1),
        ("1.2-3", "1.2-3.1", -1),
        ("7.81.0-1ubuntu1.16", "7.81.0-1ubuntu1.4", 1),
    ],
)
def test_compare_versions_matches_dpkg(left: str, right: str, expected: int) -> None:
    result = compare_versions(left, right)
    assert (result > 0) - (result < 0) == expected
    reverse = compare_versions(right, left)
    assert (reverse > 0) - (reverse < 0) == -expected


def test_versions_sort_like_dpkg() -> None:
    versions = ["1.0", "1.0~beta", "1:0.9", "1.0-1", "1.0+b1", "0.9"]
    ordered = sorted(versions, key=DebianVersion)
    assert ordered == ["0.9", "1.0~beta", "1.0", "1.0-1", "1.0+b1", "1:0.9"]


@pytest.mark.parametrize("text", ["", "   ", "abc", "x:1.0", "1:"])
def test_invalid_versions_are_rejected(text: str) -> None:
    with pytest.raises(InvalidVersion):
        DebianVersion(text)
