import pytest

from sleep_vulndb.debversion import DebianVersion, InvalidVersion


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
def test_comparison_matches_dpkg(left: str, right: str, expected: int) -> None:
    first, second = DebianVersion(left), DebianVersion(right)
    assert ((first > second) - (first < second), (second > first) - (second < first)) == (expected, -expected)
    assert (first == second) is (expected == 0)


def test_versions_sort_like_dpkg() -> None:
    versions = ["1.0", "1.0~beta", "1:0.9", "1.0-1", "1.0+b1", "0.9"]
    ordered = sorted(versions, key=DebianVersion)
    assert ordered == ["0.9", "1.0~beta", "1.0", "1.0-1", "1.0+b1", "1:0.9"]


@pytest.mark.parametrize(
    "text",
    [
        "",
        "   ",
        "abc",  # must start with a digit
        "x:1.0",  # epoch is not a number
        ":1.0",  # empty epoch
        "99999999999:1.0",  # epoch too big
        "1:",  # nothing after the epoch
        "1.0-",  # empty revision
        "1.0 2",  # embedded space
        "1.0_1",  # "_" is not allowed in the upstream version
        "1.0-a_b",  # nor in the revision
        "1.0-1:2",  # ":" is not allowed in the revision
        "1.0²",  # only ASCII digits
    ],
)
def test_invalid_versions_are_rejected(text: str) -> None:
    with pytest.raises(InvalidVersion):
        DebianVersion(text)


@pytest.mark.parametrize("text", ["1:2:3", "1.0--1", "1.0-+", " 1.0 ", "1.0~-1"])
def test_unusual_versions_accepted_by_dpkg_are_valid(text: str) -> None:
    DebianVersion(text)


def test_versions_are_not_hashable() -> None:
    # "1.0", "0:1.0" and "1.0-0" are equal, so hashing the text would put
    # equal versions into different buckets.
    assert DebianVersion("1.0") == DebianVersion("0:1.0") == DebianVersion("1.0-0")
    with pytest.raises(TypeError):
        hash(DebianVersion("1.0"))
