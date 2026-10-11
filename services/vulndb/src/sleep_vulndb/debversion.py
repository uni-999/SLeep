"""Debian package version comparison (the algorithm of dpkg's verrevcmp).

Debian and Ubuntu versions look like ``[epoch:]upstream[-revision]``, for
example ``1:8.9p1-3ubuntu0.10``. They cannot be compared as strings or as
semantic versions: ``~`` sorts before everything, even the end of the string
(``1.0~rc1 < 1.0``), letters sort before other symbols, and digit runs are
compared numerically.
"""

from functools import total_ordering


class InvalidVersion(ValueError):
    pass


def _order(character: str) -> int:
    if character == "":
        return 0
    if character.isdigit():
        return 0
    if character == "~":
        return -1
    if character.isascii() and character.isalpha():
        return ord(character)
    return ord(character) + 256


def _compare_fragment(left: str, right: str) -> int:
    i = j = 0
    while i < len(left) or j < len(right):
        first_diff = 0
        while (i < len(left) and not left[i].isdigit()) or (j < len(right) and not right[j].isdigit()):
            left_order = _order(left[i] if i < len(left) else "")
            right_order = _order(right[j] if j < len(right) else "")
            if left_order != right_order:
                return left_order - right_order
            i += 1
            j += 1
        while i < len(left) and left[i] == "0":
            i += 1
        while j < len(right) and right[j] == "0":
            j += 1
        while i < len(left) and left[i].isdigit() and j < len(right) and right[j].isdigit():
            if not first_diff:
                first_diff = ord(left[i]) - ord(right[j])
            i += 1
            j += 1
        if i < len(left) and left[i].isdigit():
            return 1
        if j < len(right) and right[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


@total_ordering
class DebianVersion:
    __slots__ = ("epoch", "upstream", "revision", "text")

    def __init__(self, text: str) -> None:
        value = text.strip()
        if not value:
            raise InvalidVersion("empty version")
        epoch = 0
        if ":" in value:
            epoch_text, value = value.split(":", 1)
            if not epoch_text.isdigit():
                raise InvalidVersion(f"invalid epoch in {text!r}")
            epoch = int(epoch_text)
        upstream, revision = value, ""
        if "-" in value:
            upstream, revision = value.rsplit("-", 1)
        if not upstream or not upstream[0].isdigit():
            raise InvalidVersion(f"upstream version must start with a digit: {text!r}")
        self.epoch = epoch
        self.upstream = upstream
        self.revision = revision
        self.text = text

    def _compare(self, other: "DebianVersion") -> int:
        if self.epoch != other.epoch:
            return self.epoch - other.epoch
        result = _compare_fragment(self.upstream, other.upstream)
        if result:
            return result
        return _compare_fragment(self.revision, other.revision)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DebianVersion):
            return NotImplemented
        return self._compare(other) == 0

    def __lt__(self, other: "DebianVersion") -> bool:
        return self._compare(other) < 0

    def __hash__(self) -> int:
        return hash(self.text)

    def __repr__(self) -> str:
        return f"DebianVersion({self.text!r})"


def compare_versions(left: str, right: str) -> int:
    """Return a negative number, zero, or a positive number, like dpkg --compare-versions."""
    return DebianVersion(left)._compare(DebianVersion(right))
