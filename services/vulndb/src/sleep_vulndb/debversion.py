"""Debian package version comparison (the algorithm of dpkg's verrevcmp).

Debian and Ubuntu versions look like ``[epoch:]upstream[-revision]``, for
example ``1:8.9p1-3ubuntu0.10``. They cannot be compared as strings or as
semantic versions: ``~`` sorts before everything, even the end of the string
(``1.0~rc1 < 1.0``), letters sort before other symbols, and digit runs are
compared numerically.

Versions are validated like dpkg validates them: whatever dpkg reports as bad
syntax, as an error or a warning, is rejected.
"""

import re
from functools import total_ordering


class InvalidVersion(ValueError):
    pass


# Debian Policy 5.6.12 and dpkg's parseversion(); ASCII only.
_EPOCH = re.compile(r"[0-9]+")
_UPSTREAM = re.compile(r"[0-9][A-Za-z0-9.+~:-]*")
_REVISION = re.compile(r"[A-Za-z0-9.+~]+")
_MAX_EPOCH = 2**31 - 1


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
        if any(character.isspace() for character in value):
            raise InvalidVersion(f"embedded spaces in {text!r}")
        epoch = 0
        if ":" in value:
            epoch_text, value = value.split(":", 1)
            if not _EPOCH.fullmatch(epoch_text) or int(epoch_text) > _MAX_EPOCH:
                raise InvalidVersion(f"invalid epoch in {text!r}")
            epoch = int(epoch_text)
        upstream, revision = value, ""
        if "-" in value:
            upstream, revision = value.rsplit("-", 1)
            if not _REVISION.fullmatch(revision):
                raise InvalidVersion(f"invalid revision in {text!r}")
        if not _UPSTREAM.fullmatch(upstream):
            raise InvalidVersion(
                f"invalid upstream version in {text!r}: it must start with a digit and contain only "
                "letters, digits and . + ~ - :"
            )
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

    # Equal versions can be spelled differently ("1.0", "0:1.0", "1.0-0"), so
    # a hash of the text would break the hash/eq contract. Versions are only
    # compared, never used as keys: keep them unhashable.
    __hash__ = None  # type: ignore[assignment]

    def __repr__(self) -> str:
        return f"DebianVersion({self.text!r})"
