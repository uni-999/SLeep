import re
from datetime import UTC, date, datetime


_FRACTION = re.compile(r"\.(\d+)")


def parse_timestamp(value: str) -> datetime:
    """Parse an RFC 3339 timestamp. OSV uses up to nanosecond precision, which
    Python's datetime cannot hold, so the fraction is cut to microseconds."""
    text = value.strip().replace("Z", "+00:00").replace("z", "+00:00")
    text = _FRACTION.sub(lambda match: "." + match.group(1)[:6].ljust(6, "0"), text, count=1)
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def parse_optional_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return parse_timestamp(value)


def parse_date(value: object) -> date | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return date.fromisoformat(value.strip()[:10])


def as_utc(value: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; treat them as UTC."""
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
