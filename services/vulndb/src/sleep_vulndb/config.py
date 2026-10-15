"""Runtime settings, read from SLEEP_VULNDB_* environment variables."""

import os
from dataclasses import dataclass, field

from . import __version__


KNOWN_SOURCES = ("osv-debian", "osv-ubuntu", "epss", "kev")

# Supported Debian and Ubuntu LTS releases. Records for other releases are
# skipped, which keeps the knowledge base small. "*" keeps every release.
DEFAULT_OSV_ECOSYSTEMS = (
    "Debian:11",
    "Debian:12",
    "Debian:13",
    "Ubuntu:20.04:LTS",
    "Ubuntu:22.04:LTS",
    "Ubuntu:24.04:LTS",
)

DEFAULT_INTERVAL_MINUTES = {
    "osv-debian": 60,
    "osv-ubuntu": 60,
    # EPSS publishes one file per day; KEV changes a few times per week.
    "epss": 24 * 60,
    "kev": 6 * 60,
}

USER_AGENT = f"SLeep-vulndb/{__version__} (+https://github.com/uni-999/SLeep)"


class ConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class Settings:
    sources: tuple[str, ...] = KNOWN_SOURCES
    osv_base_url: str = "https://osv-vulnerabilities.storage.googleapis.com"
    # None means "every Debian and Ubuntu release".
    osv_ecosystems: frozenset[str] | None = frozenset(DEFAULT_OSV_ECOSYSTEMS)
    # More changed records than this since the last cursor -> full download.
    osv_incremental_limit: int = 2000
    # A full download also runs at least this often to repair any drift.
    osv_full_sync_days: int = 7
    # A full replacement of a source must keep at least this share of its
    # current records, otherwise the run fails and the data stays (0 disables).
    min_full_sync_ratio: float = 0.5
    epss_url: str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    interval_minutes: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_INTERVAL_MINUTES))
    retry_minutes: int = 15
    # A single run longer than this marks the container unhealthy (a hung sync).
    # The first full OSV download is the longest run; keep a wide margin.
    max_sync_minutes: int = 120
    # Finished sync_runs entries older than this are deleted. Feed freshness
    # lives in feed_state, so the journal only needs recent history.
    run_retention_days: int = 90
    http_timeout_seconds: float = 60.0
    http_retries: int = 3
    http_backoff_seconds: float = 2.0
    max_download_bytes: int = 2 * 1024**3
    proxy_url: str | None = None
    heartbeat_path: str = "/tmp/sleep-vulndb.heartbeat"
    tick_seconds: int = 60

    @classmethod
    def from_env(cls) -> "Settings":
        defaults = cls()
        intervals = dict(DEFAULT_INTERVAL_MINUTES)
        for source in KNOWN_SOURCES:
            variable = f"SLEEP_VULNDB_{source.upper().replace('-', '_')}_INTERVAL_MINUTES"
            intervals[source] = _positive_int(variable, intervals[source])

        return cls(
            sources=parse_sources(os.getenv("SLEEP_VULNDB_SOURCES", "")),
            osv_base_url=_text("SLEEP_VULNDB_OSV_BASE_URL", defaults.osv_base_url).rstrip("/"),
            osv_ecosystems=parse_ecosystems(os.getenv("SLEEP_VULNDB_OSV_ECOSYSTEMS", "")),
            osv_incremental_limit=_positive_int("SLEEP_VULNDB_OSV_INCREMENTAL_LIMIT", defaults.osv_incremental_limit),
            osv_full_sync_days=_positive_int("SLEEP_VULNDB_OSV_FULL_SYNC_DAYS", defaults.osv_full_sync_days),
            min_full_sync_ratio=_ratio("SLEEP_VULNDB_MIN_FULL_SYNC_RATIO", defaults.min_full_sync_ratio),
            epss_url=_text("SLEEP_VULNDB_EPSS_URL", defaults.epss_url),
            kev_url=_text("SLEEP_VULNDB_KEV_URL", defaults.kev_url),
            interval_minutes=intervals,
            retry_minutes=_positive_int("SLEEP_VULNDB_RETRY_MINUTES", defaults.retry_minutes),
            max_sync_minutes=_positive_int("SLEEP_VULNDB_MAX_SYNC_MINUTES", defaults.max_sync_minutes),
            run_retention_days=_positive_int("SLEEP_VULNDB_RUN_RETENTION_DAYS", defaults.run_retention_days),
            http_timeout_seconds=float(_positive_int("SLEEP_VULNDB_HTTP_TIMEOUT_SECONDS", 60)),
            proxy_url=os.getenv("SLEEP_VULNDB_PROXY_URL") or None,
            heartbeat_path=_text("SLEEP_VULNDB_HEARTBEAT_PATH", defaults.heartbeat_path),
        )


def parse_sources(value: str) -> tuple[str, ...]:
    """Parse a comma-separated source list. Empty means all, "none" means none."""
    value = value.strip()
    if not value:
        return KNOWN_SOURCES
    if value.lower() == "none":
        return ()
    sources = tuple(dict.fromkeys(item.strip() for item in value.split(",") if item.strip()))
    unknown = [source for source in sources if source not in KNOWN_SOURCES]
    if unknown:
        raise ConfigurationError(
            f"Unknown source(s): {', '.join(unknown)}. Known sources: {', '.join(KNOWN_SOURCES)}"
        )
    return sources


def parse_ecosystems(value: str) -> frozenset[str] | None:
    value = value.strip()
    if not value:
        return frozenset(DEFAULT_OSV_ECOSYSTEMS)
    if value == "*":
        return None
    return frozenset(item.strip() for item in value.split(",") if item.strip())


def _text(variable: str, default: str) -> str:
    return os.getenv(variable) or default


def _ratio(variable: str, default: float) -> float:
    raw = os.getenv(variable)
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as error:
        raise ConfigurationError(f"{variable} must be a number from 0 to 1, got {raw!r}") from error
    if not 0 <= value <= 1:
        raise ConfigurationError(f"{variable} must be from 0 to 1, got {value}")
    return value


def _positive_int(variable: str, default: int) -> int:
    raw = os.getenv(variable)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as error:
        raise ConfigurationError(f"{variable} must be an integer, got {raw!r}") from error
    if value <= 0:
        raise ConfigurationError(f"{variable} must be positive, got {value}")
    return value
