from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from sqlalchemy.orm import Session

from ..config import Settings
from ..db_models import FeedStateRecord
from ..http import FeedHttp


class SyncMode(StrEnum):
    FULL = "full"
    INCREMENTAL = "incremental"


class SyncStatus(StrEnum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    NOT_MODIFIED = "not_modified"
    FAILED = "failed"


class FeedDataError(ValueError):
    """The downloaded feed is malformed or implausible; existing data is kept."""


@dataclass
class SyncContext:
    session: Session
    http: FeedHttp
    settings: Settings
    state: FeedStateRecord
    now: datetime
    force_full: bool = False
    # Accept a full replacement that is much smaller than the current data
    # (see ensure_plausible_size). Only an operator sets it, never the scheduler.
    allow_shrink: bool = False


def ensure_plausible_size(context: SyncContext, source: str, previous: int, current: int) -> None:
    """Refuse a full replacement that would drop most of the existing records.

    A truncated or half-published feed is still well-formed, so parsing alone
    does not catch it. Accepting it would silently remove knowledge, and CVE
    matching would then close the findings of every device at once.
    """
    ratio = context.settings.min_full_sync_ratio
    if context.allow_shrink or previous == 0 or current >= previous * ratio:
        return
    raise FeedDataError(
        f"{source}: the new data has {current} records, the knowledge base has {previous}; "
        f"refusing to replace it with less than {ratio:.0%} of that. If the drop is expected, "
        f"run: sleep-vulndb sync --source {source} --allow-shrink"
    )


@dataclass(frozen=True)
class SyncOutcome:
    mode: SyncMode
    status: SyncStatus  # SUCCEEDED or NOT_MODIFIED
    written: int = 0
    deleted: int = 0


class FeedSource(Protocol):
    name: str

    def sync(self, context: SyncContext) -> SyncOutcome:
        """Apply the feed to the session. Must not commit: the caller commits data,
        state, and the run journal entry in one transaction."""
        ...
