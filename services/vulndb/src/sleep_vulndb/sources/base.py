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
