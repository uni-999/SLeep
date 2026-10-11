from .base import FeedDataError, FeedSource, SyncContext, SyncMode, SyncOutcome, SyncStatus
from .epss import EpssSource
from .kev import KevSource
from .osv import OSV_SOURCES


SOURCES: dict[str, FeedSource] = {
    **OSV_SOURCES,
    "epss": EpssSource(),
    "kev": KevSource(),
}

__all__ = ["SOURCES", "FeedDataError", "FeedSource", "SyncContext", "SyncMode", "SyncOutcome", "SyncStatus"]
