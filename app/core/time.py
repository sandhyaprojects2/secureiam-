"""
Centralized timestamp helper.

Every timestamp generated or compared anywhere in the codebase — token
expiry, issued_at, revoked_at, created_at — must go through `utc_now()`.

Never call `datetime.utcnow()` (naive, deprecated) or `datetime.now()`
(local time, ambiguous) directly elsewhere in this codebase. Mixing naive
and timezone-aware datetimes is a common source of subtle comparison bugs
that usually only surface once real data crosses a timezone boundary.
"""

from datetime import datetime, timezone


def utc_now() -> datetime:
    """Returns the current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)
