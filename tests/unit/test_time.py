"""Unit tests for app.core.time."""

from datetime import timezone

from app.core.time import utc_now


def test_utc_now_is_timezone_aware():
    """utc_now() must never return a naive datetime — naive/aware mismatches
    are a common source of silent comparison bugs."""
    result = utc_now()
    assert result.tzinfo is not None


def test_utc_now_is_utc():
    """utc_now() must specifically be UTC, not local time."""
    result = utc_now()
    assert result.tzinfo == timezone.utc


def test_utc_now_increases_monotonically():
    """Two consecutive calls should be ordered (basic sanity check)."""
    first = utc_now()
    second = utc_now()
    assert second >= first
