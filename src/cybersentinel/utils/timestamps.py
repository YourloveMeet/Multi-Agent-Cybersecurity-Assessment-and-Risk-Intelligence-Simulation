"""Timestamp utilities for consistent logging and reporting."""

from datetime import datetime, timezone


def utc_now() -> datetime:
    """Return current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def format_iso(dt: datetime | None = None) -> str:
    """Format datetime as ISO 8601 string."""
    target_dt = dt or utc_now()
    return target_dt.isoformat()


def format_time_hms(dt: datetime | None = None) -> str:
    """Format time as HH:MM:SS for terminal log lines."""
    target_dt = dt or datetime.now()
    return target_dt.strftime("%H:%M:%S")
