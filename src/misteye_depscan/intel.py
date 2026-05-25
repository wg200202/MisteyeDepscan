"""MistEye match metadata helpers (severity display, intel age, expiry)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

# Treat intel older than this as stale (~3 months).
STALE_INTEL_DAYS = 90

STALE_INTEL_HINT = "Intel older than 3 months (shown as high, not critical)"
EXPIRED_INTEL_HINT = "Intel expired (shown as high, not critical)"

_FIRST_SEEN_KEYS = (
    "first_seen_utc",
    "first_seen",
    "first_seen_at",
    "discovered_at",
    "discovered_time",
    "discovery_time",
    "found_at",
    "reported_at",
    "created_at",
    "detected_at",
)

_LAST_SEEN_KEYS = ("last_seen_utc", "last_seen", "last_seen_at", "updated_at")

_EXPIRED_KEYS = ("expired_at", "expired_at_utc", "expires_at")


def parse_first_seen(match: dict) -> datetime | None:
    return _parse_time_from_keys(match, _FIRST_SEEN_KEYS)


def parse_last_seen(match: dict) -> datetime | None:
    return _parse_time_from_keys(match, _LAST_SEEN_KEYS)


def parse_expired_at(match: dict) -> datetime | None:
    return _parse_time_from_keys(match, _EXPIRED_KEYS)


def is_intel_expired(match: dict) -> bool:
    if match.get("is_expired") is True:
        return True
    expired = parse_expired_at(match)
    if expired is None:
        return False
    if expired.tzinfo is None:
        expired = expired.replace(tzinfo=timezone.utc)
    return expired < datetime.now(timezone.utc)


def is_stale_intel(match: dict, *, stale_days: int = STALE_INTEL_DAYS) -> bool:
    if is_intel_expired(match):
        return True
    discovered = parse_first_seen(match)
    if discovered is None:
        return False
    if discovered.tzinfo is None:
        discovered = discovered.replace(tzinfo=timezone.utc)
    cutoff = datetime.now(timezone.utc) - timedelta(days=stale_days)
    return discovered < cutoff


def display_severity(match: dict) -> str:
    """
    Severity label for CLI output.

    API ``critical`` hits that are expired or older than three months are shown
    as ``high`` so stale intel does not look like an active critical incident.
    """
    raw = str(match.get("severity") or "").strip().lower()
    if not raw:
        return "unknown"
    if raw == "critical" and is_stale_intel(match):
        return "high"
    return raw


def stale_intel_hint(match: dict) -> str | None:
    if is_intel_expired(match):
        return EXPIRED_INTEL_HINT
    if is_stale_intel(match):
        return STALE_INTEL_HINT
    return None


def parse_match_time(match: dict) -> datetime | None:
    """Backward-compatible alias for first-seen time."""
    return parse_first_seen(match)


def _parse_time_from_keys(match: dict, keys: tuple[str, ...]) -> datetime | None:
    for key in keys:
        if key not in match:
            continue
        parsed = _parse_datetime_value(match.get(key))
        if parsed is not None:
            return parsed
    return None


def _parse_datetime_value(value: object) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        pass
    if "/" in text:
        parts = text.split("/")
        if len(parts) == 3:
            try:
                year, month, day = (int(parts[0]), int(parts[1]), int(parts[2]))
                return datetime(year, month, day, tzinfo=timezone.utc)
            except ValueError:
                pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None
