"""Terminal labels and ANSI colors (stdlib only, no rich dependency)."""

from __future__ import annotations

import os
import sys

from misteye_depscan.models import ScanStatus

RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
DIM = "\033[2m"
BOLD = "\033[1m"

# User-facing labels (API still returns status=unknown; we do not show "unknown" in CLI)
STATUS_LABELS: dict[ScanStatus, str] = {
    ScanStatus.MALICIOUS: "Threat detected",
    ScanStatus.UNKNOWN: "No threat record",
    ScanStatus.ERROR: "Check failed",
    ScanStatus.NO_CHECK: "Not checked",
}

STATUS_COLORS: dict[ScanStatus, str] = {
    ScanStatus.MALICIOUS: RED,
    ScanStatus.UNKNOWN: GREEN,
    ScanStatus.ERROR: YELLOW,
    ScanStatus.NO_CHECK: YELLOW,
}

_color_enabled: bool | None = None


def set_color_enabled(enabled: bool) -> None:
    global _color_enabled
    _color_enabled = enabled


def use_color() -> bool:
    if _color_enabled is False:
        return False
    if _color_enabled is True:
        return True
    if os.environ.get("NO_COLOR", "").strip():
        return False
    if os.environ.get("FORCE_COLOR", "").strip():
        return True
    return sys.stdout.isatty()


def colorize(text: str, color: str) -> str:
    if not use_color():
        return text
    return f"{color}{text}{RESET}"


def status_label(status: ScanStatus) -> str:
    return STATUS_LABELS.get(status, status.value)


def format_status(status: ScanStatus, *, bold: bool = False) -> str:
    label = status_label(status)
    color = STATUS_COLORS.get(status, "")
    if bold:
        label = f"{BOLD}{label}{RESET}" if use_color() else label
    return colorize(label, color) if color else label


def format_progress_result(
    status: ScanStatus,
    *,
    severity: str | None = None,
    error: str | None = None,
) -> str:
    if status == ScanStatus.MALICIOUS:
        label = status_label(status)
        if severity:
            label = f"{label} · {severity}"
        return colorize(label, RED) if use_color() else label
    if status == ScanStatus.ERROR and error:
        msg = f"{status_label(status)}: {error}"
        return colorize(msg, YELLOW) if use_color() else msg
    return format_status(status)


def format_summary_value(label: str, value: int, color: str) -> str:
    text = f"{label}: {value}"
    return colorize(text, color) if value > 0 else text


def hyperlink(url: str, text: str) -> str:
    """Wrap *text* in an OSC 8 terminal hyperlink if color/escape is enabled."""
    if not use_color():
        return text
    return f"\033]8;;{url}\033\\{text}\033]8;;\033\\"
