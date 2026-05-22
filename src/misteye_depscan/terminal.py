"""Terminal labels and ANSI colors (stdlib only, no rich dependency)."""

from __future__ import annotations

import itertools
import os
import sys
import threading
from typing import Callable, TextIO, TypeVar

from misteye_depscan.models import ScanStatus

T = TypeVar("T")

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


class IndeterminateProgress:
    """Animated spinner on stderr while a long-running task runs (always on)."""

    _FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")

    def __init__(
        self,
        message: str = "Scanning...",
        *,
        stream: TextIO | None = None,
    ) -> None:
        self.message = message
        self._stream = stream or sys.stderr
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> IndeterminateProgress:
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        self._stream.write("\r\033[K\n")
        self._stream.flush()

    def _spin(self) -> None:
        for frame in itertools.cycle(self._FRAMES):
            if self._stop.is_set():
                break
            prefix = colorize(frame, CYAN) if use_color() else frame
            self._stream.write(f"\r{prefix} {self.message}")
            self._stream.flush()
            self._stop.wait(0.12)


def run_with_progress(
    fn: Callable[[], T],
    message: str = "Scanning...",
) -> T:
    """Run *fn* with a spinner on stderr (always shown during dependency collection)."""
    with IndeterminateProgress(message):
        return fn()
