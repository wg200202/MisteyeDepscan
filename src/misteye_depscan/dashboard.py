"""Live TUI dashboard for scan progress (rich-based) with a plain-text fallback.

Layout (matches the requested design):

    +-----------------------------------------------------------+
    |  LOGO            |  Build / Scan Status (stats)            |   header
    +-----------------------------------------------------------+
    |  Scan Targets    |  Scan Progress                         |
    |  (paths /        |  (per-package results stream +         |   body
    |   discovery /    |   progress bar)                        |
    |   completion)    |                                        |
    +-----------------------------------------------------------+
    |  Threats (malicious dependencies discovered)              |   footer
    +-----------------------------------------------------------+

When stdout is not a TTY, or when ``--json`` / ``--sarif`` / ``--quiet`` is
used, or when ``rich`` is unavailable, a plain sequential UI is used instead so
machine-readable output and pipes are never corrupted by ANSI control codes.
"""

from __future__ import annotations

import sys
import time
from collections import deque
from typing import TYPE_CHECKING

from misteye_depscan.banner import MISTEYE_BANNER
from misteye_depscan.models import DetectionResult, ScanStatus
from misteye_depscan.terminal import use_color

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Iterable

# rich is an optional-at-runtime import: if it is missing we degrade gracefully.
try:
    from rich.align import Align
    from rich.console import Console, Group
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    _RICH_AVAILABLE = True
except Exception:  # pragma: no cover - only hit when rich isn't installed
    _RICH_AVAILABLE = False


# ---------------------------------------------------------------------------
# Public factory / capability check
# ---------------------------------------------------------------------------

def dashboard_enabled(*, output_json: bool, output_sarif: bool, quiet: bool) -> bool:
    """Return True when the live dashboard should be used for this invocation.

    The dashboard is a color TUI, so it is only used on an interactive terminal
    where color output is wanted. When the user opted out of color (``--no-color``
    or ``NO_COLOR``) we fall back to the plain sequential UI rather than showing a
    washed-out, color-less dashboard.
    """
    if output_json or output_sarif or quiet:
        return False
    if not _RICH_AVAILABLE:
        return False
    try:
        if not sys.stdout.isatty():
            return False
    except Exception:
        return False
    return use_color()


def create_scan_ui(*, output_json: bool, output_sarif: bool, quiet: bool, title: str) -> "ScanUI":
    """Create the appropriate UI for this invocation (live dashboard or plain)."""
    if dashboard_enabled(output_json=output_json, output_sarif=output_sarif, quiet=quiet):
        try:
            return RichDashboard(title=title)
        except Exception as exc:  # pragma: no cover - defensive fallback
            print(f"[dashboard] falling back to plain output: {exc}", file=sys.stderr)
    return PlainScanUI(quiet=quiet)


# ---------------------------------------------------------------------------
# Base / plain UI
# ---------------------------------------------------------------------------

class ScanUI:
    """Interface used by the CLI to drive scan output.

    Both the live dashboard and the plain fallback implement this so the CLI
    code path is identical regardless of presentation.
    """

    is_live = False

    def __enter__(self) -> "ScanUI":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def set_header(self, **fields: str) -> None:  # noqa: D401 - simple setter
        """Update header metadata (path, ecosystems, depth, mode, ...)."""

    def set_phase(self, phase: str) -> None:
        """Update the current phase label (COLLECT / SCAN / DONE)."""

    def log(self, message: str) -> None:
        """Emit a discovery/runtime log line (left panel / stderr)."""

    def begin_scan(self, total: int) -> None:
        """Signal that per-package scanning is starting with *total* packages."""

    def on_progress(self, completed: int, total: int, result: DetectionResult) -> None:
        """Report one finished package result."""


class PlainScanUI(ScanUI):
    """Sequential stderr output. Reproduces the historical CLI behavior."""

    is_live = False

    def __init__(self, *, quiet: bool = False) -> None:
        self.quiet = quiet

    def log(self, message: str) -> None:
        if not self.quiet:
            print(message, file=sys.stderr)


# ---------------------------------------------------------------------------
# Rich live dashboard
# ---------------------------------------------------------------------------

class RichDashboard(ScanUI):
    """A full-screen, in-place updating dashboard rendered with rich."""

    is_live = True

    def __init__(self, *, title: str = "MistEye DepScan") -> None:
        if not _RICH_AVAILABLE:  # pragma: no cover - guarded by factory
            raise RuntimeError("rich is not available")
        self.title = title
        # Force color output: the dashboard is only created when color is wanted
        # (see ``dashboard_enabled``), so we override rich's auto-detection which
        # can be overly conservative inside tmux / some IDE terminals / when TERM
        # is reported as ``dumb`` -- otherwise foreground colors get stripped and
        # only bold/dim survive.
        self._console = Console(force_terminal=True, color_system="256", no_color=False)
        self._start = time.monotonic()

        self._phase = "COLLECT"
        self._header: dict[str, str] = {}

        # Left panel: discovery / path / completion log lines.
        self._discovery: deque[str] = deque(maxlen=500)
        # Right panel: most-recent per-package results.
        self._results: deque[Text] = deque(maxlen=1000)
        # Footer: malicious findings (lines + their severity for border color).
        self._threats: list[Text] = []
        self._threat_levels: list[str] = []

        self._total = 0
        self._completed = 0
        self._scanned = 0
        self._malicious = 0
        self._unknown = 0
        self._errors = 0

        self._live = Live(
            self,
            console=self._console,
            refresh_per_second=8,
            screen=False,
            transient=False,
        )

    # -- context management -------------------------------------------------
    def __enter__(self) -> "RichDashboard":
        try:
            self._live.start(refresh=True)
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[dashboard] failed to start live view: {exc}", file=sys.stderr)
            raise
        return self

    def __exit__(self, *exc: object) -> None:
        try:
            # Keep the final frame on screen briefly so the result is readable.
            self._live.refresh()
            time.sleep(0.4)
        except Exception as err:  # pragma: no cover - defensive
            print(f"[dashboard] refresh on exit failed: {err}", file=sys.stderr)
        finally:
            try:
                self._live.stop()
            except Exception as err:  # pragma: no cover - defensive
                print(f"[dashboard] failed to stop live view: {err}", file=sys.stderr)

    # -- state updates ------------------------------------------------------
    def set_header(self, **fields: str) -> None:
        for key, value in fields.items():
            if value is not None:
                self._header[key] = str(value)

    def set_phase(self, phase: str) -> None:
        self._phase = phase

    def log(self, message: str) -> None:
        for line in str(message).splitlines() or [""]:
            self._discovery.append(line)

    def begin_scan(self, total: int) -> None:
        self._total = total
        self._completed = 0
        self._phase = "SCAN"

    def on_progress(self, completed: int, total: int, result: DetectionResult) -> None:
        self._completed = completed
        self._total = total
        status = result.status
        if status in (ScanStatus.MALICIOUS, ScanStatus.UNKNOWN):
            self._scanned += 1
        if status == ScanStatus.MALICIOUS:
            self._malicious += 1
        elif status == ScanStatus.UNKNOWN:
            self._unknown += 1
        elif status == ScanStatus.ERROR:
            self._errors += 1

        self._results.append(self._format_result_line(completed, total, result))
        if status == ScanStatus.MALICIOUS:
            self._threats.append(self._format_threat_line(result))
            self._threat_levels.append((self._severity_of(result) or "").lower())
        if completed >= total:
            self._phase = "DONE"

    # -- formatting helpers -------------------------------------------------
    @staticmethod
    def _status_style(status: ScanStatus) -> str:
        return {
            ScanStatus.MALICIOUS: "bold red",
            ScanStatus.UNKNOWN: "green",
            ScanStatus.ERROR: "yellow",
            ScanStatus.NO_CHECK: "yellow",
        }.get(status, "white")

    @staticmethod
    def _severity_style(severity: str | None) -> str:
        """Color by severity: red=critical(严重), yellow=high(高)/medium/low, green=none(无)."""
        sev = (severity or "").strip().lower()
        if sev == "critical":
            return "bold red"
        if sev == "high":
            return "bold yellow"
        if sev in ("medium", "low"):
            return "yellow"
        return "green"

    @staticmethod
    def _status_text(status: ScanStatus) -> str:
        return {
            ScanStatus.MALICIOUS: "Threat detected",
            ScanStatus.UNKNOWN: "No threat record",
            ScanStatus.ERROR: "Check failed",
            ScanStatus.NO_CHECK: "Not checked",
        }.get(status, status.value)

    def _format_result_line(self, completed: int, total: int, result: DetectionResult) -> Text:
        status = result.status
        line = Text()
        line.append(f"[{completed}/{total}] ", style="dim")
        line.append(result.dependency.target, style="white")
        line.append(" -> ")
        label = self._status_text(status)
        if status == ScanStatus.MALICIOUS:
            severity = self._severity_of(result)
            style = self._severity_style(severity)
            if severity:
                label = f"{label} - {severity}"
        elif status == ScanStatus.UNKNOWN:
            style = "green"
        elif status == ScanStatus.ERROR:
            style = "yellow"
            if result.error:
                label = f"{label}: {result.error}"
        else:
            style = self._status_style(status)
        line.append(label, style=style)
        return line

    def _format_threat_line(self, result: DetectionResult) -> Text:
        dep = result.dependency
        severity = self._severity_of(result)
        style = self._severity_style(severity)
        text = Text()
        text.append("! ", style=style)
        text.append(dep.target, style=style)
        if severity:
            text.append(f"  [{severity}]", style=style)
        from pathlib import Path

        text.append(f"  src={Path(dep.source).name}", style="dim")
        return text

    @staticmethod
    def _severity_of(result: DetectionResult) -> str | None:
        if not result.matches:
            return None
        try:
            from misteye_depscan.intel import display_severity

            return display_severity(result.matches[0])
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[dashboard] severity formatting failed: {exc}", file=sys.stderr)
            return None

    def _elapsed(self) -> str:
        secs = int(time.monotonic() - self._start)
        return f"{secs // 60}m {secs % 60}s"

    # -- rendering ----------------------------------------------------------
    def _build_logo(self) -> "Panel":
        logo = Text(MISTEYE_BANNER, style="bold cyan")
        return Panel(Align.left(logo), border_style="cyan", padding=(0, 1))

    def _build_stats(self) -> "Panel":
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold magenta", justify="left")
        grid.add_column(justify="left")

        phase_style = {
            "COLLECT": "yellow",
            "SCAN": "bold cyan",
            "DONE": "bold green",
        }.get(self._phase, "white")
        grid.add_row("Phase", Text(self._phase, style=phase_style))
        grid.add_row("Elapsed", Text(self._elapsed(), style="white"))
        for key in ("Mode", "Target", "Ecosystems", "Depth"):
            if key in self._header:
                grid.add_row(key, Text(self._header[key], style="white"))

        counters = Table.grid(padding=(0, 2))
        for _ in range(4):
            counters.add_column(justify="left")
        threat_style = self._threat_border_style() if self._malicious else "dim"
        counters.add_row(
            Text(f"OK {self._unknown}", style="green"),
            Text(f"Threat {self._malicious}", style=threat_style),
            Text(f"Scanned {self._completed}/{self._total}", style="cyan"),
            Text(f"Err {self._errors}", style="yellow" if self._errors else "dim"),
        )

        legend = Text()
        legend.append("critical", style="bold red")
        legend.append(" / ", style="dim")
        legend.append("high", style="bold yellow")
        legend.append(" / ", style="dim")
        legend.append("none", style="green")

        body = Group(grid, Text(""), counters, legend)
        return Panel(body, title="Scan Status", border_style="magenta", padding=(0, 1))

    def _build_left(self, height: int) -> "Panel":
        lines = list(self._discovery)[-max(1, height):]
        body = Text("\n".join(lines) if lines else "Waiting...", style="white")
        return Panel(body, title="Scan Targets / Discovery", border_style="green", padding=(0, 1))

    def _progress_bar(self, width: int = 30) -> Text:
        total = self._total or 0
        done = self._completed
        ratio = (done / total) if total else 0.0
        filled = int(ratio * width)
        bar = Text()
        bar.append("[")
        bar.append("#" * filled, style="cyan")
        bar.append("-" * (width - filled), style="dim")
        bar.append("] ")
        bar.append(f"{done}/{total} ", style="bold cyan")
        bar.append(f"({int(ratio * 100)}%)", style="dim")
        return bar

    def _build_right(self, height: int) -> "Panel":
        body_lines = max(1, height - 2)  # leave room for the progress bar
        recent: Iterable[Text] = list(self._results)[-body_lines:]
        group_items: list = [self._progress_bar(), Text("")]
        group_items.extend(recent if recent else [Text("Waiting...", style="dim")])
        return Panel(
            Group(*group_items),
            title="Scan Progress",
            border_style="cyan",
            padding=(0, 1),
        )

    def _threat_border_style(self) -> str:
        """Border reflects the most severe finding: red>critical, yellow>high/med/low, green>none."""
        levels = set(self._threat_levels)
        if "critical" in levels:
            return "red"
        if levels & {"high", "medium", "low"}:
            return "yellow"
        if self._threats:  # malicious but severity unknown
            return "red"
        return "green"

    def _build_footer(self, height: int) -> "Panel":
        lines = self._threats[-max(1, height):]
        if lines:
            body = Group(*lines)
            border = self._threat_border_style()
        else:
            body = Text("No threats detected yet.", style="dim green")
            border = "green"
        title = f"Threats ({self._malicious})"
        return Panel(body, title=title, border_style=border, padding=(0, 1))

    def __rich_console__(self, console: "Console", options):  # noqa: ANN001 - rich protocol
        total_height = console.size.height
        header_size = 11
        footer_size = 8
        body_height = max(6, total_height - header_size - footer_size)
        panel_inner = max(3, body_height - 2)

        # The ASCII logo is ~52 columns wide; give it a fixed region (when the
        # terminal is wide enough) so it is not truncated, and let the stats
        # panel take the remaining width.
        logo_width = 54
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=header_size),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=footer_size),
        )
        if console.size.width >= logo_width + 30:
            layout["header"].split_row(
                Layout(self._build_logo(), name="logo", size=logo_width),
                Layout(self._build_stats(), name="stats", ratio=1),
            )
        else:
            layout["header"].split_row(
                Layout(self._build_logo(), name="logo", ratio=2),
                Layout(self._build_stats(), name="stats", ratio=3),
            )
        layout["body"].split_row(
            Layout(self._build_left(panel_inner), name="left", ratio=1),
            Layout(self._build_right(panel_inner), name="right", ratio=1),
        )
        layout["footer"].update(self._build_footer(footer_size - 2))
        yield layout
