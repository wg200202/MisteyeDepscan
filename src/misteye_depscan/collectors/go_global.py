"""Collect dependencies from ``go install`` binaries via ``go version -m``."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from misteye_depscan.collectors.base import GlobalCollector, run_command
from misteye_depscan.models import DependencyItem, PackageType

logger = logging.getLogger(__name__)

# Common locations when ``go env GOBIN`` is empty.
_FALLBACK_BIN_DIRS = (
    Path.home() / "go" / "bin",
    Path("/usr/local/go/bin"),
)


def _go_env() -> dict[str, str]:
    result = run_command(["go", "env", "-json"])
    if result is None or result.returncode != 0:
        return {}
    try:
        data = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        logger.warning("Failed to parse go env -json: %s", exc)
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(key): str(value) for key, value in data.items()}


def discover_go_bin_dirs() -> list[Path]:
    """Resolve directories that contain ``go install`` binaries."""
    env = _go_env()
    dirs: list[Path] = []
    seen: set[str] = set()

    def add(directory: Path) -> None:
        path = directory.expanduser()
        if not path.is_dir():
            return
        key = str(path.resolve())
        if key in seen:
            return
        seen.add(key)
        dirs.append(path)

    gobin = env.get("GOBIN", "").strip()
    gopath = env.get("GOPATH", "").strip()
    if gobin:
        add(Path(gobin))
    if gopath:
        add(Path(gopath) / "bin")
    for fallback in _FALLBACK_BIN_DIRS:
        add(fallback)
    return dirs


def _iter_binaries(bin_dir: Path) -> list[Path]:
    """List executable entries (regular files or symlinks, not subdirectories)."""
    binaries: list[Path] = []
    try:
        entries = list(bin_dir.iterdir())
    except OSError as exc:
        logger.warning("Failed to read Go bin dir %s: %s", bin_dir, exc)
        return binaries
    for path in entries:
        if path.name.startswith("."):
            continue
        if path.is_dir():
            continue
        if path.is_file() or path.is_symlink():
            binaries.append(path)
    return binaries


def parse_go_version_m_output(text: str, *, source: str, evidence: str) -> list[DependencyItem]:
    """Parse ``go version -m`` output (``mod`` / ``dep`` lines)."""
    items: list[DependencyItem] = []
    seen: set[tuple[str, str | None]] = set()
    for line in text.splitlines():
        # ``go version -m`` uses leading tabs: ``\\tmod\\tmodule\\tversion\\t...``
        if not line.startswith("\t"):
            continue
        parts = [part for part in line.split("\t") if part]
        if len(parts) < 3 or parts[0] not in {"mod", "dep"}:
            continue
        name = parts[1].strip()
        version = parts[2].strip().split()[0] if parts[2].strip() else None
        if not name or name.startswith("cmd/"):
            continue
        key = (name.lower(), version)
        if key in seen:
            continue
        seen.add(key)
        items.append(
            DependencyItem(
                name=name,
                version=version,
                package_type=PackageType.GO.value,
                source=source,
                evidence=evidence,
                raw=f"{name}@{version}" if version else name,
            )
        )
    return items


def collect_go_install_global() -> tuple[list[DependencyItem], list[str]]:
    """Scan ``GOBIN`` / ``GOPATH/bin`` executables installed via ``go install``."""
    bin_dirs = discover_go_bin_dirs()
    if not bin_dirs:
        return [], ["go install scan skipped: could not resolve Go bin directories."]

    items: list[DependencyItem] = []
    warnings: list[str] = []
    seen_bins: set[str] = set()
    scanned_bins = 0
    failed_bins = 0
    empty_bins = 0

    for bin_dir in bin_dirs:
        for binary in _iter_binaries(bin_dir):
            try:
                resolved = str(binary.resolve())
            except OSError as exc:
                logger.warning("Failed to resolve %s: %s", binary, exc)
                failed_bins += 1
                continue
            if resolved in seen_bins:
                continue
            seen_bins.add(resolved)
            scanned_bins += 1

            result = run_command(["go", "version", "-m", resolved], timeout=60.0)
            if result is None or result.returncode != 0:
                failed_bins += 1
                stderr = (result.stderr or "").strip() if result else "go not found"
                logger.warning("go version -m failed for %s: %s", binary.name, stderr)
                continue
            parsed = parse_go_version_m_output(
                result.stdout or "",
                source="go-global",
                evidence=f"go version -m {binary.name}",
            )
            if parsed:
                items.extend(parsed)
            else:
                empty_bins += 1

    if scanned_bins and not items:
        warnings.append(
            f"go-global: scanned {scanned_bins} binaries in {len(bin_dirs)} dir(s) "
            "but found no module metadata (go version -m)."
        )
    elif failed_bins:
        warnings.append(f"go-global: {failed_bins} binary(s) could not be inspected.")
    if not items:
        warnings.append("No packages found via go-global.")
    return items, warnings


class GoInstallCollector(GlobalCollector):
    """Dependencies from globally installed Go binaries (``go install``)."""

    name = "go-global"

    def collect(self) -> list[DependencyItem]:
        items, _warnings = collect_go_install_global()
        return items
