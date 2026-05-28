"""Collect dependencies from ``cargo install`` global binaries."""

from __future__ import annotations

import logging
import os
import re
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

from misteye_depscan.collectors.base import GlobalCollector, run_command
from misteye_depscan.models import DependencyItem, PackageType
from misteye_depscan.parsers.others import RustParser

logger = logging.getLogger(__name__)

_INSTALL_HEADER = re.compile(
    r"^(\S+)\s+v(\S+)(?:\s+\(([^)]+)\))?:\s*$"
)

_RUST_PARSER = RustParser()


@dataclass(frozen=True)
class InstalledCrate:
    name: str
    version: str
    source_detail: str | None = None

    @property
    def source_kind(self) -> str:
        if not self.source_detail:
            # ``cargo install --list`` omits ``(registry+...)`` for crates.io installs.
            return "registry"
        detail = self.source_detail.lower()
        if detail.startswith("registry+"):
            return "registry"
        if detail.startswith("git+"):
            return "git"
        if detail.startswith("path+"):
            return "path"
        if detail.startswith("http://") or detail.startswith("https://"):
            return "git"
        return "registry"


def cargo_home() -> Path:
    return Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))).expanduser()


def parse_cargo_install_list(text: str) -> list[InstalledCrate]:
    """Parse ``cargo install --list`` stdout into installed crate records."""
    items: list[InstalledCrate] = []
    for line in text.splitlines():
        match = _INSTALL_HEADER.match(line.strip())
        if not match:
            continue
        name, version, source_detail = match.group(1), match.group(2), match.group(3)
        items.append(
            InstalledCrate(
                name=name,
                version=version,
                source_detail=source_detail.strip() if source_detail else None,
            )
        )
    return items


def find_lock_in_registry_src(home: Path, name: str, version: str) -> Path | None:
    """Return ``Cargo.lock`` under ``registry/src`` for an installed registry crate."""
    src_root = home / "registry" / "src"
    if not src_root.is_dir():
        return None
    for index_dir in src_root.glob("index.*"):
        if not index_dir.is_dir():
            continue
        lock_path = index_dir / f"{name}-{version}" / "Cargo.lock"
        if lock_path.is_file():
            return lock_path
    return None


def read_lock_from_crate_cache(home: Path, name: str, version: str) -> str | None:
    """Read ``Cargo.lock`` text from a cached ``.crate`` tarball without full extraction."""
    cache_root = home / "registry" / "cache"
    if not cache_root.is_dir():
        return None
    crate_name = f"{name}-{version}.crate"
    for index_dir in cache_root.glob("index.*"):
        if not index_dir.is_dir():
            continue
        crate_path = index_dir / crate_name
        if not crate_path.is_file():
            continue
        try:
            with tarfile.open(crate_path, "r:gz") as archive:
                members = [
                    member
                    for member in archive.getmembers()
                    if member.isfile() and member.name.endswith("/Cargo.lock")
                ]
                if not members:
                    continue
                members.sort(key=lambda member: member.name.count("/"))
                lock_member = members[0]
                extracted = archive.extractfile(lock_member)
                if extracted is None:
                    continue
                return extracted.read().decode("utf-8")
        except (OSError, tarfile.TarError, UnicodeDecodeError) as exc:
            logger.warning("Failed to read Cargo.lock from %s: %s", crate_path, exc)
    return None


def _root_dependency(installed: InstalledCrate) -> DependencyItem:
    return DependencyItem(
        name=installed.name,
        version=installed.version,
        package_type=PackageType.CRATESIO.value,
        source=f"cargo-install:{installed.name}",
        evidence="cargo install --list",
        raw=f"{installed.name}@{installed.version}",
    )


def _parse_lock_path(lock_path: Path, installed: InstalledCrate) -> list[DependencyItem]:
    parsed = _RUST_PARSER.parse(lock_path)
    if not parsed:
        return []
    return [
        DependencyItem(
            name=item.name,
            version=item.version,
            package_type=PackageType.CRATESIO.value,
            source=f"cargo-install:{installed.name}",
            evidence=str(lock_path),
            raw=item.raw or f"{item.name}@{item.version}" if item.version else item.name,
        )
        for item in parsed
    ]


def _parse_lock_text(lock_text: str, installed: InstalledCrate) -> list[DependencyItem]:
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".lock",
            encoding="utf-8",
            delete=False,
        ) as handle:
            handle.write(lock_text)
            temp_path = Path(handle.name)
        try:
            return _parse_lock_path(temp_path, installed)
        finally:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError as exc:
                logger.warning("Failed to remove temp Cargo.lock %s: %s", temp_path, exc)
    except OSError as exc:
        logger.warning(
            "Failed to parse Cargo.lock for cargo-install:%s: %s",
            installed.name,
            exc,
        )
        return []


def collect_installed_crate_dependencies(
    installed: InstalledCrate,
    *,
    home: Path | None = None,
) -> tuple[list[DependencyItem], list[str]]:
    """Collect root package and lockfile dependencies for one global install."""
    cargo_dir = home or cargo_home()
    warnings: list[str] = []
    items = [_root_dependency(installed)]

    if installed.source_kind != "registry":
        warnings.append(
            f"cargo-install:{installed.name}: only root package checked "
            f"({installed.source_kind or 'unknown'} install; no registry Cargo.lock lookup)."
        )
        return items, warnings

    lock_path = find_lock_in_registry_src(cargo_dir, installed.name, installed.version)
    if lock_path is not None:
        items.extend(_parse_lock_path(lock_path, installed))
        return items, warnings

    lock_text = read_lock_from_crate_cache(cargo_dir, installed.name, installed.version)
    if lock_text:
        items.extend(_parse_lock_text(lock_text, installed))
        return items, warnings

    warnings.append(
        f"cargo-install:{installed.name}: Cargo.lock not found; checking root package only."
    )
    return items, warnings


def collect_cargo_install_global() -> tuple[list[DependencyItem], list[str]]:
    """Run ``cargo install --list`` and expand each install via its ``Cargo.lock`` when possible."""
    result = run_command(["cargo", "install", "--list"], timeout=120.0)
    if result is None:
        logger.warning("cargo install --list failed: cargo not found or command error.")
        return [], ["cargo install --list failed: cargo not found."]
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "").strip() or f"exit {result.returncode}"
        logger.warning("cargo install --list exited %s: %s", result.returncode, message)
        return [], [f"cargo install --list failed: {message}"]

    installed_crates = parse_cargo_install_list(result.stdout or "")
    if not installed_crates:
        return [], ["No packages found via cargo-install."]

    items: list[DependencyItem] = []
    warnings: list[str] = []
    for installed in installed_crates:
        try:
            collected, install_warnings = collect_installed_crate_dependencies(installed)
            items.extend(collected)
            warnings.extend(install_warnings)
        except Exception as exc:  # noqa: BLE001
            logger.warning("cargo-install:%s collection failed: %s", installed.name, exc)
            warnings.append(f"cargo-install:{installed.name} failed: {exc}")
            items.append(_root_dependency(installed))
    return items, warnings


class CargoInstallCollector(GlobalCollector):
    """Dependencies from ``cargo install`` globals via ``cargo install --list`` + Cargo.lock."""

    name = "cargo-install"

    def collect(self) -> list[DependencyItem]:
        items, _warnings = collect_cargo_install_global()
        return items
