from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path

from misteye_depscan.ecosystems import MANIFEST_SKIP_DIR_NAMES
from misteye_depscan.models import DependencyItem

OPTIONAL_MANIFEST_NAMES = {
    "go.mod",
    "go.sum",
    "cargo.toml",
    "cargo.lock",
    "gemfile",
    "gemfile.lock",
    "composer.json",
    "composer.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
}


class DependencyParser(ABC):
    enabled: bool = True
    ecosystem: str | None = None  # "npm" | "pypi" | None

    @abstractmethod
    def can_parse(self, path: Path) -> bool:
        raise NotImplementedError

    @abstractmethod
    def parse(self, path: Path) -> list[DependencyItem]:
        raise NotImplementedError


def normalize_name(name: str) -> str:
    return name.strip().strip('"').strip("'")


def strip_version_operators(spec: str) -> str | None:
    spec = spec.strip()
    if not spec or spec == "*":
        return None
    match = re.match(r"^v?(\d[\w.\-+]*.*)$", spec)
    if match:
        return match.group(1)
    for op in ("===", "==", ">=", "<=", "~=", "!=", ">", "<", "@", "^", "~"):
        if op in spec:
            _, version = spec.split(op, 1)
            version = version.strip()
            return version or None
    return spec


def _path_skipped_for_manifests(path: Path) -> bool:
    return any(part in MANIFEST_SKIP_DIR_NAMES for part in path.parts)


def _matches_ecosystem_filename(path: Path, ecosystem: str) -> bool:
    from misteye_depscan.ecosystems import NPM_MARKERS, PYPI_MARKERS

    name = path.name.lower()
    if ecosystem == "npm":
        return name in NPM_MARKERS
    if ecosystem == "pypi":
        if name in PYPI_MARKERS:
            return True
        return name.startswith("requirements") and name.endswith(".txt")
    return False


def find_manifest_files(
    root: Path,
    *,
    ecosystems: set[str] | None = None,
    include_optional: bool = False,
) -> list[Path]:
    """Find dependency manifest/lock files outside node_modules, .venv, vendor, etc."""
    root = root.resolve()
    if root.is_file():
        if _path_skipped_for_manifests(root.parent):
            return []
        if ecosystems and not any(_matches_ecosystem_filename(root, eco) for eco in ecosystems):
            if not include_optional or root.name.lower() not in OPTIONAL_MANIFEST_NAMES:
                return []
        return [root]

    found: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or _path_skipped_for_manifests(path):
            continue
        name = path.name.lower()
        if include_optional and name in OPTIONAL_MANIFEST_NAMES:
            found.append(path)
            continue
        if ecosystems:
            if not any(_matches_ecosystem_filename(path, eco) for eco in ecosystems):
                continue
        elif not (
            _matches_ecosystem_filename(path, "npm")
            or _matches_ecosystem_filename(path, "pypi")
            or (include_optional and name in OPTIONAL_MANIFEST_NAMES)
        ):
            continue
        found.append(path)
    return sorted(found)


def find_node_modules_package_json(root: Path) -> list[Path]:
    """Installed npm packages under node_modules (full tree scan per spec)."""
    root = root.resolve()
    found: list[Path] = []
    for path in root.rglob("package.json"):
        if "node_modules" not in path.parts:
            continue
        found.append(path)
    return sorted(found)


# Backward-compatible alias
find_dependency_files = find_manifest_files
