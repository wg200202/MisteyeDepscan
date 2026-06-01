from __future__ import annotations

import os
import re
from abc import ABC, abstractmethod
from pathlib import Path

from misteye_depscan.ecosystems import MANIFEST_SKIP_DIR_NAMES
from misteye_depscan.models import DependencyItem

DEFAULT_MAX_DEPTH = 10

OPTIONAL_MANIFEST_NAMES = {
    "gemfile",
    "gemfile.lock",
    "composer.json",
    "composer.lock",
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


# package.json specs that are not registry packages (skip threat lookup)
_NON_REGISTRY_SPEC_PREFIXES = (
    "file:",
    "link:",
    "workspace:",
    "git:",
    "git+",
    "github:",
    "http:",
    "https:",
    "bitbucket:",
    "gitlab:",
)


def _parse_npm_alias_payload(payload: str) -> tuple[str, str | None]:
    """Parse ``fdir@1.2.0`` or ``@scope/pkg@1.0.0`` from an ``npm:`` alias spec."""
    payload = payload.strip()
    if not payload:
        return "", None
    if payload.startswith("@"):
        idx = payload.rfind("@")
        if idx <= 1:
            return normalize_name(payload), None
        return normalize_name(payload[:idx]), strip_version_operators(payload[idx + 1 :])
    if "@" in payload:
        name, ver = payload.rsplit("@", 1)
        return normalize_name(name), strip_version_operators(ver)
    return normalize_name(payload), None


def is_private_npm_package(manifest: dict) -> bool:
    """True when package.json marks the package as private (not a public registry artifact)."""
    val = manifest.get("private")
    if val is None:
        return False
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in {"true", "1", "yes"}
    return bool(val)


def resolve_npm_dependency(alias: str, spec: str) -> tuple[str, str | None] | None:
    """
    Resolve package name and version from a package.json dependency entry.

    Handles npm aliases such as ``"fdir1": "npm:fdir@1.2.0"`` — uses ``fdir`` and
    ``1.2.0``, not the alias key ``fdir1``. Returns ``None`` for non-registry specs
    (``file:``, ``workspace:``, ``git:``, etc.).
    """
    raw = str(spec).strip()
    if not raw:
        return None
    lower = raw.lower()
    if any(lower.startswith(prefix) for prefix in _NON_REGISTRY_SPEC_PREFIXES):
        return None
    if lower.startswith("npm:"):
        name, version = _parse_npm_alias_payload(raw[4:])
        if not name:
            return None
        return name, version
    return normalize_name(alias), strip_version_operators(raw)


def _path_skipped_for_manifests(path: Path) -> bool:
    return any(part in MANIFEST_SKIP_DIR_NAMES for part in path.parts)


def _matches_ecosystem_filename(path: Path, ecosystem: str) -> bool:
    from misteye_depscan.ecosystems import (
        GO_MARKERS,
        NPM_MARKERS,
        PYPI_MARKERS,
        RUBYGEMS_MARKERS,
        RUST_MARKERS,
    )

    name = path.name.lower()
    if ecosystem == "npm":
        return name in NPM_MARKERS
    if ecosystem == "pypi":
        if name in PYPI_MARKERS:
            return True
        return name.startswith("requirements") and name.endswith(".txt")
    if ecosystem == "rust":
        return name in RUST_MARKERS
    if ecosystem == "go":
        return name in GO_MARKERS
    if ecosystem == "rubygems":
        return name in RUBYGEMS_MARKERS
    return False


def _walk_with_depth(root: Path, max_depth: int | None) -> list[Path]:
    """Walk ``root`` recursively up to ``max_depth`` levels.  ``None`` = unlimited."""
    root = root.resolve()
    if max_depth is None:
        return list(root.rglob("*"))
    results: list[Path] = []
    root_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        depth = len(current.parts) - root_depth
        if depth >= max_depth:
            dirnames.clear()
            continue
        for fname in filenames:
            results.append(current / fname)
    return results


def find_manifest_files(
    root: Path,
    *,
    ecosystems: set[str] | None = None,
    include_optional: bool = False,
    max_depth: int | None = DEFAULT_MAX_DEPTH,
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
    for path in _walk_with_depth(root, max_depth):
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
            or _matches_ecosystem_filename(path, "rust")
            or _matches_ecosystem_filename(path, "go")
            or _matches_ecosystem_filename(path, "rubygems")
            or (include_optional and name in OPTIONAL_MANIFEST_NAMES)
        ):
            continue
        found.append(path)
    return sorted(found)


def is_npm_package_root_package_json(path: Path) -> bool:
    """
    True when ``path`` is ``package.json`` at the install root of an npm package.

    Only ``node_modules/<pkg>/package.json`` or ``node_modules/@scope/<pkg>/package.json``
    count. Nested paths such as ``node_modules/npm/docs/package.json`` are internal
    subfolders of a tarball (docs, examples, etc.) and must not be treated as separate
    published packages — they often share names with unrelated malicious registry packages.
    """
    if path.name.lower() != "package.json" or "node_modules" not in path.parts:
        return False
    parts = path.parts
    idx = max(i for i, part in enumerate(parts) if part == "node_modules")
    segments = parts[idx + 1 : -1]
    if not segments:
        return False
    if segments[0].startswith("@"):
        return len(segments) == 2
    return len(segments) == 1


def find_node_modules_package_json(
    root: Path, *, max_depth: int | None = DEFAULT_MAX_DEPTH
) -> list[Path]:
    """Installed npm package roots under node_modules (depth-limited scan)."""
    root = root.resolve()
    found: list[Path] = []
    for path in _walk_with_depth(root, max_depth):
        if not path.is_file():
            continue
        if not is_npm_package_root_package_json(path):
            continue
        found.append(path)
    return sorted(found)


# Backward-compatible alias
find_dependency_files = find_manifest_files
