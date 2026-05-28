from __future__ import annotations

import os
from pathlib import Path

# Default recursion depth for manifest discovery (matches ``depscan scan --depth`` default).
DEFAULT_SCAN_DEPTH = 10

# Marker files used to auto-detect which ecosystem checks apply (outside vendor/venv trees).
NPM_MARKERS = frozenset(
    {
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
    }
)

RUST_MARKERS = frozenset(
    {
        "cargo.toml",
        "cargo.lock",
    }
)

PYPI_MARKERS = frozenset(
    {
        "pyproject.toml",
        "pipfile",
        "pipfile.lock",
        "poetry.lock",
        "uv.lock",
        "setup.py",
        "setup.cfg",
    }
)

# Skip these directories when discovering manifest/marker files (not when scanning node_modules).
MANIFEST_SKIP_DIR_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "vendor",
        ".tox",
        "site-packages",
        "dist",
        "build",
        "target",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".idea",
        ".vscode",
        ".eggs",
    }
)

SUPPORTED_ECOSYSTEMS = frozenset({"npm", "pypi", "rust"})


def _path_skipped_for_manifests(path: Path) -> bool:
    return any(part in MANIFEST_SKIP_DIR_NAMES for part in path.parts)


def _is_pypi_marker(path: Path) -> bool:
    name = path.name.lower()
    if name in PYPI_MARKERS:
        return True
    return name.startswith("requirements") and name.endswith(".txt")


def _is_npm_marker(path: Path) -> bool:
    return path.name.lower() in NPM_MARKERS


def _is_rust_marker(path: Path) -> bool:
    return path.name.lower() in RUST_MARKERS


def _walk_files_with_depth(root: Path, max_depth: int | None) -> list[Path]:
    """Walk ``root`` recursively up to ``max_depth`` directory levels below root."""
    root = root.resolve()
    if max_depth is None:
        return [path for path in root.rglob("*") if path.is_file()]
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


def detect_ecosystems(root: Path, *, max_depth: int | None = DEFAULT_SCAN_DEPTH) -> set[str]:
    """Detect npm/pypi/rust from marker files (same depth limit as manifest collection)."""
    root = root.resolve()
    found: set[str] = set()

    if root.is_file():
        if _is_npm_marker(root):
            found.add("npm")
        if _is_pypi_marker(root):
            found.add("pypi")
        if _is_rust_marker(root):
            found.add("rust")
        return found

    for path in _walk_files_with_depth(root, max_depth):
        if _path_skipped_for_manifests(path):
            continue
        if _is_npm_marker(path):
            found.add("npm")
        if _is_pypi_marker(path):
            found.add("pypi")
        if _is_rust_marker(path):
            found.add("rust")
        if found == SUPPORTED_ECOSYSTEMS:
            break
    return found


def parse_ecosystem_option(
    value: str | None,
    root: Path,
    *,
    max_depth: int | None = DEFAULT_SCAN_DEPTH,
) -> set[str]:
    """
    Parse --ecosystem: npm, pypi, rust, all, or comma-separated (e.g. npm,rust).
    Empty / omitted → auto-detect from marker files.
    """
    if value is None or not value.strip():
        detected = detect_ecosystems(root, max_depth=max_depth)
        return detected if detected else set(SUPPORTED_ECOSYSTEMS)

    normalized = value.strip().lower()
    if normalized == "all":
        return set(SUPPORTED_ECOSYSTEMS)

    selected: set[str] = set()
    for part in normalized.split(","):
        eco = part.strip()
        if eco == "cratesio":
            eco = "rust"
        if eco in SUPPORTED_ECOSYSTEMS:
            selected.add(eco)
    if not selected:
        raise ValueError(
            f"Invalid --ecosystem value: {value!r}. Use npm, pypi, rust, all, or npm,rust."
        )
    return selected
