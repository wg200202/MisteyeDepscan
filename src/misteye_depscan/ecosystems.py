from __future__ import annotations

from pathlib import Path

# Marker files used to auto-detect which ecosystem checks apply (outside vendor/venv trees).
NPM_MARKERS = frozenset(
    {
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
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
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".idea",
        ".vscode",
        ".eggs",
    }
)

SUPPORTED_ECOSYSTEMS = frozenset({"npm", "pypi"})


def _path_skipped_for_manifests(path: Path) -> bool:
    return any(part in MANIFEST_SKIP_DIR_NAMES for part in path.parts)


def _is_pypi_marker(path: Path) -> bool:
    name = path.name.lower()
    if name in PYPI_MARKERS:
        return True
    return name.startswith("requirements") and name.endswith(".txt")


def _is_npm_marker(path: Path) -> bool:
    return path.name.lower() in NPM_MARKERS


def detect_ecosystems(root: Path) -> set[str]:
    """Detect npm/pypi from marker files outside skipped trees."""
    root = root.resolve()
    found: set[str] = set()

    if root.is_file():
        if _is_npm_marker(root):
            found.add("npm")
        if _is_pypi_marker(root):
            found.add("pypi")
        return found

    for path in root.rglob("*"):
        if not path.is_file() or _path_skipped_for_manifests(path):
            continue
        if _is_npm_marker(path):
            found.add("npm")
        if _is_pypi_marker(path):
            found.add("pypi")
        if found == SUPPORTED_ECOSYSTEMS:
            break
    return found


def parse_ecosystem_option(value: str | None, root: Path) -> set[str]:
    """
    Parse --ecosystem: npm, pypi, all, or comma-separated (npm,pypi).
    Empty / omitted → auto-detect from marker files.
    """
    if value is None or not value.strip():
        detected = detect_ecosystems(root)
        return detected if detected else set(SUPPORTED_ECOSYSTEMS)

    normalized = value.strip().lower()
    if normalized == "all":
        return set(SUPPORTED_ECOSYSTEMS)

    selected: set[str] = set()
    for part in normalized.split(","):
        eco = part.strip()
        if eco in SUPPORTED_ECOSYSTEMS:
            selected.add(eco)
    if not selected:
        raise ValueError(
            f"Invalid --ecosystem value: {value!r}. Use npm, pypi, all, or npm,pypi."
        )
    return selected
