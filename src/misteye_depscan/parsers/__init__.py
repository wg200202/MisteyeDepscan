from __future__ import annotations

from pathlib import Path

from misteye_depscan.ecosystems import SUPPORTED_ECOSYSTEMS
from misteye_depscan.parsers.base import (
    DependencyParser,
    find_manifest_files,
    find_node_modules_package_json,
)
from misteye_depscan.parsers.javascript_parser import JavaScriptParser
from misteye_depscan.parsers.others import (
    DotNetParser,
    GoParser,
    RubyParser,
    RustParser,
)
from misteye_depscan.parsers.python_parser import PythonParser
from misteye_depscan.models import DependencyItem

# Note: Java/Maven is intentionally NOT included.
# MistEye Detect API supports only:
#   package:pypi / package:npm / package:go / package:nuget / package:rubygems / package:cratesio
# Sending Java coordinates under any of those types would cause false positives.
ALL_PARSERS: list[DependencyParser] = [
    PythonParser(),
    JavaScriptParser(),
    GoParser(),
    RustParser(),
    RubyParser(),
    DotNetParser(),
]

DEFAULT_PARSERS: list[DependencyParser] = [p for p in ALL_PARSERS if getattr(p, "enabled", True)]

_NPM_PARSER = JavaScriptParser()
_PYPI_PARSER = PythonParser()


def get_parser_for(path: Path, *, include_optional: bool = False) -> DependencyParser | None:
    parsers = ALL_PARSERS if include_optional else DEFAULT_PARSERS
    for parser in parsers:
        if parser.can_parse(path):
            return parser
    return None


def parse_dependency_file(path: Path, *, include_optional: bool = False) -> list[DependencyItem]:
    parser = get_parser_for(path, include_optional=include_optional)
    if parser is None:
        return []
    return parser.parse(path)


def _filter_go_module_manifests(manifest_files: list[Path]) -> list[Path]:
    """Prefer ``go.sum`` over ``go.mod`` in the same module directory."""
    non_go = [
        path
        for path in manifest_files
        if path.name.lower() not in {"go.mod", "go.sum"}
    ]
    go_files = [
        path
        for path in manifest_files
        if path.name.lower() in {"go.mod", "go.sum"}
    ]
    if not go_files:
        return manifest_files

    sum_dirs = {path.parent.resolve() for path in go_files if path.name.lower() == "go.sum"}
    if not sum_dirs:
        return non_go + go_files

    sums = [path for path in go_files if path.name.lower() == "go.sum"]
    mods = [
        path
        for path in go_files
        if path.name.lower() == "go.mod" and path.parent.resolve() not in sum_dirs
    ]
    return non_go + sums + mods


def _filter_rust_workspace_manifests(root: Path, manifest_files: list[Path]) -> list[Path]:
    """Prefer each workspace ``Cargo.lock`` over member ``Cargo.toml`` files; keep npm/pypi."""
    non_rust = [
        path
        for path in manifest_files
        if path.name.lower() not in {"cargo.toml", "cargo.lock"}
    ]
    rust_files = [
        path
        for path in manifest_files
        if path.name.lower() in {"cargo.toml", "cargo.lock"}
    ]
    if not rust_files:
        return manifest_files

    locks = sorted({path.resolve() for path in rust_files if path.name.lower() == "cargo.lock"})
    if locks:
        return non_rust + [Path(path) for path in locks]

    root_lock = (root.resolve() / "Cargo.lock")
    if root_lock.is_file():
        return non_rust + [root_lock]

    return non_rust + rust_files


def _parse_manifest_path(path: Path, *, include_optional: bool) -> list[DependencyItem]:
    if path.name.lower() == "package.json" and "node_modules" in path.parts:
        return _NPM_PARSER.parse(path)
    parser = get_parser_for(path, include_optional=include_optional)
    if parser is None:
        return []
    try:
        return parser.parse(path)
    except (OSError, ValueError, KeyError):
        return []


def collect_project_dependencies(
    root: Path,
    *,
    ecosystems: set[str] | None = None,
    include_optional: bool = False,
    scan_node_modules: bool = True,
    max_depth: int | None = None,
) -> tuple[list[DependencyItem], list[str], list[str], list[Path]]:
    """
    Collect dependencies from manifest files and (for npm) installed node_modules packages.

    ``max_depth`` controls how many directory levels are traversed (default from
    ``base.DEFAULT_MAX_DEPTH``).  Pass ``None`` for unlimited depth or ``0`` to
    only scan files directly in ``root``.

    Returns ``(dependencies, warnings, info, discovered_files)``.
    """
    from misteye_depscan.parsers.base import DEFAULT_MAX_DEPTH

    if max_depth is None:
        max_depth = DEFAULT_MAX_DEPTH

    if ecosystems is None:
        ecosystems = set(SUPPORTED_ECOSYSTEMS)

    items: list[DependencyItem] = []
    warnings: list[str] = []
    info: list[str] = []
    discovered_files: list[Path] = []

    manifest_files = find_manifest_files(
        root, ecosystems=ecosystems, include_optional=include_optional, max_depth=max_depth
    )
    if "go" in ecosystems:
        manifest_files = _filter_go_module_manifests(manifest_files)
    if "rust" in ecosystems:
        manifest_files = _filter_rust_workspace_manifests(root, manifest_files)
    discovered_files.extend(manifest_files)
    for file_path in manifest_files:
        items.extend(_parse_manifest_path(file_path, include_optional=include_optional))

    if "npm" in ecosystems and scan_node_modules:
        nm_files = find_node_modules_package_json(root, max_depth=max_depth)
        if nm_files:
            discovered_files.extend(nm_files)
            for pkg_json in nm_files:
                items.extend(_NPM_PARSER.parse(pkg_json))
        elif "package.json" in {p.name for p in manifest_files}:
            info.append(
                "npm ecosystem detected but no node_modules/ tree found (installed packages not scanned)."
            )

    return dedupe_dependencies(items), warnings, info, discovered_files


def dedupe_dependencies(items: list[DependencyItem]) -> list[DependencyItem]:
    seen: set[tuple[str, str | None, str]] = set()
    unique: list[DependencyItem] = []
    for item in items:
        if item.key in seen:
            continue
        seen.add(item.key)
        unique.append(item)
    return unique
