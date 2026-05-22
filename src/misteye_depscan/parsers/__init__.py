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
    JavaParser,
    RubyParser,
    RustParser,
)
from misteye_depscan.parsers.python_parser import PythonParser
from misteye_depscan.models import DependencyItem

ALL_PARSERS: list[DependencyParser] = [
    PythonParser(),
    JavaScriptParser(),
    GoParser(),
    RustParser(),
    RubyParser(),
    DotNetParser(),
    JavaParser(),
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


def _parse_manifest_path(path: Path, *, include_optional: bool) -> list[DependencyItem]:
    if path.name.lower() == "package.json" and "node_modules" in path.parts:
        return _NPM_PARSER.parse(path)
    parser = get_parser_for(path, include_optional=include_optional)
    if parser is None:
        return []
    return parser.parse(path)


def collect_project_dependencies(
    root: Path,
    *,
    ecosystems: set[str] | None = None,
    include_optional: bool = False,
    scan_node_modules: bool = True,
) -> tuple[list[DependencyItem], list[str]]:
    """
    Collect dependencies from manifest files and (for npm) installed node_modules packages.
    """
    if ecosystems is None:
        ecosystems = set(SUPPORTED_ECOSYSTEMS)

    items: list[DependencyItem] = []
    warnings: list[str] = []

    manifest_files = find_manifest_files(
        root, ecosystems=ecosystems, include_optional=include_optional
    )
    for file_path in manifest_files:
        items.extend(_parse_manifest_path(file_path, include_optional=include_optional))

    if "npm" in ecosystems and scan_node_modules:
        nm_files = find_node_modules_package_json(root)
        if nm_files:
            for pkg_json in nm_files:
                items.extend(_NPM_PARSER.parse(pkg_json))
        elif "package.json" in {p.name for p in manifest_files}:
            warnings.append(
                "npm ecosystem detected but no node_modules/ tree found (installed packages not scanned)."
            )

    return dedupe_dependencies(items), warnings


def dedupe_dependencies(items: list[DependencyItem]) -> list[DependencyItem]:
    seen: set[tuple[str, str | None, str]] = set()
    unique: list[DependencyItem] = []
    for item in items:
        if item.key in seen:
            continue
        seen.add(item.key)
        unique.append(item)
    return unique
