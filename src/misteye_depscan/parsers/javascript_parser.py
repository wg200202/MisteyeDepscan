from __future__ import annotations

import json
import re
from pathlib import Path

from misteye_depscan.models import DependencyItem, PackageType
from misteye_depscan.parsers.base import (
    DependencyParser,
    is_local_npm_lock_entry,
    is_npm_package_root_package_json,
    is_private_npm_package,
    normalize_name,
    resolve_npm_dependency,
    strip_version_operators,
)

YARN_ENTRY = re.compile(r'^"?((?:@[^/]+/)?[^@\s"]+)@([^:\s"]+)"?:')
PNPM_ENTRY = re.compile(r"^\s{2}(/(?:@[^/]+/)?[^/@]+)(?:@([^:]+))?:")


class JavaScriptParser(DependencyParser):
    ecosystem = "npm"

    def can_parse(self, path: Path) -> bool:
        name = path.name.lower()
        return name in {
            "package.json",
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
        }

    def parse(self, path: Path) -> list[DependencyItem]:
        name = path.name.lower()
        if name == "package.json":
            return self._parse_package_json(path)
        if name == "package-lock.json":
            return self._parse_package_lock(path)
        if name == "pnpm-lock.yaml":
            return self._parse_pnpm_lock(path)
        if name == "yarn.lock":
            return self._parse_yarn_lock(path)
        return []

    def _parse_package_json(self, path: Path) -> list[DependencyItem]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
        if not isinstance(data, dict):
            return []
        items: list[DependencyItem] = []

        under_node_modules = "node_modules" in path.parts
        at_package_root = is_npm_package_root_package_json(path)

        # Root / workspace package.json (not under node_modules): never scan the project's
        # own name@version — only external deps from dependencies/* sections below.

        # Installed package at node_modules/<pkg>/package.json only (not docs/, lib/, etc.)
        # Skip private packages — they are local/workspace artifacts, not registry deps.
        if at_package_root and not is_private_npm_package(data):
            installed_name = str(data.get("name") or "").strip()
            installed_version = strip_version_operators(str(data.get("version") or ""))
            if installed_name and installed_version:
                items.append(
                    DependencyItem(
                        name=normalize_name(installed_name),
                        version=installed_version,
                        package_type=PackageType.NPM.value,
                        source=str(path),
                        evidence="installed-package",
                        raw=f"{installed_name}@{installed_version}",
                    )
                )

        # Nested package.json inside a tarball (e.g. npm/docs/) — skip manifest sections too.
        if under_node_modules and not at_package_root:
            return items

        for section in (
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ):
            deps = data.get(section, {}) or {}
            manifest_name = str(data.get("name") or "")
            for alias, spec in deps.items():
                resolved = resolve_npm_dependency(
                    alias, str(spec), package_name=manifest_name
                )
                if resolved is None:
                    continue
                dep_name, version = resolved
                raw = f"{dep_name}@{version}" if version else dep_name
                items.append(
                    DependencyItem(
                        name=dep_name,
                        version=version,
                        package_type=PackageType.NPM.value,
                        source=str(path),
                        evidence=f"{section}.{alias}",
                        raw=raw,
                    )
                )
        return items

    def _parse_package_lock(self, path: Path) -> list[DependencyItem]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
        if not isinstance(data, dict):
            return []
        items: list[DependencyItem] = []
        packages = data.get("packages") or {}
        for pkg_path, meta in packages.items():
            if not isinstance(meta, dict):
                continue
            if is_private_npm_package(meta):
                continue
            if is_local_npm_lock_entry(meta):
                continue
            version = meta.get("version")
            if not version:
                continue
            if pkg_path in {"", "node_modules"}:
                continue
            path_name = pkg_path.split("node_modules/")[-1]
            name = normalize_name(str(meta.get("name") or path_name))
            items.append(
                DependencyItem(
                    name=name,
                    version=str(version),
                    package_type=PackageType.NPM.value,
                    source=str(path),
                    evidence=f"packages.{pkg_path}",
                    raw=f"{name}@{version}",
                )
            )
        if items:
            return items

        # npm v1 lockfile fallback
        deps = data.get("dependencies") or {}
        return self._flatten_lockfile_deps(deps, path, prefix="dependencies")

    def _flatten_lockfile_deps(
        self, deps: dict, path: Path, *, prefix: str
    ) -> list[DependencyItem]:
        items: list[DependencyItem] = []
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            items.append(
                DependencyItem(
                    name=normalize_name(name),
                    version=str(version) if version else None,
                    package_type=PackageType.NPM.value,
                    source=str(path),
                    evidence=f"{prefix}.{name}",
                    raw=f"{name}@{version}" if version else name,
                )
            )
            nested = meta.get("dependencies") or {}
            items.extend(
                self._flatten_lockfile_deps(nested, path, prefix=f"{prefix}.{name}.dependencies")
            )
        return items

    def _parse_pnpm_lock(self, path: Path) -> list[DependencyItem]:
        items: list[DependencyItem] = []
        seen: set[tuple[str, str | None]] = set()
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            match = PNPM_ENTRY.match(line)
            if not match:
                continue
            raw_name = match.group(1).lstrip("/")
            version = strip_version_operators(match.group(2) or "")
            key = (raw_name.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            items.append(
                DependencyItem(
                    name=normalize_name(raw_name),
                    version=version,
                    package_type=PackageType.NPM.value,
                    source=str(path),
                    evidence=f"{path.name}:{line_no}",
                    raw=line.strip(),
                )
            )
        return items

    def _parse_yarn_lock(self, path: Path) -> list[DependencyItem]:
        items: list[DependencyItem] = []
        seen: set[tuple[str, str | None]] = set()
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            match = YARN_ENTRY.match(line)
            if not match:
                continue
            name = normalize_name(match.group(1))
            version = strip_version_operators(match.group(2))
            key = (name.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            items.append(
                DependencyItem(
                    name=name,
                    version=version,
                    package_type=PackageType.NPM.value,
                    source=str(path),
                    evidence=f"{path.name}:{line_no}",
                    raw=line.strip(),
                )
            )
        return items
