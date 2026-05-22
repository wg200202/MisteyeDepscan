from __future__ import annotations

import json
import re
from pathlib import Path

from misteye_depscan.models import DependencyItem, PackageType
from misteye_depscan.parsers.base import DependencyParser, normalize_name, strip_version_operators

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

        # Installed package under node_modules (name + version at package root)
        if "node_modules" in path.parts:
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

        for section in (
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ):
            deps = data.get(section, {}) or {}
            for name, spec in deps.items():
                items.append(
                    DependencyItem(
                        name=normalize_name(name),
                        version=strip_version_operators(str(spec)),
                        package_type=PackageType.NPM.value,
                        source=str(path),
                        evidence=f"{section}.{name}",
                        raw=f"{name}@{spec}",
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
            version = meta.get("version")
            if not version:
                continue
            if pkg_path in {"", "node_modules"}:
                continue
            name = pkg_path.split("node_modules/")[-1]
            items.append(
                DependencyItem(
                    name=normalize_name(name),
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
