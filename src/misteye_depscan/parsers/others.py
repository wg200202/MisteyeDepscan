from __future__ import annotations

import json
import re
from pathlib import Path

from misteye_depscan.models import DependencyItem, PackageType
from misteye_depscan.parsers.base import DependencyParser, normalize_name, strip_version_operators

GO_REQUIRE = re.compile(r"^\s*(?P<name>[^\s]+)\s+(?P<version>v[^\s]+)")
RUBY_GEM = re.compile(r'^\s*gem\s+["\']?(?P<name>[^"\']+)["\']?(?:,\s*["\']?(?P<version>[^"\']+)["\']?)?')
COMPOSER_PKG = re.compile(r'^\s*"(?P<name>[^"]+)"\s*:\s*"(?P<version>[^"]+)"')
CSPROJ_REF = re.compile(
    r'Include="(?P<name>[^"]+)"\s+Version="(?P<version>[^"]+)"'
)


class GoParser(DependencyParser):
    enabled = False

    def can_parse(self, path: Path) -> bool:
        return path.name.lower() in {"go.mod", "go.sum"}

    def parse(self, path: Path) -> list[DependencyItem]:
        if path.name.lower() == "go.sum":
            return self._parse_go_sum(path)
        if path.name.lower() != "go.mod":
            return []
        items: list[DependencyItem] = []
        in_require = False
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("require ("):
                in_require = True
                continue
            if in_require and stripped == ")":
                in_require = False
                continue
            if stripped.startswith("require "):
                match = GO_REQUIRE.match(stripped)
                if match:
                    items.append(self._item(match.group("name"), match.group("version"), path, line_no))
                continue
            if in_require:
                parts = stripped.split()
                if len(parts) >= 2:
                    items.append(self._item(parts[0], parts[1], path, line_no))
        return items

    def _item(self, name: str, version: str, path: Path, line_no: int) -> DependencyItem:
        return DependencyItem(
            name=normalize_name(name),
            version=strip_version_operators(version),
            package_type=PackageType.GO.value,
            source=str(path),
            evidence=f"{path.name}:{line_no}",
            raw=f"{name} {version}",
        )

    def _parse_go_sum(self, path: Path) -> list[DependencyItem]:
        items: list[DependencyItem] = []
        seen: set[tuple[str, str | None]] = set()
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            parts = line.strip().split()
            if len(parts) < 2:
                continue
            name = parts[0]
            version = parts[1].split("/")[0]
            version = strip_version_operators(version)
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            items.append(
                DependencyItem(
                    name=normalize_name(name),
                    version=version,
                    package_type=PackageType.GO.value,
                    source=str(path),
                    evidence=f"{path.name}:{line_no}",
                    raw=line.strip(),
                )
            )
        return items


class RustParser(DependencyParser):
    enabled = False

    def can_parse(self, path: Path) -> bool:
        return path.name.lower() in {"cargo.toml", "cargo.lock"}

    def parse(self, path: Path) -> list[DependencyItem]:
        name = path.name.lower()
        if name == "cargo.toml":
            return self._parse_cargo_toml(path)
        return self._parse_cargo_lock(path)

    def _parse_cargo_toml(self, path: Path) -> list[DependencyItem]:
        items: list[DependencyItem] = []
        section: str | None = None
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                section = stripped[1:-1].strip().lower()
                continue
            if section not in {"dependencies", "dev-dependencies", "build-dependencies"}:
                continue
            if "=" in stripped and not stripped.startswith("#"):
                pkg, spec = stripped.split("=", 1)
                version = strip_version_operators(spec.strip().strip('"').strip("'"))
                items.append(
                    DependencyItem(
                        name=normalize_name(pkg),
                        version=version,
                        package_type=PackageType.CRATESIO.value,
                        source=str(path),
                        evidence=f"{path.name}:{line_no}",
                        raw=stripped,
                    )
                )
        return items

    def _parse_cargo_lock(self, path: Path) -> list[DependencyItem]:
        items: list[DependencyItem] = []
        current_name: str | None = None
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("[[package]]"):
                current_name = None
                continue
            if stripped.startswith("name = "):
                current_name = normalize_name(stripped.split("=", 1)[1].strip().strip('"'))
                continue
            if stripped.startswith("version = ") and current_name:
                version = strip_version_operators(stripped.split("=", 1)[1].strip().strip('"'))
                items.append(
                    DependencyItem(
                        name=current_name,
                        version=version,
                        package_type=PackageType.CRATESIO.value,
                        source=str(path),
                        evidence=f"{path.name}:{line_no}",
                        raw=f"{current_name}@{version}",
                    )
                )
                current_name = None
        return items


class RubyParser(DependencyParser):
    enabled = False

    def can_parse(self, path: Path) -> bool:
        return path.name.lower() in {"gemfile", "gemfile.lock"}

    def parse(self, path: Path) -> list[DependencyItem]:
        if path.name.lower() == "gemfile":
            return self._parse_gemfile(path)
        return self._parse_gemfile_lock(path)

    def _parse_gemfile(self, path: Path) -> list[DependencyItem]:
        items: list[DependencyItem] = []
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            match = RUBY_GEM.match(line)
            if not match:
                continue
            items.append(
                DependencyItem(
                    name=normalize_name(match.group("name")),
                    version=strip_version_operators(match.group("version") or ""),
                    package_type=PackageType.RUBYGEMS.value,
                    source=str(path),
                    evidence=f"{path.name}:{line_no}",
                    raw=line.strip(),
                )
            )
        return items

    def _parse_gemfile_lock(self, path: Path) -> list[DependencyItem]:
        items: list[DependencyItem] = []
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("GIT") or stripped.startswith("PLATFORMS"):
                continue
            if stripped.startswith("specs:"):
                continue
            match = re.match(r"^\s*-\s+([^\s(]+)(?:\s+\(([^)]+)\))?", stripped)
            if match:
                items.append(
                    DependencyItem(
                        name=normalize_name(match.group(1)),
                        version=strip_version_operators(match.group(2) or ""),
                        package_type=PackageType.RUBYGEMS.value,
                        source=str(path),
                        evidence=f"{path.name}:{line_no}",
                        raw=stripped,
                    )
                )
        return items


class DotNetParser(DependencyParser):
    enabled = False

    def can_parse(self, path: Path) -> bool:
        name = path.name.lower()
        return name.endswith(".csproj") or name == "packages.lock.json"

    def parse(self, path: Path) -> list[DependencyItem]:
        if path.name.lower() == "packages.lock.json":
            return self._parse_packages_lock_json(path)
        return self._parse_csproj(path)

    def _parse_csproj(self, path: Path) -> list[DependencyItem]:
        text = path.read_text(encoding="utf-8")
        items: list[DependencyItem] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            for match in CSPROJ_REF.finditer(line):
                items.append(
                    DependencyItem(
                        name=normalize_name(match.group("name")),
                        version=strip_version_operators(match.group("version")),
                        package_type=PackageType.NUGET.value,
                        source=str(path),
                        evidence=f"{path.name}:{line_no}",
                        raw=match.group(0),
                    )
                )
        return items

    def _parse_packages_lock_json(self, path: Path) -> list[DependencyItem]:
        items: list[DependencyItem] = []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return items
        if not isinstance(data, dict):
            return items
        for framework, deps in data.items():
            if framework.startswith("version") or not isinstance(deps, dict):
                continue
            for name, meta in deps.items():
                version = None
                if isinstance(meta, dict):
                    resolved = meta.get("resolved") or meta.get("version") or ""
                    version = strip_version_operators(str(resolved))
                if not name:
                    continue
                items.append(
                    DependencyItem(
                        name=normalize_name(name),
                        version=version,
                        package_type=PackageType.NUGET.value,
                        source=str(path),
                        evidence=f"{path.name}:{framework}.{name}",
                        raw=f"{name}@{version}" if version else name,
                    )
                )
        return items


# Java/Maven is intentionally not implemented.
# MistEye Detect API does not currently expose a `package:maven` type, so
# scanning Java coordinates would have to be mapped onto an unrelated ecosystem
# (e.g. PyPI), which produces false positives. Re-introduce a JavaParser only
# once a dedicated `package:maven` (or similar) type is available.
