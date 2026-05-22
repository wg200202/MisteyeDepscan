from __future__ import annotations

import configparser
import json
import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

from misteye_depscan.models import PackageType
from misteye_depscan.parsers.base import (
    DependencyParser,
    normalize_name,
    strip_version_operators,
)
from misteye_depscan.models import DependencyItem

REQUIREMENT_LINE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?P<spec>.*)?$"
)
PEP508_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")


INSTALL_REQUIRES_RE = re.compile(
    r"install_requires\s*=\s*\[(.*?)\]",
    re.DOTALL,
)

class PythonParser(DependencyParser):
    ecosystem = "pypi"

    def can_parse(self, path: Path) -> bool:
        name = path.name.lower()
        return (
            (name.startswith("requirements") and name.endswith(".txt"))
            or name
            in {
                "pyproject.toml",
                "pipfile",
                "pipfile.lock",
                "poetry.lock",
                "uv.lock",
                "setup.py",
                "setup.cfg",
            }
        )

    def parse(self, path: Path) -> list[DependencyItem]:
        name = path.name.lower()
        if name.startswith("requirements") and name.endswith(".txt"):
            return self._parse_requirements(path)
        if name == "pyproject.toml":
            return self._parse_pyproject(path)
        if name == "pipfile":
            return self._parse_pipfile(path)
        if name == "pipfile.lock":
            return self._parse_pipfile_lock(path)
        if name == "poetry.lock":
            return self._parse_poetry_lock(path)
        if name == "uv.lock":
            return self._parse_uv_lock(path)
        if name == "setup.py":
            return self._parse_setup_py(path)
        if name == "setup.cfg":
            return self._parse_setup_cfg(path)
        return []

    def _parse_requirements(self, path: Path) -> list[DependencyItem]:
        items: list[DependencyItem] = []
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            if raw.startswith("-") or raw.startswith("http://") or raw.startswith("https://"):
                continue
            match = REQUIREMENT_LINE.match(raw.split("#", 1)[0].strip())
            if not match:
                continue
            pkg_name = normalize_name(match.group("name"))
            version = strip_version_operators(match.group("spec") or "")
            items.append(
                DependencyItem(
                    name=pkg_name,
                    version=version,
                    package_type=PackageType.PYPI.value,
                    source=str(path),
                    evidence=f"{path.name}:{line_no}",
                    raw=raw,
                )
            )
        return items

    def _parse_pyproject(self, path: Path) -> list[DependencyItem]:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        items: list[DependencyItem] = []
        project = data.get("project", {})
        for spec in project.get("dependencies", []) or []:
            item = self._dependency_from_spec(spec, path, "project.dependencies")
            if item:
                items.append(item)
        optional = project.get("optional-dependencies", {}) or {}
        for group, specs in optional.items():
            for spec in specs or []:
                item = self._dependency_from_spec(
                    spec, path, f"project.optional-dependencies.{group}"
                )
                if item:
                    items.append(item)
        tool_poetry = data.get("tool", {}).get("poetry", {})
        for section in ("dependencies", "dev-dependencies"):
            deps = tool_poetry.get(section, {}) or {}
            for name, spec in deps.items():
                items.append(
                    DependencyItem(
                        name=normalize_name(name),
                        version=strip_version_operators(str(spec)),
                        package_type=PackageType.PYPI.value,
                        source=str(path),
                        evidence=f"tool.poetry.{section}.{name}",
                        raw=f"{name} {spec}",
                    )
                )
        groups = tool_poetry.get("group", {}) or {}
        for group_name, group_data in groups.items():
            if not isinstance(group_data, dict):
                continue
            group_deps = group_data.get("dependencies", {}) or {}
            for name, spec in group_deps.items():
                items.append(
                    DependencyItem(
                        name=normalize_name(name),
                        version=strip_version_operators(str(spec)),
                        package_type=PackageType.PYPI.value,
                        source=str(path),
                        evidence=f"tool.poetry.group.{group_name}.{name}",
                        raw=f"{name} {spec}",
                    )
                )
        return items

    def _parse_pipfile(self, path: Path) -> list[DependencyItem]:
        items: list[DependencyItem] = []
        section: str | None = None
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                section = stripped[1:-1].strip().lower()
                continue
            if section not in {"packages", "dev-packages"}:
                continue
            if "=" in stripped:
                name, spec = stripped.split("=", 1)
                version = strip_version_operators(spec.strip().strip('"').strip("'"))
            else:
                name, version = stripped, None
            items.append(
                DependencyItem(
                    name=normalize_name(name),
                    version=version,
                    package_type=PackageType.PYPI.value,
                    source=str(path),
                    evidence=f"{path.name}:{line_no}",
                    raw=stripped,
                )
            )
        return items

    def _parse_pipfile_lock(self, path: Path) -> list[DependencyItem]:
        items: list[DependencyItem] = []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return items
        for section in ("default", "develop"):
            deps = data.get(section) or {}
            if not isinstance(deps, dict):
                continue
            for name, meta in deps.items():
                version = None
                if isinstance(meta, dict):
                    version = strip_version_operators(str(meta.get("version") or ""))
                items.append(
                    DependencyItem(
                        name=normalize_name(name),
                        version=version,
                        package_type=PackageType.PYPI.value,
                        source=str(path),
                        evidence=f"{path.name}:{section}.{name}",
                        raw=f"{name}{meta}",
                    )
                )
        return items

    def _parse_uv_lock(self, path: Path) -> list[DependencyItem]:
        return self._parse_toml_lock_packages(path, lock_label="uv.lock")

    def _parse_poetry_lock(self, path: Path) -> list[DependencyItem]:
        return self._parse_toml_lock_packages(path, lock_label="poetry.lock")

    def _parse_toml_lock_packages(self, path: Path, *, lock_label: str) -> list[DependencyItem]:
        items: list[DependencyItem] = []
        current_name: str | None = None
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.strip()
            if stripped == "[[package]]":
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
                        package_type=PackageType.PYPI.value,
                        source=str(path),
                        evidence=f"{path.name}:{line_no}",
                        raw=f"{current_name}=={version}",
                    )
                )
                current_name = None
        return items

    def _parse_setup_py(self, path: Path) -> list[DependencyItem]:
        text = path.read_text(encoding="utf-8")
        items: list[DependencyItem] = []
        match = INSTALL_REQUIRES_RE.search(text)
        if not match:
            return items
        block = match.group(1)
        for raw in re.findall(r"['\"]([^'\"]+)['\"]", block):
            item = self._dependency_from_spec(raw, path, "install_requires")
            if item:
                items.append(item)
        return items

    def _parse_setup_cfg(self, path: Path) -> list[DependencyItem]:
        config = configparser.ConfigParser()
        config.read(path, encoding="utf-8")
        items: list[DependencyItem] = []
        if not config.has_section("options"):
            return items
        install_requires = config.get("options", "install_requires", fallback="")
        for line_no, line in enumerate(install_requires.splitlines(), start=1):
            raw = line.strip()
            if not raw:
                continue
            item = self._dependency_from_spec(raw, path, f"options.install_requires:{line_no}")
            if item:
                items.append(item)
        return items

    def _dependency_from_spec(
        self, spec: str, path: Path, evidence: str
    ) -> DependencyItem | None:
        spec = spec.strip()
        match = PEP508_NAME.match(spec)
        if not match:
            return None
        name = normalize_name(match.group(1))
        remainder = spec[len(match.group(1)) :].strip()
        version = strip_version_operators(remainder) if remainder else None
        return DependencyItem(
            name=name,
            version=version,
            package_type=PackageType.PYPI.value,
            source=str(path),
            evidence=evidence,
            raw=spec,
        )
