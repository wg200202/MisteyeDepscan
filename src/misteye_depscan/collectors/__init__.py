from __future__ import annotations

import json
import os
import re
from pathlib import Path

from misteye_depscan.collectors.base import GlobalCollector, run_command
from misteye_depscan.collectors.cargo_global import CargoInstallCollector, collect_cargo_install_global
from misteye_depscan.collectors.go_global import GoInstallCollector, collect_go_install_global
from misteye_depscan.collectors.mac_global import (
    NpmGlobalRootCollector,
    SystemPythonCollector,
    collect_node_modules,
    discover_pnpm_global_roots,
)
from misteye_depscan.models import DependencyItem, PackageType
from misteye_depscan.parsers import dedupe_dependencies


class PipxCollector(GlobalCollector):
    name = "pipx"

    def collect(self) -> list[DependencyItem]:
        result = run_command(["pipx", "list", "--json"])
        if result is None or result.returncode != 0:
            return []
        try:
            data = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            return []
        items: list[DependencyItem] = []
        for app in (data.get("venvs") or {}).values():
            for pkg in app.get("packages", {}).values():
                name = str(pkg.get("package_name") or pkg.get("package") or "").strip()
                version = str(pkg.get("package_version") or pkg.get("version") or "").strip() or None
                if name:
                    items.append(
                        DependencyItem(
                            name=name,
                            version=version,
                            package_type=PackageType.PYPI.value,
                            source="pipx",
                            evidence="pipx list --json",
                            raw=f"{name}=={version}" if version else name,
                        )
                    )
        return items


class PyenvCollector(GlobalCollector):
    name = "pyenv"

    def collect(self) -> list[DependencyItem]:
        root = Path.home() / ".pyenv" / "versions"
        if not root.exists():
            return []
        items: list[DependencyItem] = []
        for version_dir in root.iterdir():
            if not version_dir.is_dir():
                continue
            python_bin = version_dir / "bin" / "python"
            if not python_bin.exists():
                continue
            result = run_command([str(python_bin), "-m", "pip", "list", "--format=json"])
            if result is None or result.returncode != 0:
                continue
            try:
                packages = json.loads(result.stdout or "[]")
            except json.JSONDecodeError:
                continue
            for pkg in packages:
                name = str(pkg.get("name", "")).strip()
                version = str(pkg.get("version", "")).strip() or None
                if not name:
                    continue
                items.append(
                    DependencyItem(
                        name=name,
                        version=version,
                        package_type=PackageType.PYPI.value,
                        source=f"pyenv:{version_dir.name}",
                        evidence=f"{python_bin} -m pip list",
                        raw=f"{name}=={version}" if version else name,
                    )
                )
        return items


class CondaCollector(GlobalCollector):
    name = "conda"

    def collect(self) -> list[DependencyItem]:
        result = run_command(["conda", "list", "--json"])
        if result is None or result.returncode != 0:
            return []
        try:
            packages = json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            return []
        items: list[DependencyItem] = []
        for pkg in packages:
            if pkg.get("channel") == "pypi":
                name = str(pkg.get("name", "")).strip()
                version = str(pkg.get("version", "")).strip() or None
                if name:
                    items.append(
                        DependencyItem(
                            name=name,
                            version=version,
                            package_type=PackageType.PYPI.value,
                            source="conda",
                            evidence="conda list --json",
                            raw=f"{name}=={version}" if version else name,
                        )
                    )
        return items


class PnpmGlobalCollector(GlobalCollector):
    name = "pnpm-global"

    def collect(self) -> list[DependencyItem]:
        items: list[DependencyItem] = []
        seen: set[tuple[str, str | None]] = set()
        for root in discover_pnpm_global_roots():
            for item in _collect_node_modules(root, source="pnpm-global"):
                key = (item.name.lower(), item.version)
                if key in seen:
                    continue
                seen.add(key)
                items.append(item)

        result = run_command(["pnpm", "list", "-g", "--json", "--depth=0"])
        if result is None or result.returncode != 0:
            return items
        try:
            data = json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            return items
        if isinstance(data, dict):
            data = [data]
        for entry in data:
            for name, meta in (entry.get("dependencies") or {}).items():
                version = None
                if isinstance(meta, dict):
                    version = str(meta.get("version") or "").strip() or None
                key = (name.lower(), version)
                if key in seen:
                    continue
                seen.add(key)
                items.append(
                    DependencyItem(
                        name=name,
                        version=version,
                        package_type=PackageType.NPM.value,
                        source="pnpm-global",
                        evidence="pnpm list -g --json --depth=0",
                        raw=f"{name}@{version}" if version else name,
                    )
                )
        return items


class YarnGlobalCollector(GlobalCollector):
    name = "yarn-global"

    def collect(self) -> list[DependencyItem]:
        result = run_command(["yarn", "global", "list", "--depth=0"])
        if result is None or result.returncode != 0:
            return []
        items: list[DependencyItem] = []
        for line in (result.stdout or "").splitlines():
            match = re.search(r"(\S+)@(\S+)", line)
            if match:
                items.append(
                    DependencyItem(
                        name=match.group(1),
                        version=match.group(2),
                        package_type=PackageType.NPM.value,
                        source="yarn-global",
                        evidence="yarn global list --depth=0",
                        raw=line.strip(),
                    )
                )
        return items


def _collect_node_modules(root: Path, source: str) -> list[DependencyItem]:
    return collect_node_modules(root, source)


class NvmCollector(GlobalCollector):
    name = "nvm"

    def collect(self) -> list[DependencyItem]:
        nvm_dir = Path(os.environ.get("NVM_DIR", Path.home() / ".nvm"))
        root = nvm_dir / "versions" / "node"
        items: list[DependencyItem] = []
        if not root.exists():
            return items
        for node_version in root.iterdir():
            modules = node_version / "lib" / "node_modules"
            items.extend(_collect_node_modules(modules, source=f"nvm:{node_version.name}"))
        return items


class FnmCollector(GlobalCollector):
    name = "fnm"

    def collect(self) -> list[DependencyItem]:
        root = Path.home() / ".fnm" / "node-versions"
        items: list[DependencyItem] = []
        if not root.exists():
            return items
        for node_version in root.iterdir():
            modules = node_version / "installation" / "lib" / "node_modules"
            items.extend(_collect_node_modules(modules, source=f"fnm:{node_version.name}"))
        return items


class VoltaCollector(GlobalCollector):
    name = "volta"

    def collect(self) -> list[DependencyItem]:
        tools = Path.home() / ".volta" / "tools" / "image" / "packages"
        items: list[DependencyItem] = []
        if not tools.exists():
            return items
        for package_dir in tools.iterdir():
            if not package_dir.is_dir():
                continue
            for version_dir in package_dir.iterdir():
                package_json = version_dir / "package" / "package.json"
                if not package_json.exists():
                    continue
                try:
                    data = json.loads(package_json.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    continue
                name = str(data.get("name") or package_dir.name).strip()
                version = str(data.get("version") or version_dir.name).strip() or None
                items.append(
                    DependencyItem(
                        name=name,
                        version=version,
                        package_type=PackageType.NPM.value,
                        source="volta",
                        evidence=str(package_json),
                        raw=f"{name}@{version}" if version else name,
                    )
                )
        return items


PYTHON_GLOBAL_COLLECTOR_NAMES = frozenset({"system-python", "pipx"})
NODE_GLOBAL_COLLECTOR_NAMES = frozenset(
    {"npm-global", "pnpm-global", "yarn-global", "nvm", "fnm", "volta"}
)
RUST_GLOBAL_COLLECTOR_NAMES = frozenset({"cargo-install"})
GO_GLOBAL_COLLECTOR_NAMES = frozenset({"go-global"})

# Default: macOS system Python + all common Node global install locations.
DEFAULT_GLOBAL_COLLECTORS: list[GlobalCollector] = [
    SystemPythonCollector(),
    PipxCollector(),
    NpmGlobalRootCollector(),
    PnpmGlobalCollector(),
    YarnGlobalCollector(),
    NvmCollector(),
    FnmCollector(),
    VoltaCollector(),
    CargoInstallCollector(),
    GoInstallCollector(),
]

# Backward-compatible alias
MAC_GLOBAL_COLLECTORS = DEFAULT_GLOBAL_COLLECTORS

# Optional: pyenv / conda (many duplicate packages; not enabled by default)
EXTENDED_ENV_COLLECTORS: list[GlobalCollector] = [
    PyenvCollector(),
    CondaCollector(),
]

OPTIONAL_COLLECTORS: list[GlobalCollector] = []


def collect_global_dependencies(
    *,
    python_only: bool = False,
    node_only: bool = False,
    rust_only: bool = False,
    go_only: bool = False,
) -> tuple[list[DependencyItem], list[str]]:
    collectors = list(DEFAULT_GLOBAL_COLLECTORS)

    if python_only:
        collectors = [c for c in collectors if c.name in PYTHON_GLOBAL_COLLECTOR_NAMES]
    elif node_only:
        collectors = [c for c in collectors if c.name in NODE_GLOBAL_COLLECTOR_NAMES]
    elif rust_only:
        collectors = [c for c in collectors if c.name in RUST_GLOBAL_COLLECTOR_NAMES]
    elif go_only:
        collectors = [c for c in collectors if c.name in GO_GLOBAL_COLLECTOR_NAMES]

    items: list[DependencyItem] = []
    warnings: list[str] = []
    for collector in collectors:
        try:
            if collector.name == "cargo-install":
                collected, cargo_warnings = collect_cargo_install_global()
                warnings.extend(cargo_warnings)
            elif collector.name == "go-global":
                collected, go_warnings = collect_go_install_global()
                warnings.extend(go_warnings)
            else:
                collected = collector.collect()
            if collected:
                items.extend(collected)
            elif collector.name not in {"cargo-install", "go-global"}:
                warnings.append(f"No packages found via {collector.name}.")
        except Exception as exc:  # noqa: BLE001 - collector failures should not abort scan
            warnings.append(f"{collector.name} failed: {exc}")
    return dedupe_dependencies(items), warnings
