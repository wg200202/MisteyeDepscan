"""Collect macOS / system-level global Python and npm packages (not project venv)."""

from __future__ import annotations

import json
from pathlib import Path

from misteye_depscan.collectors.base import GlobalCollector, run_command
from misteye_depscan.models import DependencyItem, PackageType

_VENV_MARKERS = (".venv", "venv", "virtualenv", "/envs/", "/node_modules/")


def _is_venv_python(python: Path) -> bool:
    result = run_command(
        [
            str(python),
            "-c",
            "import sys; raise SystemExit(1 if sys.prefix != sys.base_prefix else 0)",
        ],
        timeout=15.0,
    )
    return result is not None and result.returncode == 1


def _should_skip_python_path(path: Path) -> bool:
    text = str(path).lower()
    return any(marker in text for marker in _VENV_MARKERS)


def discover_system_python_binaries() -> list[tuple[str, Path]]:
    """Find system/Homebrew Python interpreters, excluding venv shims."""
    found: list[tuple[str, Path]] = []
    seen: set[str] = set()

    def add(label: str, path: Path) -> None:
        resolved = str(path.resolve())
        if resolved in seen or _should_skip_python_path(path):
            return
        if _is_venv_python(path):
            return
        seen.add(resolved)
        found.append((label, path))

    for path_str, label in (
        ("/opt/homebrew/bin/python3", "homebrew"),
        ("/usr/local/bin/python3", "usr-local"),
        ("/usr/bin/python3", "system"),
    ):
        path = Path(path_str)
        if path.exists():
            add(label, path)

    framework_root = Path("/Library/Frameworks/Python.framework/Versions")
    if framework_root.exists():
        for version_dir in sorted(framework_root.iterdir()):
            if not version_dir.is_dir() or version_dir.name.startswith("."):
                continue
            python_bin = version_dir / "bin" / "python3"
            if python_bin.exists():
                add(f"python-framework-{version_dir.name}", python_bin)

    which = run_command(["/usr/bin/which", "-a", "python3"])
    if which and which.returncode == 0:
        for line in which.stdout.splitlines():
            path = Path(line.strip())
            if path.exists():
                add(f"which:{path.parent.name}", path)

    return found


def _pip_list_packages(python: Path, source: str, evidence: str) -> list[DependencyItem]:
    result = run_command([str(python), "-m", "pip", "list", "--format=json"])
    if result is None or result.returncode != 0:
        return []
    try:
        packages = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        return []
    items: list[DependencyItem] = []
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
                source=source,
                evidence=evidence,
                raw=f"{name}=={version}" if version else name,
            )
        )
    return items


class SystemPythonCollector(GlobalCollector):
    """macOS system / Homebrew Python global site-packages (not active project venv)."""

    name = "system-python"

    def collect(self) -> list[DependencyItem]:
        items: list[DependencyItem] = []
        for label, python in discover_system_python_binaries():
            source = f"python:{label}"
            evidence = f"{python} -m pip list --format=json"
            items.extend(_pip_list_packages(python, source, evidence))
        return items


def _npm_global_root() -> Path | None:
    result = run_command(["npm", "root", "-g"])
    if result is None or result.returncode != 0:
        return None
    root = Path(result.stdout.strip())
    return root if root.exists() else None


def _collect_node_modules(root: Path, source: str) -> list[DependencyItem]:
    items: list[DependencyItem] = []
    if not root.exists():
        return items
    for package_json in list(root.glob("*/package.json")) + list(root.glob("@*/*/package.json")):
        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        name = str(data.get("name") or package_json.parent.name).strip()
        version = str(data.get("version") or "").strip() or None
        if not name:
            continue
        items.append(
            DependencyItem(
                name=name,
                version=version,
                package_type=PackageType.NPM.value,
                source=source,
                evidence=str(package_json),
                raw=f"{name}@{version}" if version else name,
            )
        )
    return items


class NpmGlobalRootCollector(GlobalCollector):
    """npm install -g packages via `npm root -g` (true global prefix on Mac)."""

    name = "npm-global"

    def collect(self) -> list[DependencyItem]:
        items: list[DependencyItem] = []
        root = _npm_global_root()
        if root:
            items.extend(_collect_node_modules(root, source="npm-global"))

        result = run_command(["npm", "list", "-g", "--json", "--depth=0"])
        if result is not None and result.returncode in (0, 1):
            try:
                data = json.loads(result.stdout or "{}")
                deps = (data.get("dependencies") or {}) if isinstance(data, dict) else {}
                seen = {(i.name.lower(), i.version) for i in items}
                for name, meta in deps.items():
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
                            source="npm-global",
                            evidence="npm list -g --json --depth=0",
                            raw=f"{name}@{version}" if version else name,
                        )
                    )
            except json.JSONDecodeError:
                pass
        return items
