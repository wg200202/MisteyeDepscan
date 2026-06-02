from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PackageType(str, Enum):
    PYPI = "package:pypi"
    NPM = "package:npm"
    NUGET = "package:nuget"
    RUBYGEMS = "package:rubygems"
    GO = "package:go"
    CRATESIO = "package:cratesio"


class ScanStatus(str, Enum):
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"
    ERROR = "error"
    NO_CHECK = "no_check"


@dataclass(frozen=True)
class DependencyItem:
    name: str
    version: str | None
    package_type: str
    source: str
    evidence: str
    raw: str = ""

    @property
    def target(self) -> str:
        """Canonical label: PyPI uses ``name==version``; other ecosystems use ``name@version``."""
        if not self.version:
            return self.name
        if self.package_type == PackageType.PYPI.value:
            return f"{self.name}=={self.version}"
        return f"{self.name}@{self.version}"

    @property
    def api_target(self) -> str:
        """Target string sent to MistEye detect API (same format as ``target``)."""
        return self.target

    @property
    def key(self) -> tuple[str, str | None, str]:
        return (self.package_type, self.version, self.name.lower())


@dataclass
class DetectionResult:
    dependency: DependencyItem
    api_status: str | None
    matches: list[dict[str, Any]] = field(default_factory=list)
    status: ScanStatus = ScanStatus.NO_CHECK
    error: str | None = None


@dataclass
class ScanReport:
    results: list[DetectionResult] = field(default_factory=list)
    dependency_count: int = 0
    scanned_count: int = 0
    malicious_count: int = 0
    error_count: int = 0
    no_check_count: int = 0
    degraded: bool = False
    warnings: list[str] = field(default_factory=list)
    info: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return self.scanned_count >= self.dependency_count and self.error_count == 0

    @property
    def exit_code(self) -> int:
        if self.malicious_count > 0:
            return 1
        if self.error_count > 0 or self.no_check_count > 0 or not self.complete:
            return 2
        return 0
