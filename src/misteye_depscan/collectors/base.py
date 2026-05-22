from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod

from misteye_depscan.models import DependencyItem


class GlobalCollector(ABC):
    name: str
    enabled: bool = True

    @abstractmethod
    def collect(self) -> list[DependencyItem]:
        raise NotImplementedError


def run_command(args: list[str], *, timeout: float = 60.0) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
