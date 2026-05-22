from __future__ import annotations

import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from pathlib import Path

from misteye_depscan.api import (
    API_STATUS_MALICIOUS,
    API_STATUS_UNKNOWN,
    MistEyeAPIError,
    MistEyeClient,
    parse_detect_response,
)
from misteye_depscan.models import DependencyItem, DetectionResult, ScanReport, ScanStatus
from misteye_depscan.terminal import DIM, colorize, format_progress_result


class ScanCache:
    def __init__(self, cache_dir: Path | None = None) -> None:
        self.cache_dir = cache_dir or Path.home() / ".cache" / "misteye-depscan"
        self._memory: dict[str, DetectionResult] = {}
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache_key(self, dependency: DependencyItem) -> str:
        raw = f"{dependency.package_type}|{dependency.api_target.lower()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get(self, dependency: DependencyItem) -> DetectionResult | None:
        key = self._cache_key(dependency)
        if key in self._memory:
            return self._memory[key]
        path = self.cache_dir / f"{key}.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            result = _result_from_cache(dependency, data)
            self._memory[key] = result
            return result
        except (json.JSONDecodeError, OSError, KeyError):
            return None

    def set(self, result: DetectionResult) -> None:
        key = self._cache_key(result.dependency)
        self._memory[key] = result
        path = self.cache_dir / f"{key}.json"
        payload = {
            "api_status": result.api_status,
            "matches": result.matches,
            "status": result.status.value,
            "error": result.error,
            "cached_at": int(time.time()),
        }
        path.write_text(json.dumps(payload), encoding="utf-8")


def _result_from_cache(dependency: DependencyItem, data: dict) -> DetectionResult:
    status_value = data.get("status", ScanStatus.UNKNOWN.value)
    if status_value == "no_match":
        status_value = ScanStatus.UNKNOWN.value
    api_status = data.get("api_status")
    if api_status is None and "safe" in data:
        api_status = API_STATUS_UNKNOWN if data.get("safe") else API_STATUS_MALICIOUS
    return DetectionResult(
        dependency=dependency,
        api_status=api_status,
        matches=data.get("matches") or [],
        status=ScanStatus(status_value),
        error=data.get("error"),
    )


class DependencyScanner:
    def __init__(
        self,
        client: MistEyeClient,
        *,
        workers: int = 4,
        use_cache: bool = True,
        show_progress: bool = True,
    ) -> None:
        self.client = client
        self.workers = max(1, workers)
        self.cache = ScanCache() if use_cache else None
        self.show_progress = show_progress

    def scan_dependencies(self, dependencies: list[DependencyItem]) -> ScanReport:
        report = ScanReport(dependency_count=len(dependencies))
        if not dependencies:
            return report

        results: list[DetectionResult] = []
        total = len(dependencies)
        completed = 0

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {
                executor.submit(self._scan_one, dependency): dependency
                for dependency in dependencies
            }
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                completed += 1
                if self.show_progress:
                    print(self._format_progress_line(completed, total, result), flush=True)

        report.results = sorted(
            results,
            key=lambda item: (item.status != ScanStatus.MALICIOUS, item.dependency.name),
        )
        report.scanned_count = sum(
            1 for item in results if item.status in {ScanStatus.MALICIOUS, ScanStatus.UNKNOWN}
        )
        report.malicious_count = sum(1 for item in results if item.status == ScanStatus.MALICIOUS)
        report.error_count = sum(1 for item in results if item.status == ScanStatus.ERROR)
        report.no_check_count = sum(1 for item in results if item.status == ScanStatus.NO_CHECK)
        if report.scanned_count < report.dependency_count:
            report.degraded = True
            report.warnings.append(
                "Coverage insufficient: scanned_count < dependency_count."
            )
        return report

    @staticmethod
    def _format_progress_line(
        completed: int, total: int, result: DetectionResult
    ) -> str:
        target = result.dependency.target
        cache_tag = colorize(" [cached]", DIM) if result.from_cache else ""
        severity = None
        if result.status == ScanStatus.MALICIOUS and result.matches:
            severity = str(result.matches[0].get("severity") or "")
        detail = format_progress_result(
            result.status,
            severity=severity or None,
            error=result.error,
        )
        prefix = colorize(f"[{completed}/{total}]", DIM)
        return f"{prefix} {target} → {detail}{cache_tag}"

    def _scan_one(self, dependency: DependencyItem) -> DetectionResult:
        if not dependency.name:
            return DetectionResult(
                dependency=dependency,
                api_status=None,
                status=ScanStatus.NO_CHECK,
                error="Empty dependency name.",
            )

        if self.cache:
            cached = self.cache.get(dependency)
            if cached is not None:
                return replace(cached, from_cache=True)

        try:
            response = self.client.detect(dependency.api_target, dependency.package_type)
        except MistEyeAPIError as exc:
            result = DetectionResult(
                dependency=dependency,
                api_status=None,
                status=ScanStatus.ERROR,
                error=str(exc),
            )
            return result

        try:
            api_status, matches = parse_detect_response(response)
        except MistEyeAPIError as exc:
            return DetectionResult(
                dependency=dependency,
                api_status=None,
                matches=response.get("matches") or [],
                status=ScanStatus.ERROR,
                error=str(exc),
            )

        if api_status == API_STATUS_MALICIOUS or matches:
            status = ScanStatus.MALICIOUS
        elif api_status == API_STATUS_UNKNOWN:
            status = ScanStatus.UNKNOWN
        else:
            return DetectionResult(
                dependency=dependency,
                api_status=api_status,
                matches=matches,
                status=ScanStatus.ERROR,
                error=f"Unexpected API status: {api_status}",
            )

        result = DetectionResult(
            dependency=dependency,
            api_status=api_status,
            matches=matches,
            status=status,
        )
        if self.cache:
            self.cache.set(result)
        return result
