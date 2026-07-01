from __future__ import annotations

import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

logger = logging.getLogger(__name__)

from misteye_depscan.exceptions import ScanInterrupted
from misteye_depscan.api import (
    API_STATUS_MALICIOUS,
    API_STATUS_UNKNOWN,
    MistEyeAPIError,
    MistEyeClient,
    build_search_url,
    parse_detect_response,
)
from misteye_depscan.intel import display_severity, stale_intel_hint
from misteye_depscan.models import DependencyItem, DetectionResult, ScanReport, ScanStatus
from misteye_depscan.terminal import DIM, YELLOW, colorize, format_progress_result, hyperlink


class DependencyScanner:
    def __init__(
        self,
        client: MistEyeClient,
        *,
        workers: int = 4,
        show_progress: bool = True,
        progress_callback: Callable[[int, int, DetectionResult], None] | None = None,
    ) -> None:
        self.client = client
        self.workers = max(1, workers)
        self.show_progress = show_progress
        # When set, the callback receives (completed, total, result) for each
        # finished package and takes over presentation (e.g. live dashboard);
        # the inline progress line is then suppressed.
        self.progress_callback = progress_callback

    def scan_dependencies(
        self,
        dependencies: list[DependencyItem],
        *,
        retry_errors: bool = True,
        on_retry_begin: Callable[[int], None] | None = None,
        on_retry_progress: Callable[[int, int, DetectionResult], None] | None = None,
    ) -> ScanReport:
        if not dependencies:
            return ScanReport(dependency_count=0)

        results = self._run_scan_batch(dependencies, workers=self.workers)

        if retry_errors:
            failed = [item for item in results if item.status == ScanStatus.ERROR]
            if failed:
                if on_retry_begin is not None:
                    try:
                        on_retry_begin(len(failed))
                    except Exception as exc:
                        logger.warning("Retry begin callback failed: %s", exc)
                        print(
                            f"Retry begin callback failed: {exc}",
                            file=sys.stderr,
                            flush=True,
                        )

                retry_deps = [item.dependency for item in failed]
                retry_results = self._run_scan_batch(
                    retry_deps,
                    workers=1,
                    progress_callback=on_retry_progress,
                    progress_tag="retry",
                )
                retry_map = {item.dependency.key: item for item in retry_results}
                results = [
                    retry_map.get(item.dependency.key, item)
                    if item.status == ScanStatus.ERROR
                    else item
                    for item in results
                ]

                recovered = sum(
                    1
                    for item in failed
                    if retry_map.get(item.dependency.key, item).status != ScanStatus.ERROR
                )
                still_failed = len(failed) - recovered
                report = self._build_report(results, len(dependencies))
                report.info.append(
                    f"Retried {len(failed)} failed package(s); "
                    f"{recovered} recovered, {still_failed} still failed."
                )
                return report

        return self._build_report(results, len(dependencies))

    def _run_scan_batch(
        self,
        dependencies: list[DependencyItem],
        *,
        workers: int | None = None,
        progress_callback: Callable[[int, int, DetectionResult], None] | None = None,
        progress_tag: str | None = None,
    ) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        total = len(dependencies)
        completed = 0
        callback = (
            progress_callback
            if progress_callback is not None
            else self.progress_callback
        )
        show_progress = self.show_progress if callback is None else False
        pool_workers = self.workers if workers is None else max(1, workers)

        executor = ThreadPoolExecutor(max_workers=pool_workers)
        futures = {
            executor.submit(self._scan_one, dependency): dependency
            for dependency in dependencies
        }
        try:
            for future in as_completed(futures):
                dependency = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    logger.warning(
                        "Unexpected error scanning %s: %s",
                        dependency.target,
                        exc,
                    )
                    result = DetectionResult(
                        dependency=dependency,
                        api_status=None,
                        status=ScanStatus.ERROR,
                        error=str(exc),
                    )
                results.append(result)
                completed += 1
                if callback is not None:
                    try:
                        callback(completed, total, result)
                    except Exception as exc:
                        logger.warning("Progress callback failed: %s", exc)
                        print(
                            f"Progress callback failed: {exc}",
                            file=sys.stderr,
                            flush=True,
                        )
                elif show_progress:
                    print(
                        self._format_progress_line(
                            completed,
                            total,
                            result,
                            tag=progress_tag,
                        ),
                        flush=True,
                    )
        except KeyboardInterrupt:
            for pending in futures:
                pending.cancel()
            raise ScanInterrupted(completed, total) from None
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        return results

    @staticmethod
    def _build_report(results: list[DetectionResult], dependency_count: int) -> ScanReport:
        report = ScanReport(dependency_count=dependency_count)
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
        completed: int,
        total: int,
        result: DetectionResult,
        *,
        tag: str | None = None,
    ) -> str:
        dep = result.dependency
        target = dep.target
        severity = None
        stale_hint = None
        if result.status == ScanStatus.MALICIOUS and result.matches:
            primary = result.matches[0]
            severity = display_severity(primary)
            stale_hint = stale_intel_hint(primary)
        detail = format_progress_result(
            result.status,
            severity=severity or None,
            error=result.error,
        )
        if stale_hint:
            detail += colorize(f" · {stale_hint}", YELLOW)
        label = f"{tag} {completed}/{total}" if tag else f"{completed}/{total}"
        prefix = colorize(f"[{label}]", DIM)
        line = f"{prefix} {target} → {detail}"
        if result.status == ScanStatus.MALICIOUS:
            line += f"\n       Source: {dep.source}"
            url = build_search_url(dep.api_target, dep.package_type)
            line += "\n       Detail: " + hyperlink(url, url)
        return line

    def _scan_one(self, dependency: DependencyItem) -> DetectionResult:
        if not dependency.name:
            return DetectionResult(
                dependency=dependency,
                api_status=None,
                status=ScanStatus.NO_CHECK,
                error="Empty dependency name.",
            )

        try:
            response = self.client.detect(dependency.api_target, dependency.package_type)
        except MistEyeAPIError as exc:
            return DetectionResult(
                dependency=dependency,
                api_status=None,
                status=ScanStatus.ERROR,
                error=str(exc),
            )

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

        # Cross-ecosystem guard: only matches whose ``type`` agrees with what
        # we sent count as a real hit. The MistEye intel DB may contain a
        # package with the same name in another ecosystem (e.g. npm and PyPI
        # both have a package called ``loguru``); treating that as a hit for
        # the wrong ecosystem produces false positives.
        requested_type = dependency.package_type
        filtered_matches = [
            m for m in matches if m.get("type") == requested_type
        ]
        dropped = len(matches) - len(filtered_matches)
        matches = filtered_matches

        if matches:
            status = ScanStatus.MALICIOUS
        elif api_status == API_STATUS_MALICIOUS:
            # API said malicious, but every match was for another ecosystem.
            # Demote to unknown so we don't false-positive on this dependency.
            status = ScanStatus.UNKNOWN
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

        error: str | None = None
        if dropped and status == ScanStatus.UNKNOWN:
            error = (
                f"Ignored {dropped} match(es) from other ecosystem(s); "
                f"only {requested_type} matches count for this dependency."
            )

        return DetectionResult(
            dependency=dependency,
            api_status=api_status,
            matches=matches,
            status=status,
            error=error,
        )
