from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from misteye_depscan.models import DetectionResult, ScanReport, ScanStatus
from misteye_depscan.terminal import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    RED,
    YELLOW,
    colorize,
    format_status,
    format_summary_value,
    status_label,
)


def render_report(report: ScanReport, *, output_format: str = "table") -> str:
    if output_format == "json":
        return render_json(report)
    if output_format == "sarif":
        return render_sarif(report)
    return render_table(report)


def _format_match_detail(match: dict) -> str:
    parts = [
        f"severity={match.get('severity')}",
        f"type={match.get('type')}",
    ]
    ioc = match.get("indicator") or match.get("value")
    if ioc:
        parts.append(f"indicator={ioc}")
    threat_type = match.get("threat_type")
    if threat_type:
        parts.append(f"threat_type={threat_type}")
    confidence = match.get("confidence")
    if confidence is not None:
        parts.append(f"confidence={confidence}")
    return " ".join(parts)


def render_table(report: ScanReport) -> str:
    title = colorize("MistEye DepScan Report", f"{BOLD}{CYAN}")
    unknown_count = sum(1 for item in report.results if item.status == ScanStatus.UNKNOWN)

    lines = [
        title,
        format_summary_value("Dependencies", report.dependency_count, CYAN),
        format_summary_value("Scanned", report.scanned_count, CYAN),
        colorize(f"Threat detected: {report.malicious_count}", RED)
        if report.malicious_count
        else f"Threat detected: {report.malicious_count}",
        colorize(f"No threat record: {unknown_count}", GREEN)
        if unknown_count
        else f"No threat record: {unknown_count}",
        f"Check failed: {report.error_count}",
        "",
    ]
    if report.warnings:
        lines.append(colorize("Warnings:", YELLOW))
        for warning in report.warnings:
            lines.append(f"  - {warning}")
        lines.append("")

    if not report.results:
        lines.append("No scannable dependencies found.")
        return "\n".join(lines)

    if unknown_count:
        lines.append(
            colorize(
                "Note: \"No threat record\" means no match in MistEye intel; it does not guarantee the package is safe.",
                DIM,
            )
        )
        lines.append("")

    header_status = colorize("Status", BOLD)
    lines.append(f"{header_status:<16} {'Package':<40} {'Source':<28} Evidence")
    lines.append(colorize("-" * 110, DIM))
    for result in report.results:
        target = result.dependency.target
        status_col = format_status(result.status, bold=True)
        source_display = Path(result.dependency.source).name
        lines.append(
            f"{status_col:<24} {target[:40]:<40} {source_display[:28]:<28} {result.dependency.evidence}"
        )
        if result.status == ScanStatus.MALICIOUS and result.matches:
            for match in result.matches[:3]:
                lines.append(colorize(f"           {_format_match_detail(match)}", RED))
        elif result.error:
            lines.append(colorize(f"           {result.error}", YELLOW))
    return "\n".join(lines)


def render_json(report: ScanReport) -> str:
    payload = {
        "summary": {
            "dependency_count": report.dependency_count,
            "scanned_count": report.scanned_count,
            "malicious_count": report.malicious_count,
            "unknown_count": sum(
                1 for item in report.results if item.status == ScanStatus.UNKNOWN
            ),
            "error_count": report.error_count,
            "no_check_count": report.no_check_count,
            "degraded": report.degraded,
            "exit_code": report.exit_code,
        },
        "warnings": report.warnings,
        "results": [_result_to_dict(result) for result in report.results],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _result_to_dict(result: DetectionResult) -> dict:
    return {
        "status": result.status.value,
        "status_label": status_label(result.status),
        "api_status": result.api_status,
        "target": result.dependency.target,
        "package_type": result.dependency.package_type,
        "source": result.dependency.source,
        "evidence": result.dependency.evidence,
        "raw": result.dependency.raw,
        "matches": result.matches,
        "error": result.error,
    }


def render_sarif(report: ScanReport) -> str:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for index, item in enumerate(
        [result for result in report.results if result.status == ScanStatus.MALICIOUS],
        start=1,
    ):
        rule_id = f"misteye/malicious-package/{index}"
        rules[rule_id] = {
            "id": rule_id,
            "name": "MaliciousPackage",
            "shortDescription": {"text": "Malicious dependency detected by MistEye"},
            "fullDescription": {"text": "A dependency matched MistEye threat intelligence."},
            "defaultConfiguration": {"level": "error"},
        }
        results.append(
            {
                "ruleId": rule_id,
                "level": "error",
                "message": {
                    "text": f"Malicious dependency detected: {item.dependency.target}",
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": item.dependency.source},
                        }
                    }
                ],
            }
        )

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "misteye-depscan",
                        "informationUri": "https://app.misteye.io/api-docs",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": report.error_count == 0,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)
