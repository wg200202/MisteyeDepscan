from __future__ import annotations

import argparse
import sys
from pathlib import Path

from misteye_depscan import __version__
from misteye_depscan.banner import print_banner
from misteye_depscan.api import MistEyeClient
from misteye_depscan.collectors import collect_global_dependencies
from misteye_depscan.config import ensure_api_key, load_api_key, prompt_and_save_api_key
from misteye_depscan.models import DependencyItem, PackageType
from misteye_depscan.ecosystems import parse_ecosystem_option
from misteye_depscan.parsers import collect_project_dependencies
from misteye_depscan.report import render_report
from misteye_depscan.scanner import DependencyScanner
from misteye_depscan.terminal import run_with_progress, set_color_enabled


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="depscan",
        description="Scan project and global dependencies with MistEye threat intelligence.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored terminal output.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan dependencies in a project path.")
    scan_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Project directory to scan (default: current directory).",
    )
    scan_parser.add_argument("--json", action="store_true", help="Output JSON report.")
    scan_parser.add_argument("--sarif", action="store_true", help="Output SARIF report.")
    scan_parser.add_argument(
        "--include-optional",
        action="store_true",
        help="Include optional ecosystems (Go/Rust/Ruby/.NET).",
    )
    scan_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Hide scan progress output.",
    )
    scan_parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Save full scan report as JSON to this file.",
    )
    scan_parser.add_argument(
        "--ecosystem",
        metavar="ECOSYSTEM",
        help="Ecosystems to scan: npm, pypi, all, or comma-separated (default: auto-detect).",
    )
    scan_parser.add_argument(
        "--no-node-modules",
        action="store_true",
        help="Do not scan installed packages under node_modules/.",
    )
    scan_parser.add_argument(
        "--depth",
        type=int,
        default=10,
        metavar="N",
        help="Max directory depth to scan (default: 10). Use 0 for unlimited.",
    )

    global_parser = subparsers.add_parser("global", help="Scan globally installed packages.")
    global_parser.add_argument("--json", action="store_true", help="Output JSON report.")
    global_parser.add_argument("--sarif", action="store_true", help="Output SARIF report.")
    global_parser.add_argument(
        "--python-only",
        action="store_true",
        help="Scan only Python global environments.",
    )
    global_parser.add_argument(
        "--node-only",
        action="store_true",
        help="Scan only Node.js global environments.",
    )
    global_parser.add_argument("--quiet", action="store_true", help="Hide scan progress output.")
    global_parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Save full scan report as JSON to this file.",
    )

    check_parser = subparsers.add_parser("check", help="Check a single package.")
    check_parser.add_argument("package", help="Package target, e.g. requests@2.32.3")
    check_parser.add_argument("--npm", action="store_true", help="Treat package as npm.")
    check_parser.add_argument("--pypi", action="store_true", help="Treat package as PyPI.")
    check_parser.add_argument("--json", action="store_true", help="Output JSON report.")
    check_parser.add_argument("--sarif", action="store_true", help="Output SARIF report.")
    check_parser.add_argument("--quiet", action="store_true", help="Hide scan progress output.")

    return parser


def parse_package_ref(package: str, *, npm: bool = False, pypi: bool = False) -> DependencyItem:
    if npm and pypi:
        raise SystemExit("Use only one of --npm or --pypi.")

    if npm or (not pypi and package.startswith("@")):
        package_type = PackageType.NPM.value
    elif pypi:
        package_type = PackageType.PYPI.value
    else:
        package_type = PackageType.PYPI.value

    if "==" in package:
        name, version = package.split("==", 1)
    elif "@" in package:
        name, version = package.rsplit("@", 1)
    else:
        name, version = package, None

    return DependencyItem(
        name=name.strip(),
        version=version.strip() if version else None,
        package_type=package_type,
        source="manual-check",
        evidence="depscan check",
        raw=package,
    )


def _print_discovered_files(root: Path, files: list[Path]) -> None:
    if not files:
        print("No dependency files found.", file=sys.stderr)
        return

    from collections import defaultdict

    nm_files: list[Path] = []
    manifest_files: list[Path] = []
    for f in files:
        (nm_files if "node_modules" in f.parts else manifest_files).append(f)

    print(f"Discovered {len(files)} dependency file(s):", file=sys.stderr)
    for f in manifest_files:
        try:
            rel = f.relative_to(root)
        except ValueError:
            rel = f
        print(f"  {rel}", file=sys.stderr)

    if nm_files:
        groups: dict[Path, int] = defaultdict(int)
        for f in nm_files:
            parts = f.parts
            try:
                idx = parts.index("node_modules")
            except ValueError:
                continue
            groups[Path(*parts[: idx + 1])] += 1
        for nm_dir, count in sorted(groups.items()):
            try:
                rel = nm_dir.relative_to(root)
            except ValueError:
                rel = nm_dir
            print(f"  {rel}/ ({count} packages)", file=sys.stderr)


def _resolve_api_key() -> str:
    key = load_api_key(interactive=False)
    if key:
        return key
    if sys.stdin.isatty():
        return prompt_and_save_api_key()
    return ensure_api_key(interactive=False)


def run_scan(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser().resolve()
    if not root.exists():
        print(f"Path not found: {root}", file=sys.stderr)
        return 3

    try:
        ecosystems = parse_ecosystem_option(getattr(args, "ecosystem", None), root)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 3

    depth = getattr(args, "depth", 3)
    max_depth: int | None = None if depth == 0 else depth

    def _collect() -> tuple[list[DependencyItem], list[str], list[Path]]:
        return collect_project_dependencies(
            root,
            ecosystems=ecosystems,
            include_optional=args.include_optional,
            scan_node_modules=not getattr(args, "no_node_modules", False),
            max_depth=max_depth,
        )

    dependencies, collect_warnings, discovered_files = run_with_progress(
        _collect,
        message=f"Scanning {root} ...",
    )
    eco_text = ", ".join(sorted(ecosystems))
    print(f"Ecosystems: {eco_text}", file=sys.stderr)
    _print_discovered_files(root, discovered_files)
    print(f"Dependencies to check: {len(dependencies)}", file=sys.stderr)
    return _run_detection(
        dependencies,
        output_json=args.json,
        output_sarif=args.sarif,
        quiet=args.quiet,
        warnings=collect_warnings,
        output_file=getattr(args, "output", None),
    )


def run_global(args: argparse.Namespace) -> int:
    dependencies, warnings = run_with_progress(
        lambda: collect_global_dependencies(
            python_only=args.python_only,
            node_only=args.node_only,
        ),
        message="Scanning global environments ...",
    )
    if not dependencies:
        warnings.append("No global packages were discovered.")
    else:
        sources = sorted({d.source for d in dependencies})
        print("Scan sources:", file=sys.stderr)
        for src in sources:
            print(f"  {src}", file=sys.stderr)
    print(f"Dependencies to check: {len(dependencies)}", file=sys.stderr)
    return _run_detection(
        dependencies,
        output_json=args.json,
        output_sarif=args.sarif,
        quiet=args.quiet,
        warnings=warnings,
        output_file=getattr(args, "output", None),
    )


def run_check(args: argparse.Namespace) -> int:
    dependency = parse_package_ref(args.package, npm=args.npm, pypi=args.pypi)
    return _run_detection(
        [dependency],
        output_json=args.json,
        output_sarif=args.sarif,
        quiet=args.quiet,
        warnings=[],
    )


def _run_detection(
    dependencies: list[DependencyItem],
    *,
    output_json: bool,
    output_sarif: bool = False,
    quiet: bool,
    warnings: list[str],
    output_file: str | None = None,
) -> int:
    api_key = _resolve_api_key()
    client = MistEyeClient(api_key)
    scanner = DependencyScanner(
        client,
        show_progress=not quiet and not output_json and not output_sarif,
    )
    report = scanner.scan_dependencies(dependencies)
    report.warnings.extend(warnings)

    if output_sarif:
        output_format = "sarif"
    elif output_json:
        output_format = "json"
    else:
        output_format = "table"
    report_text = render_report(report, output_format=output_format)
    print(report_text)

    if output_file:
        out_path = Path(output_file).expanduser()
        save_format = "sarif" if output_sarif else "json"
        out_path.write_text(
            render_report(report, output_format=save_format),
            encoding="utf-8",
        )
        if not quiet:
            print(f"Report saved to {out_path.resolve()}", file=sys.stderr)

    return report.exit_code


def main(argv: list[str] | None = None) -> int:
    try:
        return _main_inner(argv)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        return 130


def _main_inner(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    set_color_enabled(not args.no_color)

    if args.command in {"scan", "global", "check"}:
        print_banner()

    if args.command == "scan":
        return run_scan(args)
    if args.command == "global":
        return run_global(args)
    if args.command == "check":
        return run_check(args)
    parser.print_help()
    return 3


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        raise SystemExit(130)
