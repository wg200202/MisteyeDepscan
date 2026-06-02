from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Callable

from misteye_depscan import __version__
from misteye_depscan.banner import print_banner
from misteye_depscan.api import MistEyeClient
from misteye_depscan.collectors import collect_global_dependencies
from misteye_depscan.config import ensure_api_key, load_api_key, prompt_and_save_api_key
from misteye_depscan.dashboard import ScanUI, create_scan_ui, dashboard_enabled
from misteye_depscan.exceptions import ScanInterrupted
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
        help="Ecosystems to scan: npm, pypi, rust, go, rubygems, all, or comma-separated (default: auto-detect).",
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
    global_parser.add_argument(
        "--rust-only",
        action="store_true",
        help="Scan only Rust cargo install globals.",
    )
    global_parser.add_argument(
        "--go-only",
        action="store_true",
        help="Scan only Go go install globals.",
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
    check_parser.add_argument("--go", action="store_true", help="Treat package as Go module.")
    check_parser.add_argument("--json", action="store_true", help="Output JSON report.")
    check_parser.add_argument("--sarif", action="store_true", help="Output SARIF report.")
    check_parser.add_argument("--quiet", action="store_true", help="Hide scan progress output.")

    return parser


def parse_package_ref(
    package: str,
    *,
    npm: bool = False,
    pypi: bool = False,
    go: bool = False,
) -> DependencyItem:
    flags = sum(1 for value in (npm, pypi, go) if value)
    if flags > 1:
        raise SystemExit("Use only one of --npm, --pypi, or --go.")

    if npm or (not pypi and not go and package.startswith("@")):
        package_type = PackageType.NPM.value
    elif go:
        package_type = PackageType.GO.value
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


def _print_discovered_files(
    root: Path,
    files: list[Path],
    emit: Callable[[str], None],
) -> None:
    if not files:
        emit("No dependency files found.")
        return

    from collections import defaultdict

    nm_files: list[Path] = []
    manifest_files: list[Path] = []
    for f in files:
        (nm_files if "node_modules" in f.parts else manifest_files).append(f)

    emit(f"Discovered {len(files)} dependency file(s):")
    by_kind: dict[str, list[Path]] = defaultdict(list)
    for f in manifest_files:
        name = f.name.lower()
        if name in {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}:
            by_kind["npm"].append(f)
        elif name in {"cargo.toml", "cargo.lock"}:
            by_kind["rust"].append(f)
        elif name in {"go.mod", "go.sum"}:
            by_kind["go"].append(f)
        elif name in {"gemfile", "gemfile.lock"}:
            by_kind["rubygems"].append(f)
        elif name.startswith("requirements") or name in {
            "pyproject.toml",
            "pipfile",
            "pipfile.lock",
            "poetry.lock",
            "uv.lock",
            "setup.py",
            "setup.cfg",
        }:
            by_kind["pypi"].append(f)
        else:
            by_kind["other"].append(f)
    for kind in ("npm", "rust", "go", "rubygems", "pypi", "other"):
        for f in by_kind.get(kind, []):
            try:
                rel = f.relative_to(root)
            except ValueError:
                rel = f
            emit(f"  [{kind}] {rel}")

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
            emit(f"  {rel}/ ({count} packages)")


def _dependency_count_by_ecosystem(dependencies: list[DependencyItem]) -> str:
    """Format ``npm=120, pypi=80, ...`` for display after the dependency total."""
    if not dependencies:
        return ""
    from collections import Counter

    by_type = Counter(d.package_type for d in dependencies)
    parts: list[str] = []
    if by_type.get("package:npm"):
        parts.append(f"npm={by_type['package:npm']}")
    if by_type.get("package:cratesio"):
        parts.append(f"rust={by_type['package:cratesio']}")
    if by_type.get("package:go"):
        parts.append(f"go={by_type['package:go']}")
    if by_type.get("package:rubygems"):
        parts.append(f"rubygems={by_type['package:rubygems']}")
    if by_type.get("package:pypi"):
        parts.append(f"pypi={by_type['package:pypi']}")
    return ", ".join(parts)


def _format_dependencies_to_check_line(
    dependencies: list[DependencyItem],
    *,
    ecosystems: str | None = None,
) -> str:
    """One summary line: total count plus per-ecosystem breakdown (visible in the dashboard)."""
    total = len(dependencies)
    breakdown = _dependency_count_by_ecosystem(dependencies)
    if breakdown:
        return f"Dependencies to check: {total} ({breakdown})"
    if ecosystems:
        return f"Dependencies to check: {total} | Ecosystems: {ecosystems}"
    return f"Dependencies to check: {total}"


def _resolve_api_key() -> str:
    key = load_api_key(interactive=False)
    if key:
        return key
    if sys.stdin.isatty():
        return prompt_and_save_api_key()
    return ensure_api_key(interactive=False)


def _collect_with_ui(
    ui: ScanUI,
    fn: Callable[[], object],
    message: str,
) -> object:
    """Run a (blocking) collection step, showing a spinner only in plain mode.

    In live-dashboard mode the dashboard's own refresh loop provides feedback,
    so we avoid the stderr spinner which would corrupt the live region.
    """
    if ui.is_live:
        ui.log(message)
        return fn()
    return run_with_progress(fn, message=message)


def run_scan(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser().resolve()
    if not root.exists():
        print(f"Path not found: {root}", file=sys.stderr)
        return 3

    depth = args.depth
    max_depth: int | None = None if depth == 0 else depth

    try:
        ecosystems = parse_ecosystem_option(
            getattr(args, "ecosystem", None),
            root,
            max_depth=max_depth,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 3

    try:
        api_key = _resolve_api_key()
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        return 3
    client = MistEyeClient(api_key)

    depth_label = "unlimited" if depth == 0 else str(depth)
    eco_text = ", ".join(sorted(ecosystems))

    ui = create_scan_ui(
        output_json=args.json,
        output_sarif=args.sarif,
        quiet=args.quiet,
        title="MistEye DepScan",
    )

    def _collect() -> tuple[list[DependencyItem], list[str], list[str], list[Path]]:
        return collect_project_dependencies(
            root,
            ecosystems=ecosystems,
            include_optional=args.include_optional,
            scan_node_modules=not getattr(args, "no_node_modules", False),
            max_depth=max_depth,
        )

    with ui:
        ui.set_header(Mode="project scan", Target=str(root), Ecosystems=eco_text, Depth=depth_label)
        ui.set_phase("COLLECT")
        ui.log(f"Scan depth: {depth_label} (recursive manifest discovery)")
        dependencies, collect_warnings, collect_info, discovered_files = _collect_with_ui(
            ui, _collect, f"Scanning {root} ..."
        )
        _print_discovered_files(root, discovered_files, ui.log)
        ui.log(_format_dependencies_to_check_line(dependencies, ecosystems=eco_text))
        report = _run_detection(
            dependencies,
            client=client,
            quiet=args.quiet,
            output_json=args.json,
            output_sarif=args.sarif,
            warnings=collect_warnings,
            info=collect_info,
            ui=ui,
        )

    return _emit_report(
        report,
        output_json=args.json,
        output_sarif=args.sarif,
        quiet=args.quiet,
        output_file=getattr(args, "output", None),
    )


def run_global(args: argparse.Namespace) -> int:
    try:
        api_key = _resolve_api_key()
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        return 3
    client = MistEyeClient(api_key)

    ui = create_scan_ui(
        output_json=args.json,
        output_sarif=args.sarif,
        quiet=args.quiet,
        title="MistEye DepScan",
    )

    with ui:
        ui.set_header(Mode="global env", Target="local machine")
        ui.set_phase("COLLECT")
        dependencies, warnings, info = _collect_with_ui(
            ui,
            lambda: collect_global_dependencies(
                python_only=args.python_only,
                node_only=args.node_only,
                rust_only=args.rust_only,
                go_only=args.go_only,
            ),
            "Scanning global environments ...",
        )
        if not dependencies:
            info.append("No global packages were discovered.")
        else:
            sources = sorted({d.source for d in dependencies})
            ui.log("Scan sources:")
            for src in sources:
                ui.log(f"  {src}")
        ui.log(_format_dependencies_to_check_line(dependencies))
        report = _run_detection(
            dependencies,
            client=client,
            quiet=args.quiet,
            output_json=args.json,
            output_sarif=args.sarif,
            warnings=warnings,
            info=info,
            ui=ui,
        )

    return _emit_report(
        report,
        output_json=args.json,
        output_sarif=args.sarif,
        quiet=args.quiet,
        output_file=getattr(args, "output", None),
    )


def run_check(args: argparse.Namespace) -> int:
    dependency = parse_package_ref(
        args.package,
        npm=args.npm,
        pypi=args.pypi,
        go=args.go,
    )
    try:
        api_key = _resolve_api_key()
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        return 3
    client = MistEyeClient(api_key)

    ui = create_scan_ui(
        output_json=args.json,
        output_sarif=args.sarif,
        quiet=args.quiet,
        title="MistEye DepScan",
    )

    with ui:
        ui.set_header(Mode="single check", Target=dependency.target)
        report = _run_detection(
            [dependency],
            client=client,
            quiet=args.quiet,
            output_json=args.json,
            output_sarif=args.sarif,
            warnings=[],
            info=[],
            ui=ui,
        )

    return _emit_report(
        report,
        output_json=args.json,
        output_sarif=args.sarif,
        quiet=args.quiet,
        output_file=None,
    )


def _run_detection(
    dependencies: list[DependencyItem],
    *,
    client: MistEyeClient,
    quiet: bool,
    output_json: bool,
    output_sarif: bool,
    warnings: list[str],
    info: list[str],
    ui: ScanUI,
):
    """Run the detection phase inside the (already started) UI and return the report."""
    ui.begin_scan(len(dependencies))
    scanner = DependencyScanner(
        client,
        show_progress=not quiet and not output_json and not output_sarif,
        progress_callback=ui.on_progress if ui.is_live else None,
    )
    report = scanner.scan_dependencies(dependencies)
    report.warnings.extend(warnings)
    report.info.extend(info)
    ui.set_phase("DONE")
    return report


def _emit_report(
    report,
    *,
    output_json: bool,
    output_sarif: bool,
    quiet: bool,
    output_file: str | None,
) -> int:
    """Render and print the final report after the live UI has closed."""
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
        try:
            out_path.write_text(
                render_report(report, output_format=save_format),
                encoding="utf-8",
            )
        except OSError as exc:
            print(f"Failed to save report to {out_path}: {exc}", file=sys.stderr)
            return report.exit_code
        if not quiet:
            print(f"Report saved to {out_path.resolve()}", file=sys.stderr)

    return report.exit_code


def _exit_interrupted(*, completed: int = 0, total: int = 0) -> int:
    """Print a single line and exit without waiting on background HTTP threads."""
    if total > 0:
        print(
            f"\nScan interrupted ({completed}/{total} completed).",
            file=sys.stderr,
            flush=True,
        )
    else:
        print("\nScan interrupted.", file=sys.stderr, flush=True)
    os._exit(130)


def main(argv: list[str] | None = None) -> int:
    try:
        return _main_inner(argv)
    except ScanInterrupted as exc:
        return _exit_interrupted(completed=exc.completed, total=exc.total)
    except KeyboardInterrupt:
        return _exit_interrupted()


def _main_inner(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    set_color_enabled(not args.no_color)

    if args.command in {"scan", "global", "check"}:
        # The live dashboard renders its own logo; only print the static banner
        # when we are going to use plain sequential output.
        use_dashboard = dashboard_enabled(
            output_json=getattr(args, "json", False),
            output_sarif=getattr(args, "sarif", False),
            quiet=getattr(args, "quiet", False),
        )
        if not use_dashboard:
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
    raise SystemExit(main())
