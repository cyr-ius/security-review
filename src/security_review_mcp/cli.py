"""Command line helpers for pipelines and administrators (no MCP client or agent needed).

Commands: ``gate``, ``sarif``, ``trend``, ``advisories`` and ``deps``. Exit codes follow the same
convention everywhere: 0 success, 1 blocked (gate / vulnerabilities found), 2 usage or data error.
"""

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path

from . import advisories, depscan, sarif, services, trends
from .database import init_db
from .models import SEVERITY_RANK, Severity
from .services import NotFoundError

EXIT_PASSED = 0
EXIT_BLOCKED = 1
EXIT_ERROR = 2

MAX_FILE_BYTES = 50 * 1024 * 1024
_SEVERITY_CHOICES = [s.value for s in Severity]


def _fail(message: str) -> int:
    """Print an error as JSON on stderr and return the error exit code."""
    print(json.dumps({"error": message}), file=sys.stderr)
    return EXIT_ERROR


def _read_text(path: Path) -> str:
    """Read a text file chosen by the operator (bounded size)."""
    if not path.is_file():
        raise ValueError(f"File not found: {path}")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"File too large (> {MAX_FILE_BYTES} bytes): {path}")
    return path.read_text(encoding="utf-8", errors="replace")


# ── gate ─────────────────────────────────────────────────────────────────────


def gate_command(argv: list[str]) -> int:
    """Run ``security-review-mcp gate``: fail when open findings reach a severity threshold."""
    parser = argparse.ArgumentParser(
        prog="security-review-mcp gate",
        description="Fail when open findings reach a severity threshold.",
    )
    parser.add_argument("--project", required=True)
    parser.add_argument(
        "--fail-on",
        choices=_SEVERITY_CHOICES,
        default=Severity.HIGH.value,
        help="lowest blocking severity (default: high)",
    )
    parser.add_argument("--report-id", type=int, default=None, help="check a single report")
    args = parser.parse_args(argv)

    try:
        init_db()
        result = services.evaluate_gate(args.project, Severity(args.fail_on), args.report_id)
    except (NotFoundError, ValueError) as exc:
        print(json.dumps({"passed": False, "error": str(exc)}), file=sys.stderr)
        return EXIT_ERROR

    print(json.dumps(result, indent=2))
    return EXIT_PASSED if result["passed"] else EXIT_BLOCKED


# ── sarif ────────────────────────────────────────────────────────────────────


def sarif_command(argv: list[str]) -> int:
    """Run ``security-review-mcp sarif``: export stored findings as SARIF 2.1.0."""
    parser = argparse.ArgumentParser(
        prog="security-review-mcp sarif", description="Export findings as a SARIF 2.1.0 log."
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--project")
    target.add_argument("--report-id", type=int)
    parser.add_argument("--include-resolved", action="store_true")
    parser.add_argument("--output", "-o", help="file to write (default: standard output)")
    args = parser.parse_args(argv)

    try:
        init_db()
        name, items = services.collect_sarif_items(args.report_id, args.project)
        log = sarif.build_sarif(items, name, args.include_resolved)
        text = json.dumps(log, indent=2)
        if args.output:
            Path(args.output).write_text(text + "\n", encoding="utf-8")
            print(
                f"{len(log['runs'][0]['results'])} result(s) written to {args.output}",
                file=sys.stderr,
            )
        else:
            print(text)
    except (NotFoundError, ValueError, OSError) as exc:
        return _fail(str(exc))
    return EXIT_PASSED


# ── trend ────────────────────────────────────────────────────────────────────


def trend_command(argv: list[str]) -> int:
    """Run ``security-review-mcp trend``: print the trend report of a project."""
    parser = argparse.ArgumentParser(
        prog="security-review-mcp trend", description="Trend report of a project."
    )
    parser.add_argument("--project", required=True)
    parser.add_argument("--days", type=int, default=90)
    parser.add_argument("--granularity", choices=["day", "week", "month"], default="week")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    args = parser.parse_args(argv)

    try:
        init_db()
        trend = trends.get_trend(args.project, args.days, args.granularity)
    except ValueError as exc:
        return _fail(str(exc))
    if args.format == "json":
        print(json.dumps(trend, indent=2))
    else:
        print(trends.render_trend_markdown(trend), end="")
    return EXIT_PASSED


# ── advisories ───────────────────────────────────────────────────────────────


def advisories_command(argv: list[str]) -> int:
    """Run ``security-review-mcp advisories``: import or inspect the OSV database."""
    parser = argparse.ArgumentParser(
        prog="security-review-mcp advisories", description="Manage the offline advisory database."
    )
    actions = parser.add_subparsers(dest="action", required=True)
    importer = actions.add_parser("import", help="import OSV records (.json, directory or .zip)")
    importer.add_argument("path")
    importer.add_argument(
        "--ecosystem",
        action="append",
        help="ecosystem to keep (PyPI, npm, Maven); repeat the option; default: all three",
    )
    actions.add_parser("status", help="show the size and age of the database")
    args = parser.parse_args(argv)

    try:
        init_db()
        if args.action == "import":
            stats = advisories.import_advisories(args.path, set(args.ecosystem or []) or None)
            print(json.dumps(stats, indent=2))
        else:
            print(json.dumps(advisories.advisory_status(), indent=2))
    except (ValueError, OSError) as exc:
        return _fail(str(exc))
    return EXIT_PASSED


# ── deps ─────────────────────────────────────────────────────────────────────


def _blocking(result: dict, threshold: int) -> int:
    """Count the vulnerabilities and hygiene issues that reach the threshold."""
    entries = result["vulnerabilities"] + result["hygiene"]
    return sum(1 for e in entries if SEVERITY_RANK[Severity(e["severity"])] >= threshold)


def _print_text(results: list[dict], blocked: int, fail_on: str) -> None:
    """Print a short human-readable summary of the scans."""
    for result in results:
        kind = "lockfile" if result["is_lockfile"] else "manifest"
        print(
            f"{result['file']} ({result['ecosystem']}, {kind}): {result['components_total']} "
            f"component(s), vulnerability check: {result['vulnerability_check']}"
        )
        for vuln in result["vulnerabilities"]:
            upgrade = vuln["recommended_upgrade"]
            fix = f" -> upgrade to {upgrade}" if upgrade else ""
            print(
                f"  [{vuln['severity'].upper()}] {vuln['package']} {vuln['version']} "
                f"{vuln['advisory_id']}{fix}"
            )
        for issue in result["hygiene"]:
            print(f"  [{issue['severity'].upper()}] {issue['rule_id']} {issue['message']}")
        for note in result["notes"]:
            print(f"  note: {note}")
    verdict = f"BLOCKED ({blocked} finding(s) >= {fail_on})" if blocked else "OK"
    print(f"RESULT: {verdict}")


def deps_command(argv: list[str]) -> int:
    """Run ``security-review-mcp deps scan``: scan dependency files of a workspace."""
    parser = argparse.ArgumentParser(
        prog="security-review-mcp deps", description="Scan dependency manifests and lockfiles."
    )
    parser.add_argument("action", choices=["scan"])
    parser.add_argument("files", nargs="+", help="manifests or lockfiles")
    parser.add_argument("--fail-on", choices=_SEVERITY_CHOICES, default=Severity.HIGH.value)
    parser.add_argument("--format", choices=["json", "text"], default="text")
    parser.add_argument(
        "--require-database",
        action="store_true",
        help="exit 2 when the vulnerability check could not run (no advisory database)",
    )
    parser.add_argument("--project", help="project name (required with --save)")
    parser.add_argument("--save", action="store_true", help="store the findings as a report")
    parser.add_argument("--repository")
    parser.add_argument("--branch")
    parser.add_argument("--commit")
    args = parser.parse_args(argv)
    if args.save and not args.project:
        return _fail("--save requires --project")

    results: list[dict] = []
    try:
        init_db()
        for name in args.files:
            path = Path(name)
            results.append(depscan.scan_dependencies(_read_text(path), path.name))
    except (ValueError, OSError) as exc:
        return _fail(str(exc))

    skipped = [r["file"] for r in results if r["vulnerability_check"] != "performed"]
    if skipped:
        print(
            f"warning: vulnerability check did not run for: {', '.join(skipped)} "
            "(no advisory database for this ecosystem)",
            file=sys.stderr,
        )
    if skipped and args.require_database:
        return _fail("vulnerability check could not run and --require-database was given")

    threshold = SEVERITY_RANK[Severity(args.fail_on)]
    blocked = sum(_blocking(r, threshold) for r in results)

    saved = None
    if args.save:
        findings = [f for r in results for f in depscan.to_findings(r)]
        vulnerabilities = sum(r["vulnerabilities_count"] for r in results)
        hygiene = sum(r["hygiene_count"] for r in results)
        saved = services.save_report(
            project=args.project,
            summary=(
                f"Dependency scan of {len(results)} file(s): {vulnerabilities} vulnerable "
                f"component(s), {hygiene} hygiene issue(s)."
            ),
            findings=findings,
            repository=args.repository,
            branch=args.branch,
            commit_sha=args.commit,
            reviewer="security-review-mcp deps scan",
            scope=", ".join(r["file"] for r in results),
        )

    if args.format == "json":
        slim = [{k: v for k, v in r.items() if k != "components"} for r in results]
        print(
            json.dumps(
                {
                    "blocked": blocked > 0,
                    "blocking_findings": blocked,
                    "saved_report": saved,
                    "files": slim,
                },
                indent=2,
            )
        )
    else:
        _print_text(results, blocked, args.fail_on)
        if saved:
            print(f"Report #{saved['report_id']} saved for project {args.project}")
    return EXIT_BLOCKED if blocked else EXIT_PASSED


COMMANDS: dict[str, Callable[[list[str]], int]] = {
    "gate": gate_command,
    "sarif": sarif_command,
    "trend": trend_command,
    "advisories": advisories_command,
    "deps": deps_command,
}


def run(argv: list[str]) -> int:
    """Run the command named by ``argv[0]`` and return its exit code."""
    return COMMANDS[argv[0]](argv[1:])
