"""Command line helpers for pipelines and administrators (no MCP client or agent needed).

Commands: ``gate``, ``sarif``, ``trend``, ``advisories``, ``deps``, ``code``, ``rules``,
``token`` and ``enroll``. Exit codes follow the same convention everywhere: 0 success, 1 blocked
(gate / findings found), 2 usage or data error.
"""

import argparse
import json
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.exc import SQLAlchemyError

from . import (
    advisories,
    codescan,
    depscan,
    enrollment,
    http_server,
    registry,
    rule_store,
    rules_loader,
    sarif,
    services,
    token_store,
    trends,
)
from .config import get_settings
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


# ── code ─────────────────────────────────────────────────────────────────────


def _print_code_text(result: dict, blocked: int, fail_on: str) -> None:
    """Print a short human-readable summary of the codebase scan."""
    for entry in result["files"]:
        for match in entry["matches"]:
            print(
                f"{entry['file']}:{match['line']} [{match['severity'].upper()}] "
                f"{match['rule_id']} {match['title']}"
            )
    for entry in result["skipped"]:
        if entry["reason"] != "excluded":
            print(f"skipped: {entry['file']} ({entry['reason']})", file=sys.stderr)
    counts = ", ".join(f"{k}: {v}" for k, v in result["by_severity"].items() if v)
    print(
        f"{result['files_scanned']} file(s) scanned ({result['lines_scanned']} lines, listed with "
        f"{result['listing']}), {result['files_skipped']} skipped, "
        f"{result['matches_count']} match(es){f' ({counts})' if counts else ''}, "
        f"{result['suppressed_count']} suppressed"
    )
    verdict = f"BLOCKED ({blocked} match(es) >= {fail_on})" if blocked else "OK"
    print(f"RESULT: {verdict}")


def _save_code_scan(args: argparse.Namespace, result: dict) -> dict:
    """Store the matches as a report; keep the most severe ones when there are too many."""
    findings = codescan.to_findings(result)
    limit = get_settings().max_findings_per_report
    summary = (
        f"Pattern scan of the whole codebase: {result['files_scanned']} file(s), "
        f"{result['matches_count']} match(es) to verify, {result['suppressed_count']} suppressed."
    )
    if len(findings) > limit:
        summary += f" Only the {limit} most severe matches are stored."
        findings = findings[:limit]
    skipped = [s["file"] for s in result["skipped"] if s["reason"] != "excluded"]
    scope = f"Codebase {args.path} ({result['files_scanned']} files scanned)"
    if skipped:
        scope += f"; not scanned: {', '.join(skipped[:50])}"
        scope += f" and {len(skipped) - 50} more" if len(skipped) > 50 else ""
    return services.save_report(
        project=args.project,
        summary=summary,
        findings=findings,
        repository=args.repository,
        branch=args.branch,
        commit_sha=args.commit,
        reviewer="security-review-mcp code scan",
        scope=scope,
    )


def code_command(argv: list[str]) -> int:
    """Run ``security-review-mcp code scan``: pattern-scan every file of a codebase."""
    parser = argparse.ArgumentParser(
        prog="security-review-mcp code",
        description="Pattern-scan a whole codebase (leads to verify, not a full SAST).",
    )
    parser.add_argument("action", choices=["scan"])
    parser.add_argument("path", nargs="?", default=".", help="directory to scan (default: .)")
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="file or directory glob to skip, relative to the path; repeat the option",
    )
    parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=codescan.DEFAULT_MAX_FILE_BYTES,
        help="skip larger files (default: 1 MiB)",
    )
    parser.add_argument(
        "--no-git", action="store_true", help="walk the tree instead of using git ls-files"
    )
    parser.add_argument("--fail-on", choices=_SEVERITY_CHOICES, default=Severity.HIGH.value)
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    parser.add_argument("--output", "-o", help="file to write (default: standard output)")
    parser.add_argument("--project", help="project name (required with --save)")
    parser.add_argument("--save", action="store_true", help="store the matches as a report")
    parser.add_argument("--repository")
    parser.add_argument("--branch")
    parser.add_argument("--commit")
    args = parser.parse_args(argv)
    if args.save and not args.project:
        return _fail("--save requires --project")

    try:
        # Internal rules live in the database; without it, only the built-in rules apply
        try:
            init_db()
        except SQLAlchemyError:
            if args.save:
                raise
        for message in registry.snapshot().errors:
            print(f"warning: {message}", file=sys.stderr)
        result = codescan.scan_tree(args.path, args.exclude, args.max_file_bytes, not args.no_git)
        saved = _save_code_scan(args, result) if args.save else None
    except (ValueError, OSError) as exc:
        return _fail(str(exc))

    blocked = codescan.blocking_count(result, Severity(args.fail_on))
    if args.format == "text":
        _print_code_text(result, blocked, args.fail_on)
        if saved:
            print(f"Report #{saved['report_id']} saved for project {args.project}")
        return EXIT_BLOCKED if blocked else EXIT_PASSED

    if args.format == "sarif":
        if saved:
            name, items = services.collect_sarif_items(saved["report_id"], None)
        else:
            name = args.project or Path(result["root"]).name
            now = datetime.now(UTC)
            items = [
                sarif.SarifItem(f, 0, name, args.repository, args.branch, args.commit, now)
                for f in codescan.to_public(codescan.to_findings(result))
            ]
        document = sarif.build_sarif(items, name)
    else:
        document = {
            "blocked": blocked > 0,
            "blocking_findings": blocked,
            "saved_report": saved,
            **result,
        }
    text = json.dumps(document, indent=2)
    if args.output:
        try:
            Path(args.output).write_text(text + "\n", encoding="utf-8")
        except OSError as exc:
            return _fail(str(exc))
        print(f"{result['matches_count']} match(es) written to {args.output}", file=sys.stderr)
    else:
        print(text)
    return EXIT_BLOCKED if blocked else EXIT_PASSED


# ── token ────────────────────────────────────────────────────────────────────


def token_command(argv: list[str]) -> int:
    """Run ``security-review-mcp token``: manage the bearer tokens stored in the database."""
    parser = argparse.ArgumentParser(
        prog="security-review-mcp token",
        description="Manage the bearer tokens of the HTTP transport (stored as SHA-256 digests).",
    )
    actions = parser.add_subparsers(dest="action", required=True)
    creator = actions.add_parser("create", help="create a token and print its secret once")
    creator.add_argument("--label", required=True, help="unique name of the client (in the logs)")
    creator.add_argument(
        "--role",
        choices=[role.value for role in http_server.Role],
        default=http_server.DEFAULT_ROLE.value,
        help="mcp (default): MCP endpoint; reader/triager: web interface; admin: both",
    )
    creator.add_argument(
        "--project", help="restrict the token to one project (MCP tools and web interface)"
    )
    lister = actions.add_parser("list", help="list the tokens (never their secret or hash)")
    lister.add_argument("--project", help="only the tokens restricted to this project")
    lister.add_argument(
        "--pending", action="store_true", help="only the enrollment requests waiting for approval"
    )
    revoker = actions.add_parser("revoke", help="delete a token by id or label")
    revoker.add_argument("token", help="token id or label")
    approver = actions.add_parser("approve", help="approve a pending enrollment request")
    approver.add_argument("token", help="request id or label")
    rejecter = actions.add_parser("reject", help="reject (delete) a pending enrollment request")
    rejecter.add_argument("token", help="request id or label")
    actions.add_parser("reset-admin", help="replace the bootstrap administrator password")
    args = parser.parse_args(argv)

    try:
        init_db()
        if args.action == "create":
            result: object = token_store.create_token(args.label, args.role, args.project)
        elif args.action == "list":
            result = token_store.list_tokens(args.project, args.pending)
        elif args.action == "approve":
            result = token_store.approve_enrollment(args.token)
        elif args.action == "reject":
            result = token_store.reject_enrollment(args.token)
        elif args.action == "revoke":
            result = token_store.revoke_token(args.token)
            if not token_store.DatabaseTokenStore().has_tokens():
                # Without any token the HTTP transport no longer requires authentication
                print(
                    json.dumps({"warning": "No token left: the MCP endpoint is now open"}),
                    file=sys.stderr,
                )
        else:
            password = token_store.reset_bootstrap_admin()
            result = {"label": token_store.BOOTSTRAP_LABEL, "token": password}
    except ValueError as exc:
        return _fail(str(exc))
    print(json.dumps(result, indent=2))
    return EXIT_PASSED


# ── enroll ───────────────────────────────────────────────────────────────────


def enroll_command(argv: list[str]) -> int:
    """Run ``security-review-mcp enroll``: request a project token from a shared server."""
    parser = argparse.ArgumentParser(
        prog="security-review-mcp enroll",
        description="Request a token restricted to one project from a shared server. The token "
        "is printed once and works after an administrator approves the request.",
    )
    parser.add_argument(
        "--url", required=True, help="server URL, for example https://secreview.example.com"
    )
    parser.add_argument("--project", required=True, help="project name used for the reports")
    parser.add_argument(
        "--label", help="name of the token (default: the project); a random suffix is added"
    )
    parser.add_argument("--requested-by", help="who asks (name, email or team), for the admin")
    parser.add_argument("--cafile", help="CA bundle used to verify the server certificate")
    parser.add_argument(
        "--allow-http",
        action="store_true",
        help="allow plain HTTP to a non-loopback server (the token would travel in clear)",
    )
    args = parser.parse_args(argv)
    try:
        result = enrollment.request_enrollment(
            args.url,
            args.project,
            label=args.label,
            requested_by=args.requested_by,
            cafile=args.cafile,
            allow_http=args.allow_http,
        )
    except ValueError as exc:
        return _fail(str(exc))
    print(json.dumps(result, indent=2))
    return EXIT_PASSED


# ── rules ────────────────────────────────────────────────────────────────────


def _read_pack(path: Path) -> tuple[str, str]:
    """Read one rule pack chosen by the operator; symbolic links are not followed."""
    if path.is_symlink():
        raise ValueError(f"Refusing to read a symbolic link: {path}")
    if not path.is_file():
        raise ValueError(f"File not found: {path}")
    if path.stat().st_size > rules_loader.MAX_PACK_BYTES:
        raise ValueError(f"Rule pack larger than {rules_loader.MAX_PACK_BYTES} bytes: {path}")
    return path.name, path.read_text(encoding="utf-8")


def _collect_packs(names: list[str]) -> list[tuple[str, str]]:
    """Read the given packs; a directory contributes its ``*.toml`` files in name order."""
    packs: list[tuple[str, str]] = []
    for name in names:
        path = Path(name)
        if path.is_dir() and not path.is_symlink():
            files = sorted(path.glob("*.toml"))
            if not files:
                raise ValueError(f"No *.toml rule pack in {path}")
            for file in files:
                if file.is_symlink():
                    print(f"skipped: {file} (symbolic link)", file=sys.stderr)
                    continue
                packs.append(_read_pack(file))
        else:
            packs.append(_read_pack(path))
    return packs


def _print_rules_text(rows: list[dict]) -> None:
    """Print one line per rule: id, severity, origin (builtin, modified, custom), state, title."""
    for row in rows:
        state = "enabled" if row["enabled"] else "disabled"
        origin = "modified" if row["modified"] else row["origin"]
        print(f"{row['id']:<12} {row['severity']:<8} {origin:<8} {state:<8} {row['title']}")
    disabled = sum(1 for row in rows if not row["enabled"])
    print(f"{len(rows)} rule(s), {disabled} disabled")


def rules_command(argv: list[str]) -> int:
    """Run ``security-review-mcp rules``: manage the internal rules stored in the database."""
    parser = argparse.ArgumentParser(
        prog="security-review-mcp rules",
        description="Manage the internal scan rules and checklist items stored in the database.",
    )
    actions = parser.add_subparsers(dest="action", required=True)
    lister = actions.add_parser("list", help="list every rule (default and custom) and its state")
    lister.add_argument("--language", help="only the rules that apply to this language")
    lister.add_argument("--custom", action="store_true", help="only the custom rules")
    lister.add_argument("--format", choices=["text", "json"], default="text")
    importer = actions.add_parser("import", help="import TOML rule packs (files or directories)")
    importer.add_argument("paths", nargs="+", metavar="PATH")
    importer.add_argument(
        "--replace",
        action="store_true",
        help="first reset the stored rules, checklist items and disabled states to the defaults",
    )
    exporter = actions.add_parser("export", help="export the stored content as a TOML pack")
    exporter.add_argument("--output", "-o", help="file to write (default: standard output)")
    for action, text in (("enable", "enable"), ("disable", "disable")):
        toggler = actions.add_parser(action, help=f"{text} default or custom rules")
        toggler.add_argument("ids", nargs="+", metavar="ID")
    remover = actions.add_parser(
        "delete", help="delete custom rules or checklist items (default ones cannot be deleted)"
    )
    remover.add_argument("ids", nargs="+", metavar="ID")
    args = parser.parse_args(argv)

    try:
        init_db()
        if args.action == "list":
            current = registry.reload()  # always the current state of the database
            rows = registry.describe_rules(args.language, include_disabled=True)
            if args.custom:
                rows = [row for row in rows if row["origin"] == "custom"]
            for message in current.errors:
                print(f"warning: {message}", file=sys.stderr)
            if args.format == "text":
                _print_rules_text(rows)
                return EXIT_PASSED
            result: object = rows
        elif args.action == "import":
            result = rule_store.import_packs(_collect_packs(args.paths), args.replace)
        elif args.action == "export":
            text = rule_store.export_pack()
            if not args.output:
                print(text, end="")
                return EXIT_PASSED
            Path(args.output).write_text(text, encoding="utf-8")
            print(f"Internal rules written to {args.output}", file=sys.stderr)
            return EXIT_PASSED
        elif args.action in ("enable", "disable"):
            changed = rule_store.set_enabled(args.ids, args.action == "enable")
            result = {f"{args.action}d": changed}
        else:
            result = rule_store.delete_entries(args.ids)
    except (ValueError, OSError, UnicodeDecodeError) as exc:
        return _fail(str(exc))
    print(json.dumps(result, indent=2))
    return EXIT_PASSED


COMMANDS: dict[str, Callable[[list[str]], int]] = {
    "gate": gate_command,
    "sarif": sarif_command,
    "trend": trend_command,
    "advisories": advisories_command,
    "deps": deps_command,
    "code": code_command,
    "rules": rules_command,
    "token": token_command,
    "enroll": enroll_command,
}


def run(argv: list[str]) -> int:
    """Run the command named by ``argv[0]`` and return its exit code."""
    return COMMANDS[argv[0]](argv[1:])
