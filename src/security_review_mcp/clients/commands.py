"""Client commands of ``security-review-mcp``: ``enroll`` and ``scan-deps`` (MCP_COMMANDS).

They contact the URL given by the operator. This module is kept apart from cli (the commands
of the controller) so that the MCP server never loads the controller modules (advisory
download, OIDC, syslog, ticketing): tests/test_server.py checks it. Exit codes follow the
convention of cli: 0 success, 1 blocked, 2 usage or data error.
"""

import argparse
import json
import sys
from collections.abc import Callable

from .. import ci_client
from ..ci_client import EXIT_BLOCKED, EXIT_ERROR, EXIT_PASSED
from ..config import get_settings
from ..storage.models import SEVERITY_RANK, Severity
from . import enrollment, remote_scan

_SEVERITY_CHOICES = [s.value for s in Severity]


def _fail(message: str) -> int:
    """Print an error as JSON on stderr and return the error exit code."""
    print(json.dumps({"error": message}), file=sys.stderr)
    return EXIT_ERROR


# ── scan output ──────────────────────────────────────────────────────────────


def _blocking(result: dict, threshold: int) -> int:
    """Count the vulnerabilities and hygiene issues that reach the threshold."""
    entries = result["vulnerabilities"] + result["hygiene"]
    return sum(1 for e in entries if SEVERITY_RANK[Severity(e["severity"])] >= threshold)


def _print_deps(
    results: list[dict], fail_on: str, output_format: str, saved: dict | None = None
) -> int:
    """Print the dependency scans and return the exit code (blocked at ``fail_on``).

    ``saved`` is the answer of save_security_report when the result was stored (--save).
    """
    threshold = SEVERITY_RANK[Severity(fail_on)]
    blocked = sum(_blocking(r, threshold) for r in results)
    if output_format == "json":
        slim = [{k: v for k, v in r.items() if k != "components"} for r in results]
        answer = {"blocked": blocked > 0, "blocking_findings": blocked, "files": slim}
        if saved:
            answer["saved_report"] = saved
        print(json.dumps(answer, indent=2))
    else:
        ci_client.print_deps_text(results, blocked, fail_on)
        if saved:
            ci_client.print_saved_line({"saved_report": saved}, saved.get("project", ""))
    return EXIT_BLOCKED if blocked else EXIT_PASSED


# ── enroll ───────────────────────────────────────────────────────────────────


def enroll_command(argv: list[str]) -> int:
    """Run ``security-review-mcp enroll``: request the project of a repository on a server."""
    parser = argparse.ArgumentParser(
        prog="security-review-mcp enroll",
        description="Request a project on a shared server (unchanged when it exists); an "
        "administrator approves it. No token is created: sign in to the web interface of the "
        "server (web_url of the answer), create a personal MCP token there and ask an "
        "administrator for access to the project.",
    )
    parser.add_argument(
        "--url", required=True, help="server URL, for example https://secreview.example.com"
    )
    parser.add_argument("--project", required=True, help="project name used for the reports")
    parser.add_argument(
        "--requested-by",
        help="who asks (name, email or team), for the administrator (default: your login name)",
    )
    parser.add_argument("--cafile", help="CA bundle used to verify the server certificate")
    parser.add_argument(
        "--allow-http",
        action="store_true",
        help="allow plain HTTP to a non-loopback server",
    )
    args = parser.parse_args(argv)
    try:
        result = enrollment.request_enrollment(
            args.url,
            args.project,
            requested_by=args.requested_by or enrollment.local_username(),
            cafile=args.cafile,
            allow_http=args.allow_http,
        )
    except ValueError as exc:
        return _fail(str(exc))
    print(json.dumps(result, indent=2))
    return EXIT_PASSED


# ── scan-deps ────────────────────────────────────────────────────────────────

DEPRECATED_SCAN_DEPS = (
    "warning: security-review-mcp scan-deps is deprecated and will be removed in a major "
    "version: use security-review-ci scan-deps (controller URL and a personal ci token)"
)


def scan_deps_command(argv: list[str]) -> int:
    """Run ``security-review-mcp scan-deps``: scan dependency files with a shared server.

    Deprecated: ``security-review-ci scan-deps`` sends the files to the controller instead, with
    a ci token (personal on a workstation); this command will be removed in a major version.
    """
    print(DEPRECATED_SCAN_DEPS, file=sys.stderr)
    settings = get_settings()
    parser = argparse.ArgumentParser(
        prog="security-review-mcp scan-deps",
        description="Deprecated: use security-review-ci scan-deps. Scan dependency manifests "
        "and lockfiles with the advisory database of a shared MCP server (commit hooks, "
        "pipelines). The token is read from SECREVIEW_TOKEN "
        "or, with --token-stdin, from the standard input.",
    )
    parser.add_argument("files", nargs="+", help="manifests or lockfiles")
    parser.add_argument(
        "--url",
        default=settings.server_url,
        help="server URL, for example https://secreview.example.com (default: SECREVIEW_MCP_URL)",
    )
    parser.add_argument(
        "--fail-on",
        choices=_SEVERITY_CHOICES,
        default=Severity.HIGH.value,
        help="exit 1 when a finding reaches this severity (default: %(default)s)",
    )
    parser.add_argument(
        "--format", choices=["json", "text"], default="text", help="output (default: %(default)s)"
    )
    parser.add_argument(
        "--require-database",
        action="store_true",
        help="exit 2 when the vulnerability check could not run (no advisory database)",
    )
    parser.add_argument(
        "--skip-unconfigured",
        action="store_true",
        help="exit 0 with a warning when no server URL is configured (shared commit hooks)",
    )
    parser.add_argument(
        "--token-stdin", action="store_true", help="read the token on stdin (not SECREVIEW_TOKEN)"
    )
    parser.add_argument("--cafile", help="CA bundle used to verify the server certificate")
    parser.add_argument(
        "--allow-http",
        action="store_true",
        help="allow plain HTTP to a non-loopback server (the token would travel in clear)",
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="store the result as a dependency-scan report of --project on the server",
    )
    parser.add_argument("--project", help="project name of the report (with --save)")
    parser.add_argument("--repository", help="repository URL stored with the report")
    parser.add_argument("--branch", help="branch stored with the report")
    parser.add_argument("--commit", help="commit stored with the report")
    parser.add_argument("--author", help="username of the developer, stored with the report")
    args = parser.parse_args(argv)
    if args.save and not args.project:
        return _fail("--save needs --project")
    if not args.url:
        if args.skip_unconfigured:
            print(
                "warning: dependency scan skipped (SECREVIEW_MCP_URL is not set)",
                file=sys.stderr,
            )
            return EXIT_PASSED
        return _fail("No server URL: give --url or set SECREVIEW_MCP_URL")
    token = settings.token
    if args.token_stdin:
        # Never on the command line: it would show in the process list and the shell history
        token = sys.stdin.readline().strip()
        if not token:
            return _fail("--token-stdin: no token read on stdin")

    try:
        files: list[tuple[str, str]] = []
        for name in args.files:
            # The content leaves the machine: never through a symbolic link, bounded size
            read = ci_client.read_dependency_file(name)
            files.append((read["path"], read["content"]))
        results = remote_scan.scan_files(
            args.url, files, token=token, cafile=args.cafile, allow_http=args.allow_http
        )
    except (ValueError, OSError) as exc:
        return _fail(str(exc))

    if ci_client.warn_unchecked(results) and args.require_database:
        return _fail("vulnerability check could not run and --require-database was given")
    saved = None
    if args.save:
        fields = {
            "repository": args.repository,
            "branch": args.branch,
            "commit_sha": args.commit,
            "author": args.author,
        }
        try:
            saved = remote_scan.save_report(
                args.url,
                results,
                args.project,
                fields,
                token=token,
                cafile=args.cafile,
                allow_http=args.allow_http,
            )
        except ValueError as exc:
            return _fail(str(exc))
    return _print_deps(results, args.fail_on, args.format, saved)


# Commands of security-review-mcp (client side of a shared MCP server)
MCP_COMMANDS: dict[str, Callable[[list[str]], int]] = {
    "enroll": enroll_command,
    "scan-deps": scan_deps_command,
}


def run(argv: list[str]) -> int:
    """Run the command named by ``argv[0]`` and return its exit code."""
    return MCP_COMMANDS[argv[0]](argv[1:])
