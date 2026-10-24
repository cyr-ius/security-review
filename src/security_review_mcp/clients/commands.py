"""Client command of ``security-review-mcp``: ``enroll`` (MCP_COMMANDS).

It contacts the URL given by the operator. This module is kept apart from cli (the commands
of the controller) so that the MCP server never loads the controller modules (advisory
download, OIDC, syslog, ticketing): tests/test_server.py checks it. Exit codes follow the
convention of cli: 0 success, 1 blocked, 2 usage or data error.
"""

import argparse
import json
import sys
from collections.abc import Callable

from ..ci_client import EXIT_ERROR, EXIT_PASSED
from . import enrollment


def _fail(message: str) -> int:
    """Print an error as JSON on stderr and return the error exit code."""
    print(json.dumps({"error": message}), file=sys.stderr)
    return EXIT_ERROR


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


# Commands of security-review-mcp (client side of a shared MCP server)
MCP_COMMANDS: dict[str, Callable[[list[str]], int]] = {
    "enroll": enroll_command,
}


def run(argv: list[str]) -> int:
    """Run the command named by ``argv[0]`` and return its exit code."""
    return MCP_COMMANDS[argv[0]](argv[1:])
