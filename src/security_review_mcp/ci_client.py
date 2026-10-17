"""Lightweight pipeline client of the controller (Jenkins, GitLab CI, GitHub Actions...).

``security-review-ci`` runs the security gate, downloads the SARIF log or prints the trend of a
project through the pipeline routes of the controller REST API (``/api/v1/ci/``), with a
``ci`` token restricted to the projects the pipeline may see. Unlike ``security-review-controller
gate`` / ``sarif`` / ``trend``, it opens no database: no database driver, no SQLModel, no
database URL in the pipeline.

The module only uses the Python standard library and imports nothing from the package, so it
can also be copied alone to a build agent and run with ``python3 ci_client.py``. That is why it
reads its two variables (``SECREVIEW_CONTROLLER_URL``, ``SECREVIEW_TOKEN``) from the environment
itself instead of through ``config.Settings``, and ignores the ``.env`` file.

Exit codes are those of the other commands: 0 success (gate passed), 1 gate blocked, 2 usage,
connection or data error (written as JSON on stderr). The token is never written anywhere.
"""

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlencode, urlsplit

EXIT_PASSED = 0
EXIT_BLOCKED = 1
EXIT_ERROR = 2

CI_PATH = "/api/v1/ci"
DEFAULT_TIMEOUT = 60.0
# Bound of an answer read from the controller (a SARIF log of a large project included)
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
# Bound of the error messages taken from the controller
MAX_ERROR_CHARS = 500
# Plain HTTP is only accepted to these hosts (the token travels in the request)
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
SEVERITIES = ["info", "low", "medium", "high", "critical"]

URL_VARIABLE = "SECREVIEW_CONTROLLER_URL"
TOKEN_VARIABLE = "SECREVIEW_TOKEN"

# Explanation added to the refusals of the controller
_REFUSAL_HINTS = {
    401: f"missing or invalid token ({TOKEN_VARIABLE} or --token-stdin)",
    403: "the token may not use the pipeline routes (role ci, reader, triager or admin)",
    404: "unknown project or report, or outside the projects of the token",
    503: "authentication is not configured on the controller",
}

# Sends a GET request and returns (HTTP status, content type, body); tests replace it
Fetch = Callable[[str, dict[str, str]], tuple[int, str, bytes]]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects: the token must never be sent elsewhere (or over HTTP)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        """Return None so that urllib raises an HTTPError for the 3xx answer."""
        return None


def controller_endpoint(controller_url: str, route: str, allow_http: bool = False) -> str:
    """Return the URL of a pipeline route of a controller given by its base URL.

    Plain HTTP is refused except on a loopback address or with ``allow_http``, and so are
    credentials in the URL: the token is the only credential and goes in a header.
    """
    parts = urlsplit(controller_url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(
            f"Invalid controller URL '{controller_url}' (expected https://host[:port])"
        )
    if parts.username or parts.password:
        raise ValueError("The controller URL must not contain credentials")
    if parts.scheme == "http" and parts.hostname not in LOOPBACK_HOSTS and not allow_http:
        raise ValueError("Refusing to send the token over plain HTTP (see --allow-http)")
    # The base URL may be given with the path of the web interface or of the API
    path = parts.path.rstrip("/")
    for suffix in ("/ui", "/api/v1", "/api"):
        path = path.removesuffix(suffix)
    return f"{parts.scheme}://{parts.netloc}{path}{CI_PATH}/{route}"


def urllib_fetch(cafile: str | None = None, timeout: float = DEFAULT_TIMEOUT) -> Fetch:
    """Return a fetch function that verifies the certificate with ``cafile`` (default: the
    system CA bundle), follows no redirect and reads at most MAX_RESPONSE_BYTES."""
    context = ssl.create_default_context(cafile=cafile)
    opener = urllib.request.build_opener(
        _NoRedirect(), urllib.request.HTTPSHandler(context=context)
    )

    def fetch(url: str, headers: dict[str, str]) -> tuple[int, str, bytes]:
        """Send a GET request and return its status, content type and bounded body."""
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with opener.open(request, timeout=timeout) as response:
                return (
                    response.status,
                    response.headers.get("Content-Type", ""),
                    response.read(MAX_RESPONSE_BYTES + 1),
                )
        except urllib.error.HTTPError as exc:
            with exc:
                body = exc.read(MAX_RESPONSE_BYTES + 1)
            return exc.code, exc.headers.get("Content-Type", "") if exc.headers else "", body
        except (urllib.error.URLError, OSError) as exc:
            # The message never holds the token: it is only in the request headers
            reason = getattr(exc, "reason", exc)
            raise ValueError(f"Cannot reach {url}: {reason}") from exc

    return fetch


def _error_detail(body: bytes) -> str:
    """Extract the error message of a FastAPI or middleware answer, bounded."""
    try:
        answer = json.loads(body)
    except ValueError:
        return ""
    if not isinstance(answer, dict):
        return ""
    detail = answer.get("detail") or answer.get("error_description") or ""
    if isinstance(detail, list):
        # Pydantic validation errors
        detail = "; ".join(str(item.get("msg", item)) for item in detail if isinstance(item, dict))
    return str(detail)[:MAX_ERROR_CHARS]


def call(
    controller_url: str,
    route: str,
    params: dict[str, str | int | bool | None],
    token: str,
    fetch: Fetch,
    allow_http: bool = False,
) -> tuple[str, bytes]:
    """Call a pipeline route and return the content type and body of a successful answer.

    Raises:
        ValueError: Invalid URL, unreachable controller, refused request or oversized answer.
    """
    query = {
        key: str(value).lower() if isinstance(value, bool) else value
        for key, value in params.items()
        if value is not None
    }
    url = controller_endpoint(controller_url, route, allow_http)
    if query:
        url = f"{url}?{urlencode(query)}"
    status, content_type, body = fetch(
        url, {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    )
    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError(f"Answer of {route} too large (> {MAX_RESPONSE_BYTES} bytes)")
    if status != 200:
        detail = _error_detail(body) or _REFUSAL_HINTS.get(status, "no detail")
        raise ValueError(f"The controller refused the request ({status}): {detail}")
    return content_type, body


def printable(text: str) -> str:
    """Remove the control characters (terminal escapes) of a text answer, except new lines and
    tabs: project names and titles come from the reports."""
    return "".join(c for c in text if c in "\n\t" or (c.isprintable() and c != "\x7f"))


def _json(body: bytes, route: str) -> dict:
    """Decode a JSON object answered by a pipeline route."""
    try:
        answer = json.loads(body)
    except ValueError as exc:
        raise ValueError(f"Unexpected answer of {route}: not JSON") from exc
    if not isinstance(answer, dict):
        raise ValueError(f"Unexpected answer of {route}: not a JSON object")
    return answer


# ── Command line ─────────────────────────────────────────────────────────────


def _fail(message: str, **fields: object) -> int:
    """Print an error as JSON on stderr and return the error exit code."""
    print(json.dumps(fields | {"error": message}), file=sys.stderr)
    return EXIT_ERROR


def _parser() -> argparse.ArgumentParser:
    """Build the parser of ``security-review-ci`` and its sub-commands."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--url",
        default=os.environ.get(URL_VARIABLE) or None,
        help=f"controller URL, for example https://secreview.example.com (default: {URL_VARIABLE})",
    )
    common.add_argument("--project", required=True, help="project name used for the reports")
    common.add_argument(
        "--token-stdin",
        action="store_true",
        help=f"read the token on stdin (default: {TOKEN_VARIABLE})",
    )
    common.add_argument("--cafile", help="CA bundle used to verify the controller certificate")
    common.add_argument(
        "--allow-http",
        action="store_true",
        help="allow plain HTTP to a non-loopback controller (the token would travel in clear)",
    )
    common.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT, help="seconds (default: 60)"
    )

    parser = argparse.ArgumentParser(
        prog="security-review-ci",
        description="Pipeline client of the security-review controller: gate, SARIF export and "
        "trend of a project through the REST API, with a ci token restricted to its projects. "
        "No database access.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    gate = commands.add_parser(
        "gate", parents=[common], help="fail when open findings reach a severity threshold"
    )
    gate.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default="high",
        help="lowest blocking severity (default: high)",
    )
    gate.add_argument("--report-id", type=int, default=None, help="check a single report")
    exporter = commands.add_parser(
        "sarif", parents=[common], help="download the findings as a SARIF 2.1.0 log"
    )
    exporter.add_argument("--include-resolved", action="store_true")
    exporter.add_argument("--output", "-o", help="file to write (default: standard output)")
    trend = commands.add_parser("trend", parents=[common], help="print the trend of a project")
    trend.add_argument("--days", type=int, default=90)
    trend.add_argument("--granularity", choices=["day", "week", "month"], default="week")
    trend.add_argument("--format", choices=["markdown", "json"], default="markdown")
    return parser


def _read_token(from_stdin: bool) -> str:
    """Return the token from stdin or from SECREVIEW_TOKEN (never from the command line, where
    it would show in the process list and the job log)."""
    token = sys.stdin.readline().strip() if from_stdin else os.environ.get(TOKEN_VARIABLE, "")
    if not token.strip():
        source = "stdin" if from_stdin else TOKEN_VARIABLE
        raise ValueError(f"No token: {source} is empty")
    return token.strip()


def main(argv: list[str] | None = None, fetch: Fetch | None = None) -> int:
    """Run ``security-review-ci`` and return its exit code (``fetch``: tests)."""
    args = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    gate = args.command == "gate"
    try:
        if not args.url:
            raise ValueError(f"No controller URL: give --url or set {URL_VARIABLE}")
        token = _read_token(args.token_stdin)
        fetch = fetch or urllib_fetch(args.cafile, args.timeout)
        if gate:
            params: dict[str, str | int | bool | None] = {
                "project": args.project,
                "fail_on": args.fail_on,
                "report_id": args.report_id,
            }
        elif args.command == "sarif":
            params = {"project": args.project, "include_resolved": args.include_resolved}
        else:
            params = {
                "project": args.project,
                "days": args.days,
                "granularity": args.granularity,
                "format": args.format,
            }
        _, body = call(args.url, args.command, params, token, fetch, args.allow_http)
        if gate:
            result = _json(body, "gate")
            if not isinstance(result.get("passed"), bool):
                raise ValueError("Unexpected answer of gate: no 'passed' field")
            print(json.dumps(result, indent=2))
            return EXIT_PASSED if result["passed"] else EXIT_BLOCKED
        if args.command == "sarif":
            log = _json(body, "sarif")
            text = json.dumps(log, indent=2)
            if not args.output:
                print(text)
                return EXIT_PASSED
            Path(args.output).write_text(text + "\n", encoding="utf-8")
            runs = log.get("runs") or [{}]
            count = len(runs[0].get("results") or []) if isinstance(runs[0], dict) else 0
            print(f"{count} result(s) written to {args.output}", file=sys.stderr)
            return EXIT_PASSED
        text = printable(body.decode("utf-8", errors="replace"))
        if args.format == "json":
            text = json.dumps(_json(body, "trend"), indent=2) + "\n"
        print(text, end="")
        return EXIT_PASSED
    except (ValueError, OSError) as exc:
        return _fail(str(exc), **({"passed": False} if gate else {}))


if __name__ == "__main__":
    sys.exit(main())
