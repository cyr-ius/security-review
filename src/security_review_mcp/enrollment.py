"""Client side of the enrollment: request a project token, or one more project for an
existing token (complementary enrollment), from a shared server.

Used by ``security-review-mcp enroll``. This is the only place where the package opens an
outgoing connection, and only to the server URL the operator gives on the command line: the
MCP server itself never does.
"""

import json
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .http_server import ENROLL_PATH, LOOPBACK_HOSTS

MAX_RESPONSE_BYTES = 64 * 1024
DEFAULT_TIMEOUT = 30.0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects: the token must never be sent or received elsewhere (or over HTTP)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        """Return None so that urllib raises an HTTPError for the 3xx answer."""
        return None


def enrollment_url(server_url: str, allow_http: bool = False) -> str:
    """Return the enrollment endpoint of a server given by its base or MCP URL.

    Plain HTTP is refused except on a loopback address or with ``allow_http``: the answer
    carries the new token.
    """
    parts = urlsplit(server_url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"Invalid server URL '{server_url}' (expected https://host[:port])")
    if parts.username or parts.password:
        raise ValueError("The server URL must not contain credentials")
    if parts.scheme == "http" and parts.hostname not in LOOPBACK_HOSTS and not allow_http:
        raise ValueError(
            "Refusing to send an enrollment request over plain HTTP (see --allow-http)"
        )
    path = parts.path.rstrip("/").removesuffix("/mcp")
    return f"{parts.scheme}://{parts.netloc}{path}{ENROLL_PATH}"


def _error_detail(error: urllib.error.HTTPError) -> str:
    """Extract the error message of a FastAPI answer (``detail``), bounded."""
    try:
        body = json.loads(error.read(MAX_RESPONSE_BYTES))
    except (OSError, ValueError):
        return error.reason or "no detail"
    detail = body.get("detail") if isinstance(body, dict) else None
    if isinstance(detail, list):
        # Pydantic validation errors
        return "; ".join(str(item.get("msg", item)) for item in detail if isinstance(item, dict))
    return str(detail or body)


def request_enrollment(
    server_url: str,
    project: str,
    label: str | None = None,
    requested_by: str | None = None,
    cafile: str | None = None,
    allow_http: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
    token: str | None = None,
) -> dict:
    """Send an enrollment request to a shared server and return its answer.

    Without ``token`` the answer carries a new token. With the token of a client restricted to
    other projects, the project is requested for that token (no new secret); the token is only
    sent to the enrollment URL, which refuses plain HTTP and redirects like any request.

    Raises:
        ValueError: Invalid URL, unreachable server or request refused by the server.
    """
    url = enrollment_url(server_url, allow_http)
    payload = {"project": project, "label": label, "requested_by": requested_by}
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST"
    )
    context = ssl.create_default_context(cafile=cafile)
    opener = urllib.request.build_opener(
        _NoRedirect(), urllib.request.HTTPSHandler(context=context)
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as exc:
        detail = _error_detail(exc)
        raise ValueError(f"The server refused the request ({exc.code}): {detail}") from exc
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise ValueError(f"Cannot reach {url}: {reason}") from exc
    try:
        answer = json.loads(body)
    except ValueError as exc:
        raise ValueError(f"Unexpected answer from {url}") from exc
    expected = "status" if token is not None else "token"
    if not isinstance(answer, dict) or expected not in answer:
        raise ValueError(f"Unexpected answer from {url}")
    return answer
