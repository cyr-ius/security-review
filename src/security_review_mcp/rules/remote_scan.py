"""Scan of the scan_code tool delegated to the controller (the URL stored by the controller from
SECREVIEW_SCANCODE_DELEGATED or the web interface, or the deprecated
SECREVIEW_MCP_SCAN_CONTROLLER_URL).

The only outgoing connection of the MCP server, disabled by default: it sends the fragment given
to scan_code to ``POST /api/v1/scan/content`` of the controller with the bearer token of the
caller, so that the agent gets the matches of the rules and of the OpenGrep rules of the
controller. It goes to the configured URL only, without proxy nor redirect, with a time limit and
a bounded answer. The token and the answer are never logged: an error only carries a short
reason, and scan_code then scans with its own rules.

The tool start_codebase_scan goes the same way to ``POST /api/v1/scan/tickets`` to get the
single-use ticket of a codebase scan (see auth.scan_tickets), which it gives to the agent.
"""

import json
import urllib.error
import urllib.request
from typing import Any

from .. import __version__
from ..http_server import CONTENT_SCAN_PATH, SCAN_TICKET_PATH

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_REFUSAL_BYTES = 4096
MAX_REFUSAL_CHARS = 300
ENGINES = frozenset({"rules", "opengrep"})


class RemoteScanError(Exception):
    """The controller did not scan the fragment (the message names no token nor content)."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: the token is only sent to the configured URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        return None


# No proxy (the controller is an internal service) and no redirect
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def _matches(value: Any) -> list[dict]:
    """The matches of the answer, checked to be a list of objects."""
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise RemoteScanError("the controller sent an unexpected answer")
    return value


def _post(controller_url: str, path: str, authorization: str, body: dict, timeout: int) -> dict:
    """POST ``body`` to ``path`` of the controller with the ``authorization`` header of the
    caller and return the JSON object of the answer.

    Raises:
        RemoteScanError: If the controller cannot be reached, refuses the request (with the
            short reason it gives for a 403 or 422) or sends an unexpected answer.
    """
    request = urllib.request.Request(
        f"{controller_url}{path}",
        data=json.dumps(body).encode(),
        method="POST",
        headers={
            "Authorization": authorization,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"secreview-mcp/{__version__}",
        },
    )
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        reason = _refusal(exc) if exc.code in (403, 422) else ""
        exc.close()
        raise RemoteScanError(f"the controller answered HTTP {exc.code}{reason}") from None
    except urllib.error.URLError, OSError:
        raise RemoteScanError("the controller cannot be reached") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise RemoteScanError("the answer of the controller is too large")
    try:
        document = json.loads(raw)
    except ValueError:
        raise RemoteScanError("the controller sent invalid JSON") from None
    if not isinstance(document, dict):
        raise RemoteScanError("the controller sent an unexpected answer")
    return document


def _refusal(exc: urllib.error.HTTPError) -> str:
    """Short reason of a refusal (``detail`` of the answer), printable and bounded."""
    try:
        detail = json.loads(exc.read(MAX_REFUSAL_BYTES)).get("detail")
    except ValueError, AttributeError, OSError:
        return ""
    if not isinstance(detail, str):
        return ""
    return ": " + "".join(c if c.isprintable() else "?" for c in detail)[:MAX_REFUSAL_CHARS]


def scan(
    controller_url: str, authorization: str, content: str, language: str, timeout: int
) -> dict:
    """Scan ``content`` on the controller at ``controller_url`` with the ``authorization``
    header of the caller.

    Returns:
        ``matches``, ``suppressed`` and ``engines`` of the answer.

    Raises:
        RemoteScanError: If the controller cannot be reached or refuses the scan.
    """
    document = _post(
        controller_url,
        CONTENT_SCAN_PATH,
        authorization,
        {"content": content, "language": language},
        timeout,
    )
    engines = document.get("engines")
    if not isinstance(engines, list) or not set(engines) <= ENGINES:
        raise RemoteScanError("the controller sent an unexpected answer")
    return {
        "matches": _matches(document.get("matches")),
        "suppressed": _matches(document.get("suppressed")),
        "engines": engines,
    }


def request_ticket(controller_url: str, authorization: str, project: str, timeout: int) -> dict:
    """Ask the controller for a single-use ticket of a codebase scan of ``project`` (see
    auth.scan_tickets), with the ``authorization`` header of the caller.

    Returns:
        ``ticket``, ``project``, ``expires_at``, ``controller_url`` (public URL, may be None)
        and ``client_download``.

    Raises:
        RemoteScanError: If the controller cannot be reached, refuses or answers unexpectedly.
    """
    document = _post(controller_url, SCAN_TICKET_PATH, authorization, {"project": project}, timeout)
    fields = ("ticket", "project", "expires_at")
    if not all(isinstance(document.get(name), str) for name in fields):
        raise RemoteScanError("the controller sent an unexpected answer")
    url = document.get("controller_url")
    return {name: document[name] for name in fields} | {
        "controller_url": url if isinstance(url, str) else None,
        "client_download": document.get("client_download") is True,
    }
