"""Scan of the scan_code tool delegated to the controller (SECREVIEW_MCP_SCAN_CONTROLLER_URL, or
the public URL of the controller when the delegation is turned on in the web interface).

The only outgoing connection of the MCP server, disabled by default: it sends the fragment given
to scan_code to ``POST /api/v1/scan/content`` of the controller with the bearer token of the
caller, so that the agent gets the matches of the rules and of the OpenGrep rules of the
controller. It goes to the configured URL only, without proxy nor redirect, with a time limit and
a bounded answer. The token and the answer are never logged: an error only carries a short
reason, and scan_code then scans with its own rules.
"""

import json
import urllib.error
import urllib.request
from typing import Any

from .. import __version__
from ..http_server import CONTENT_SCAN_PATH

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
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
    request = urllib.request.Request(
        f"{controller_url}{CONTENT_SCAN_PATH}",
        data=json.dumps({"content": content, "language": language}).encode(),
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
        exc.close()
        raise RemoteScanError(f"the controller answered HTTP {exc.code}") from None
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
    engines = document.get("engines")
    if not isinstance(engines, list) or not set(engines) <= ENGINES:
        raise RemoteScanError("the controller sent an unexpected answer")
    return {
        "matches": _matches(document.get("matches")),
        "suppressed": _matches(document.get("suppressed")),
        "engines": engines,
    }
