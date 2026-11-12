"""Client of the scan engines (``security-review-scan-engine``), used by the controller only.

With SECREVIEW_SCAN_ENGINE_TOKEN, the controller sends the files of a code scan or a fragment of
scan_code to ``POST /engine/v1/scan`` of an enrolled engine, with the shared secret as a bearer
token. It goes to the URL the engine gave at its enrollment only (an IP address of
SECREVIEW_SCAN_ENGINE_NETWORKS, see engine_clients), without proxy (the engines are an internal
service) nor redirect, with a time limit and a bounded
answer, which is validated before it becomes matches. The secret and the content are never
logged: an error only carries a short reason.

The MCP server never loads this module (no outgoing connection from the MCP server).
"""

import http.client
import json
import logging
import urllib.error
import urllib.request
from collections.abc import Sequence

from pydantic import ValidationError

from .. import __version__
from ..rules import scanner
from .local import Source
from .opengrep import OpenGrepBusyError
from .protocol import ENGINE_SCAN_PATH, EngineRequest, EngineResponse, EngineSource

logger = logging.getLogger("security_review_mcp.engines")

UNAVAILABLE = "No scan engine could scan the files; retry later"
# Smallest bound of an answer, whatever SECREVIEW_MAX_SCAN_REQUEST_MB
MIN_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_REFUSAL_BYTES = 4096
MAX_REFUSAL_CHARS = 300


class ScanEngineError(OpenGrepBusyError):
    """No scan engine scanned the files: answered like a busy OpenGrep (503, Retry-After)."""


class ScanEngineBusyError(ScanEngineError):
    """The engine refused the scan because all its OpenGrep slots are taken."""


class ScanEngineUnavailableError(ScanEngineError):
    """The engine cannot be reached, failed or answered unexpectedly."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: the secret is only sent to the configured URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        return None


# No proxy (the engines are an internal service) and no redirect
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def _refusal(exc: urllib.error.HTTPError) -> str:
    """Short reason of a refusal (``detail`` of the answer), printable and bounded."""
    try:
        detail = json.loads(exc.read(MAX_REFUSAL_BYTES)).get("detail")
    except ValueError, AttributeError, OSError:
        return "the scan engine refused the files"
    if not isinstance(detail, str):
        return "the scan engine refused the files"
    return "".join(c if c.isprintable() else "?" for c in detail)[:MAX_REFUSAL_CHARS]


def scan(
    engine_url: str,
    token: str,
    sources: Sequence[Source],
    fragment: bool,
    timeout: int,
    max_response_bytes: int,
) -> dict:
    """Scan ``sources`` on the engines at ``engine_url``, as engines.local.scan does.

    Returns:
        ``files`` (one entry per source, in the same order) and ``engines``.

    Raises:
        ValueError: If the engine refused the files (422), with its reason.
        ScanEngineBusyError: If the engine is busy with other scans (429).
        ScanEngineUnavailableError: If the engine cannot be reached, failed or answered
            unexpectedly.
    """
    body = EngineRequest(
        fragment=fragment,
        sources=[
            EngineSource(path=s.path, language=s.language, content=s.content) for s in sources
        ],
    )
    request = urllib.request.Request(
        f"{engine_url}{ENGINE_SCAN_PATH}",
        data=body.model_dump_json().encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"secreview-controller/{__version__}",
        },
    )
    limit = max(MIN_RESPONSE_BYTES, max_response_bytes)
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            raw = response.read(limit + 1)
    except urllib.error.HTTPError as exc:
        try:
            if exc.code == 422:
                raise ValueError(_refusal(exc)) from None
            if exc.code == 429:
                raise ScanEngineBusyError(
                    "The scan engines are busy with other scans; retry later"
                ) from None
        finally:
            exc.close()
        logger.warning("Scan engine answered HTTP %d", exc.code)
        raise ScanEngineUnavailableError(UNAVAILABLE) from None
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        # HTTPException: answer cut short (IncompleteRead) or malformed, not an OSError
        # The reason names the host or the error, never the secret nor the content
        logger.warning("Scan engine unreachable: %s", type(exc).__name__)
        raise ScanEngineUnavailableError(UNAVAILABLE) from None
    if len(raw) > limit:
        logger.warning("Scan engine answer above %d bytes", limit)
        raise ScanEngineUnavailableError("The answer of the scan engine is too large")
    try:
        result = EngineResponse.model_validate_json(raw)
    except ValidationError:
        logger.warning("Scan engine sent an unexpected answer")
        raise ScanEngineUnavailableError("The scan engine sent an unexpected answer") from None
    if len(result.files) != len(sources):
        logger.warning("Scan engine answered %d files for %d", len(result.files), len(sources))
        raise ScanEngineUnavailableError("The scan engine sent an unexpected answer")
    return {
        "files": [
            _file(entry.model_dump(mode="json", exclude_unset=True)) for entry in result.files
        ],
        "engines": result.engines,
    }


def _file(entry: dict) -> dict:
    """An answered file, its excerpts masked again (the engine masks them already)."""
    for name in ("matches", "suppressed"):
        for match in entry[name]:
            match["excerpt"] = scanner.redact_secrets(match["excerpt"])
    return entry
