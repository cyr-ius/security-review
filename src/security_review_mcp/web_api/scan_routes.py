"""Scan delegated by the scan_code tool of the MCP server (``POST /api/v1/scan/content``).

When SECREVIEW_MCP_SCAN_CONTROLLER_URL is set, or the delegation is turned on in the web
interface, the MCP server sends the fragment given to scan_code here, with the token of its
caller, so that the agent gets the matches of the rules and of the OpenGrep rules of the
controller. The route reads and stores nothing: it is the only one
an ``mcp`` token reaches (see http_server.BearerAuthMiddleware.role_allowed), and its body is
bounded by SECREVIEW_MAX_CONTENT_CHARS (see body_limit).
"""

import logging

from fastapi import APIRouter, HTTPException, status
from fastapi.concurrency import run_in_threadpool

from ..engines.opengrep import OpenGrepBusyError, OpenGrepError
from ..http_server import CONTENT_SCAN_PATH
from ..rules import codescan
from .deps import ContentScanIdentity, unprocessable
from .schemas import ContentScanRequest, ContentScanResult

logger = logging.getLogger("security_review_mcp.web")

router = APIRouter(tags=["scan"])


@router.post(CONTENT_SCAN_PATH)
async def scan_content(
    request: ContentScanRequest, identity: ContentScanIdentity
) -> ContentScanResult:
    """Scan a fragment for the scan_code tool with the rules, and OpenGrep when it is enabled.

    The matches are leads to verify, their secrets masked. 503 when OpenGrep cannot run: the MCP
    server then scans with its own rules.
    """
    try:
        result = await run_in_threadpool(codescan.scan_content, request.content, request.language)
    except ValueError as exc:
        raise unprocessable(exc) from exc
    except OpenGrepError as exc:
        # Generic messages, never the output of OpenGrep; a busy engine can be retried
        headers = {"Retry-After": "60"} if isinstance(exc, OpenGrepBusyError) else None
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), headers) from exc
    logger.debug(
        "Content scan by %s: %d match(es) with %s",
        identity.client,
        len(result["matches"]),
        ", ".join(result["engines"]),
    )
    return ContentScanResult.model_validate(result)
