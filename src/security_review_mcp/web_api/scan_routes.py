"""Scan delegated by the scan_code tool of the MCP server (``POST /api/v1/scan/content``).

When the delegation is turned on (SECREVIEW_SCANCODE_DELEGATED on the controller, or the web
interface), the MCP server sends the fragment given to scan_code here, with the token of its
caller, so that the agent gets the matches of the rules and of the OpenGrep rules of the
controller. While the delegation is off, the route answers 404: an ``mcp`` token cannot make the
controller run OpenGrep for a feature that is not in use. The route reads and stores nothing,
and its body is bounded by SECREVIEW_MAX_CONTENT_CHARS (see body_limit).

The MCP tool start_codebase_scan asks here for a single-use ticket (``POST /api/v1/scan/tickets``,
see auth.scan_tickets), with which ``security-review-ci`` sends the files of the workstation to
the scans of one project. These two routes are the only ones an ``mcp`` token reaches (see
http_server.BearerAuthMiddleware.role_allowed).
"""

import logging

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool

from .. import app_settings
from ..auth import scan_tickets
from ..config import get_settings
from ..engines.opengrep import OpenGrepBusyError, OpenGrepError
from ..http_server import CONTENT_SCAN_PATH, SCAN_TICKET_PATH
from ..rules import codescan
from .deps import ContentScanIdentity, unprocessable
from .schemas import ContentScanRequest, ContentScanResult, ScanTicketRequest, ScanTicketResult

logger = logging.getLogger("security_review_mcp.web")

router = APIRouter(tags=["scan"])


@router.post(CONTENT_SCAN_PATH)
async def scan_content(
    request: ContentScanRequest, identity: ContentScanIdentity
) -> ContentScanResult:
    """Scan a fragment for the scan_code tool with the rules, and OpenGrep when it is enabled.

    The matches are leads to verify, their secrets masked. 404 while the delegation of scan_code
    is off; 503 when OpenGrep cannot run: the MCP server then scans with its own rules.
    """
    if not await run_in_threadpool(app_settings.mcp_scan_delegated):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "The delegation of scan_code is off")
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


@router.post(SCAN_TICKET_PATH, status_code=status.HTTP_201_CREATED)
async def issue_scan_ticket(
    body: ScanTicketRequest, identity: ContentScanIdentity, request: Request
) -> ScanTicketResult:
    """Issue a single-use ticket of a codebase scan for the start_codebase_scan tool.

    With it, ``security-review-ci scan-code`` and ``scan-deps`` (``--token-stdin``) send the files
    of the workstation to the scans of the project (both, or the one of ``scope``), once each,
    before it expires. 422 when the
    caller may not save reports on the project or holds too many tickets.
    """
    state = dict(request.scope.get("state") or {})
    try:
        ticket = await run_in_threadpool(scan_tickets.issue, body.project, state, body.scope)
    except ValueError as exc:
        raise unprocessable(exc) from exc
    controller_url = await run_in_threadpool(app_settings.controller_url)
    logger.info("Scan ticket of %r issued to %s", ticket["project"], identity.client)
    return ScanTicketResult(
        **ticket,
        controller_url=controller_url,
        client_download=get_settings().ci_client_download_enabled,
    )
