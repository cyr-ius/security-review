"""Bound of the request bodies of the controller (413 above), before FastAPI parses them.

Every route takes a small JSON body (MAX_BODY_BYTES), including the public ones (login, OIDC),
except the pack imports, which carry a TOML file, and the pipeline scans, which carry the files
of a whole codebase (SECREVIEW_MAX_SCAN_REQUEST_MB). It runs inside the bearer middleware, so a
request to a protected route without a valid token is refused before its body is read.
"""

import logging

from fastapi import status
from fastapi.responses import JSONResponse
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .. import standards
from ..config import get_settings

logger = logging.getLogger("security_review_mcp.web")

# Body of any route of the controller, unless a prefix below gives another bound
MAX_BODY_BYTES = 512 * 1024
PACK_PREFIX = "/api/v1/packs/"
# The TOML text of a pack is escaped in a JSON string (quotes, backslashes, new lines)
MAX_PACK_BODY_BYTES = 2 * standards.MAX_PACK_BYTES
SCAN_PREFIX = "/api/v1/ci/scan/"


def body_limit(path: str) -> tuple[int, str]:
    """Bound (in bytes) of the body of a request to ``path``, and the hint of its 413 answer."""
    if path.startswith(SCAN_PREFIX):
        limit = get_settings().max_scan_request_mb * 1024 * 1024
        return limit, "SECREVIEW_MAX_SCAN_REQUEST_MB): exclude files or raise the limit"
    if path.startswith(PACK_PREFIX):
        return MAX_PACK_BODY_BYTES, "TOML pack)"
    return MAX_BODY_BYTES, "JSON request)"


class BodyLimit:
    """Refuse (413) a request whose body exceeds the bound of its route (see body_limit).

    The declared ``Content-Length`` is checked first; a body without it (chunked) is read here,
    bounded, and replayed to the application.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit, hint = body_limit(scope.get("path", ""))
        declared = Headers(scope=scope).get("content-length", "")
        if declared.isdigit() and int(declared) > limit:
            await self._too_large(scope, receive, send, limit, hint)
            return
        chunks: list[bytes] = []
        size = 0
        more = True
        while more:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > limit:
                await self._too_large(scope, receive, send, limit, hint)
                return
            chunks.append(chunk)
            more = message.get("more_body", False)
        body = b"".join(chunks)
        replayed = False

        async def replay() -> Message:
            """Give the buffered body once, then the next messages of the connection."""
            nonlocal replayed
            if replayed:
                return await receive()
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay, send)

    @staticmethod
    async def _too_large(scope: Scope, receive: Receive, send: Send, limit: int, hint: str) -> None:
        """Send the 413 answer."""
        logger.warning("Rejected request body above %d bytes: %s", limit, scope.get("path"))
        answer = JSONResponse(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            content={"detail": f"Request body too large (limit {limit} bytes, {hint}"},
        )
        await answer(scope, receive, send)
