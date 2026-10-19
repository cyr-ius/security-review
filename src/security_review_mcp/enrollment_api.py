"""Public enrollment endpoint (``POST /api/v1/enroll``) served by the HTTP MCP server.

Clients without a token (``security-review-mcp enroll``, scripts) request their project here:
it waits for an administrator (see access_control.enroll_project) and no token is returned. The user
then signs in to the web interface and creates a personal MCP token. The endpoint lives next to
the MCP endpoint, so the controller exposes no unauthenticated write endpoint and can stay
private.

Plain Starlette (no FastAPI): the MCP server does not serve the web API. Errors use the same
``{"detail": ...}`` body as the controller API.
"""

import logging
from typing import Any

from pydantic import BaseModel, Field, ValidationError
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import access_control, token_store
from .config import get_settings
from .http_server import ENROLL_PATH, LOOPBACK_HOSTS
from .project_names import ProjectName

logger = logging.getLogger("security_review_mcp.enrollment")

# The body holds two short fields: anything larger is refused before parsing
MAX_BODY_BYTES = 4096


class EnrollmentRequest(BaseModel):
    """Body of the public POST /enroll: the project to request and who asks for it."""

    project: ProjectName
    requested_by: str | None = Field(default=None, max_length=access_control.MAX_REQUESTED_BY_CHARS)


class EnrollmentError(Exception):
    """An enrollment request refused with an HTTP status."""

    def __init__(self, status: int, detail: Any) -> None:
        super().__init__(str(detail))
        self.status = status
        self.detail = detail


async def _read_body(request: Request) -> bytes:
    """Read the request body, refusing it beyond MAX_BODY_BYTES."""
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_BODY_BYTES:
            raise EnrollmentError(413, "Request body too large")
    return body


def _parse(body: bytes) -> EnrollmentRequest:
    """Validate the JSON body (422 with the validation errors otherwise)."""
    try:
        return EnrollmentRequest.model_validate_json(body)
    except ValidationError as exc:
        errors = [
            {"loc": list(error["loc"]), "msg": error["msg"], "type": error["type"]}
            for error in exc.errors(include_url=False, include_input=False)
        ]
        raise EnrollmentError(422, errors) from exc


async def _enroll(request: Request) -> dict[str, Any]:
    """Validate the request and enroll its project; return what the user does next."""
    if not get_settings().enrollment:
        raise EnrollmentError(404, "Enrollment is disabled")
    if request.app.state.allow_open and not await run_in_threadpool(
        token_store.DatabaseTokenStore().has_tokens
    ):
        raise EnrollmentError(409, "Authentication is not configured: no token is needed")
    body = _parse(await _read_body(request))
    address = request.client.host if request.client else None
    try:
        enrolled = await run_in_threadpool(
            access_control.enroll_project, body.project, body.requested_by, address
        )
    except access_control.EnrollmentThrottled as exc:
        raise EnrollmentError(429, str(exc)) from exc
    except ValueError as exc:
        raise EnrollmentError(422, str(exc)) from exc
    logger.info("Project %s enrolled from %s", enrolled["project"], address or "unknown")
    return enrolled


async def enroll(request: Request) -> JSONResponse:
    """Request a project (public endpoint): it waits for an administrator, no token is returned.

    The answer (202, the same whether the project existed or not) gives the URL of the web
    interface, where the user creates a personal MCP token, and the next steps.
    """
    try:
        enrolled = await _enroll(request)
    except EnrollmentError as exc:
        return JSONResponse({"detail": exc.detail}, status_code=exc.status)
    return JSONResponse(enrolled, status_code=202)


def create_app(host: str = "127.0.0.1", allow_open: bool = False) -> Starlette:
    """Build the enrollment endpoint app (protected against DNS rebinding on loopback).

    ``allow_open`` is the one given to http_server.build_mcp_app: an open server without any
    token needs no enrollment, a closed one accepts requests even before its first token.
    """
    middleware = []
    if host in LOOPBACK_HOSTS:
        # Same protection as the MCP endpoint against DNS rebinding on a local server
        middleware.append(
            Middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]"])
        )
    app = Starlette(routes=[Route(ENROLL_PATH, enroll, methods=["POST"])], middleware=middleware)
    app.state.allow_open = allow_open
    return app
