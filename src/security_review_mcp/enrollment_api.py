"""Public enrollment endpoint (``POST /api/v1/enroll``) served by the HTTP MCP server.

Clients without a token (``security-review-mcp enroll``, scripts) request one here; an
administrator approves the request on the controller. The endpoint lives next to the MCP
endpoint, so the controller exposes no unauthenticated write endpoint and can stay private.

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

from . import token_store
from .config import get_settings
from .http_server import ENROLL_PATH, LOOPBACK_HOSTS, has_credentials, hash_token

logger = logging.getLogger("security_review_mcp.enrollment")

# The body holds three short fields: anything larger is refused before parsing
MAX_BODY_BYTES = 4096


class EnrollmentRequest(BaseModel):
    """Body of the public POST /enroll.

    Without credentials it requests a new project token; with the bearer token of a client
    already restricted to other projects it requests one more project for that token.
    """

    project: str = Field(min_length=1, max_length=token_store.MAX_PROJECT_CHARS)
    label: str | None = Field(default=None, max_length=token_store.MAX_LABEL_CHARS)  # + suffix
    requested_by: str | None = Field(default=None, max_length=token_store.MAX_REQUESTED_BY_CHARS)


class EnrollmentError(Exception):
    """An enrollment request refused with an HTTP status."""

    def __init__(self, status: int, detail: Any, headers: dict[str, str] | None = None) -> None:
        super().__init__(str(detail))
        self.status = status
        self.detail = detail
        self.headers = headers


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


async def _enrolled_token(request: Request) -> str | None:
    """Id of the active token presented to the public enrollment endpoint, or None without one.

    The endpoint is public (the middleware does not authenticate it), so the token is checked
    here: a complementary enrollment must come from the holder of the token.
    """
    authorization = request.headers.get("authorization", "")
    if not has_credentials(authorization):
        return None
    scheme, _, credentials = authorization.strip().partition(" ")
    info = None
    if scheme.lower() == "bearer":
        lookup = token_store.DatabaseTokenStore().lookup
        info = await run_in_threadpool(lookup, hash_token(credentials.strip()))
    if info is None:
        raise EnrollmentError(
            401,
            "Missing or invalid bearer token",
            {"WWW-Authenticate": 'Bearer realm="security-review-mcp"'},
        )
    if info.pending:
        raise EnrollmentError(
            403, "This token is waiting for an administrator to approve its enrollment"
        )
    return info.token_id


async def _enroll(request: Request) -> dict[str, Any]:
    """Validate and store an enrollment request; return the created request."""
    if not get_settings().enrollment:
        raise EnrollmentError(404, "Enrollment is disabled")
    if request.app.state.allow_open and not await run_in_threadpool(
        token_store.DatabaseTokenStore().has_tokens
    ):
        raise EnrollmentError(409, "Authentication is not configured: no token is needed")
    body = _parse(await _read_body(request))
    address = request.client.host if request.client else None
    token_id = await _enrolled_token(request)
    try:
        if token_id is None:
            created = await run_in_threadpool(
                token_store.request_enrollment,
                body.project,
                body.label,
                body.requested_by,
                address,
            )
        else:
            created = await run_in_threadpool(
                token_store.request_additional_project,
                token_id,
                body.project,
                body.requested_by,
                address,
            )
    except ValueError as exc:
        raise EnrollmentError(422, str(exc)) from exc
    logger.info(
        "Enrollment (%s) requested for project %s (%s) from %s",
        created["kind"],
        created["project"],
        created["label"],
        address or "unknown",
    )
    return created


async def enroll(request: Request) -> JSONResponse:
    """Request access to a project (public endpoint).

    Without credentials a new token is returned once; it works only after an administrator
    approves the request. With the bearer token of a client restricted to other projects, the
    project is requested for that token (complementary enrollment, no new secret).
    """
    try:
        created = await _enroll(request)
    except EnrollmentError as exc:
        return JSONResponse({"detail": exc.detail}, status_code=exc.status, headers=exc.headers)
    return JSONResponse(created, status_code=201)


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
