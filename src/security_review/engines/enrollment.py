"""Enrollment of the scan engines and their OAuth access tokens, served by the controller.

Served only when SECREVIEW_SCAN_ENGINE_TOKEN is set, in front of the bearer middleware of the
controller (the engines have no token of the database yet):

- ``POST /engine/v1/enroll``, behind the shared secret of the engines (protocol.EngineAuth,
  checked before the body is read): the engine gets its own OAuth client, a client id and a
  client secret given once (see auth.engine_clients).
- ``POST /engine/v1/token``: OAuth 2.0 ``client_credentials`` grant (RFC 6749 §4.4), the client
  authenticated by HTTP Basic (``client_secret_basic``) or in the form
  (``client_secret_post``). The answer is an access token of the ``engine`` role, which only
  reaches the routes of the REST API under ``/api/v1/engine/`` (see web_api.engine_routes).

Both bodies are bounded. The MCP server never loads this module.
"""

import base64
import binascii
from urllib.parse import parse_qs, unquote

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.types import ASGIApp

from .. import __version__
from ..auth import engine_clients
from ..http_server import BodyLimit
from .protocol import (
    ENGINE_ENROLL_PATH,
    ENGINE_TOKEN_PATH,
    EngineAuth,
    EnrollRequest,
    EnrollResponse,
    TokenResponse,
)

# Body of an enrollment (a name and a version) and of a token request (a form)
MAX_BODY_BYTES = 4096
GRANT_TYPE = "client_credentials"


def _token_error(code: int, error: str, description: str) -> JSONResponse:
    """An OAuth error answer (RFC 6749 §5.2), never cached."""
    headers = {"Cache-Control": "no-store", "Pragma": "no-cache"}
    if code == status.HTTP_401_UNAUTHORIZED:
        headers["WWW-Authenticate"] = 'Basic realm="secreview-scan-engine"'
    return JSONResponse(
        {"error": error, "error_description": description}, status_code=code, headers=headers
    )


def _basic_credentials(authorization: str) -> tuple[str, str] | None:
    """Client id and secret of an HTTP Basic header (form-encoded, RFC 6749 §2.3.1)."""
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "basic":
        return None
    try:
        decoded = base64.b64decode(value.strip(), validate=True).decode()
    except binascii.Error, UnicodeDecodeError:
        return None
    client_id, separator, secret = decoded.partition(":")
    return (unquote(client_id), unquote(secret)) if separator else None


def create_app() -> FastAPI:
    """Build the enrollment and token routes (without their protections, see routes)."""
    app = FastAPI(
        title="Security Review enrollment of the scan engines",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.post(ENGINE_ENROLL_PATH, status_code=status.HTTP_201_CREATED)
    async def enroll(body: EnrollRequest, request: Request) -> EnrollResponse:
        """Enroll the engine that holds the shared secret; 422 when its URL is refused, 409
        when too many are enrolled."""
        address = request.client.host if request.client else None
        try:
            url = await run_in_threadpool(engine_clients.check_engine_url, body.url)
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
        try:
            credentials = await run_in_threadpool(
                engine_clients.enroll, body.name, body.version, url, address
            )
        except ValueError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
        return EnrollResponse(**credentials)

    @app.post(ENGINE_TOKEN_PATH, response_model=TokenResponse)
    async def token(request: Request) -> JSONResponse:
        """Issue an access token to an enrolled engine (client_credentials)."""
        try:
            form = parse_qs((await request.body()).decode(), max_num_fields=10)
        except UnicodeDecodeError, ValueError:
            return _token_error(400, "invalid_request", "The body must be a form")
        fields = {key: values[0] for key, values in form.items() if len(values) == 1}
        if fields.get("grant_type") != GRANT_TYPE:
            return _token_error(400, "unsupported_grant_type", f"Only {GRANT_TYPE} is supported")
        credentials = _basic_credentials(request.headers.get("authorization", "")) or (
            fields.get("client_id", ""),
            fields.get("client_secret", ""),
        )
        try:
            access_token, expires_in = await run_in_threadpool(
                engine_clients.issue_token, *credentials
            )
        except engine_clients.InvalidClientError:
            return _token_error(401, "invalid_client", "Unknown or revoked scan engine")
        return JSONResponse(
            TokenResponse(access_token=access_token, expires_in=expires_in).model_dump(),
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    return app


def routes(token: str) -> dict[str, ASGIApp]:
    """The enrollment behind the shared secret of the engines, the token endpoint behind the
    credentials of each engine; both bodies bounded."""

    def body_limit(_path: str) -> tuple[int, str]:
        """Bound of an enrollment or token request."""
        return MAX_BODY_BYTES, "enrollment of the scan engines)"

    app = BodyLimit(create_app(), body_limit)
    return {ENGINE_ENROLL_PATH: EngineAuth(app, token), ENGINE_TOKEN_PATH: app}
