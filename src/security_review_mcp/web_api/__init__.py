"""Controller: REST API (``/api/v1``) and the bundled Angular application (``/ui``).

Served by ``security-review-controller serve``, in its own process, apart from the MCP server
(see http_server). The bearer middleware authenticates the requests and stores the token label
and role in the ASGI scope; ``deps`` checks the permissions of each route.

The routes are split by domain (``*_routes`` modules) and every answer has a response model
(``schemas``). The services are synchronous (SQLModel sessions), so every call runs in the
thread pool.
"""

import base64
import hashlib
import logging
import re
import threading
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from mcp.server.auth.handlers.metadata import MetadataHandler
from mcp.server.auth.routes import build_metadata, cors_middleware, create_auth_routes
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from pydantic import AnyHttpUrl, ConfigDict, TypeAdapter
from starlette.datastructures import URLPath
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.routing import BaseRoute, Match, NoMatchFound, Route
from starlette.types import Receive, Scope, Send

from .. import __version__, app_settings
from ..auth import oauth_server, oidc, rate_limit
from ..config import Settings, get_settings, secret_value
from ..http_server import (
    API_HEALTH_PATH,
    DOCS_ASSETS_PREFIX,
    DOCS_PATH,
    FAVICON_PATH,
    HEALTH_PATH,
    LOOPBACK_HOSTS,
    METRICS_PATH,
    OAUTH_METADATA_PATH,
    OAUTH_PATHS,
    OPENAPI_PATH,
    BodyLimit,
)
from ..observability import metrics
from ..reports import services
from . import (
    access_routes,
    account_routes,
    admin_routes,
    auth_routes,
    ci_client_routes,
    ci_routes,
    connector_routes,
    oauth_routes,
    report_routes,
    rule_routes,
    opengrep_routes,
    token_routes,
)
from .auth_routes import OidcLogins
from .body_limit import body_limit
from .deps import MetricsIdentity, current_identity
from .schemas import HealthStatus, Identity

__all__ = [
    "BUNDLED_UI_DIR",
    "FAVICON",
    "Identity",
    "OAuthRoutes",
    "OidcLogins",
    "SinglePageApp",
    "create_app",
    "resolve_ui_dir",
]

logger = logging.getLogger("security_review_mcp.web")

BUNDLED_UI_DIR = Path(__file__).parent.parent / "webui"
# Icon of the web interface and of the Swagger documentation (the brand mark of the UI)
FAVICON = (Path(__file__).parent.parent / "favicon.svg").read_bytes()

# The Angular build loads no inline script and no external resource. Component styles are
# injected as <style> elements at runtime, hence 'unsafe-inline' for styles only.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; "
    "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}

# Files of Swagger UI in the web interface build (web/angular.json copies them)
SWAGGER_FILES = ("swagger-ui-bundle.js", "swagger-ui.css")
# Swagger UI never sends the schema to the online validator of swagger.io
SWAGGER_PARAMETERS = {"validatorUrl": None}
_INLINE_SCRIPT = re.compile(r"<script>(.*?)</script>", re.DOTALL | re.IGNORECASE)


def swagger_assets_dir(configured: str | None) -> Path | None:
    """Directory of the Swagger UI files of the web interface build, or None when missing."""
    directory = (Path(configured) if configured else BUNDLED_UI_DIR) / "swagger"
    if all((directory / name).is_file() for name in SWAGGER_FILES):
        return directory
    return None


def docs_security_policy(html: str) -> str:
    """CSP of the Swagger page: its own files only, and its inline script by its digest."""
    digests = " ".join(
        f"'sha256-{base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()}'"
        for script in _INLINE_SCRIPT.findall(html)
    )
    return (
        f"default-src 'none'; script-src 'self' {digests}; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; "
        "frame-ancestors 'none'"
    )


# Every route needs an authenticated identity, even those that do not use it (health)
api_router = APIRouter(prefix="/api/v1", dependencies=[Depends(current_identity)])
for _domain in (
    account_routes,
    report_routes,
    rule_routes,
    opengrep_routes,
    token_routes,
    admin_routes,
    access_routes,
    connector_routes,
    oauth_routes,
):
    api_router.include_router(_domain.router)


# ── Static files ─────────────────────────────────────────────────────────────


class SinglePageApp(StaticFiles):
    """Static files with a fallback on index.html for the client-side routes."""

    async def get_response(self, path: str, scope: Scope) -> Response:
        """Serve a file, or index.html for a client-side route, with the security headers."""
        try:
            response = await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code != status.HTTP_404_NOT_FOUND:
                raise
            response = await super().get_response("index.html", scope)
        response.headers.update(SECURITY_HEADERS)
        if path in ("", ".", "index.html") or response.media_type == "text/html":
            # The page references hashed bundles: always revalidate it after an upgrade
            response.headers["Cache-Control"] = "no-cache"
        return response


def resolve_ui_dir(configured: str | None) -> Path | None:
    """Directory of the built Angular application, or None when it is not available."""
    directory = Path(configured) if configured else BUNDLED_UI_DIR
    if (directory / "index.html").is_file():
        return directory
    if configured:
        raise ValueError(f"SECREVIEW_WEB_UI_DIR: no index.html in {directory}")
    return None


# ── Application ──────────────────────────────────────────────────────────────


def oauth_routes_of(issuer: str | None, settings: Settings | None = None) -> list[BaseRoute]:
    """Routes of the OAuth authorization server of the MCP clients (see oauth_server): those of
    the MCP SDK, at the root of the controller URL, its issuer. Every client is public (PKCE)
    with the single ``mcp`` scope; registration and revocation are served.

    Raises:
        ValueError: If the controller URL is unknown, or not https outside the loopback
            interface.
    """
    if issuer is None:
        raise ValueError(
            "the OAuth login of the MCP clients needs the public URL of the controller: set "
            "SECREVIEW_PUBLIC_URL"
        )
    # RFC 8414 compares the issuer as a string: no slash added to a URL without path
    url = TypeAdapter(AnyHttpUrl, config=ConfigDict(url_preserve_empty_path=True)).validate_python(
        issuer
    )
    scopes = [oauth_server.SCOPE]
    registration = ClientRegistrationOptions(
        enabled=True, valid_scopes=scopes, default_scopes=scopes
    )
    revocation = RevocationOptions(enabled=True)
    routes = create_auth_routes(
        oauth_server.OAuthProvider(issuer, settings),
        url,
        client_registration_options=registration,
        revocation_options=revocation,
    )
    # The metadata of the SDK offer secret-based client methods: every client is public here
    metadata = build_metadata(url, None, registration, revocation)
    metadata.token_endpoint_auth_methods_supported = ["none"]
    metadata.revocation_endpoint_auth_methods_supported = ["none"]
    served = Route(
        OAUTH_METADATA_PATH,
        endpoint=cors_middleware(MetadataHandler(metadata).handle, ["GET", "OPTIONS"]),
        methods=["GET", "OPTIONS"],
    )
    return [
        served,
        *(route for route in routes if getattr(route, "path", None) != OAUTH_METADATA_PATH),
    ]


class OAuthRoutes(BaseRoute):
    """The OAuth authorization server of the MCP clients (see oauth_routes_of), following the
    effective settings: SECREVIEW_MCP_OAUTH_ENABLED and SECREVIEW_MCP_URL, or the values stored
    in the web interface (see app_settings.set_mcp_oauth). They are read at each OAuth request
    and the routes rebuilt when they change, so that every replica applies a change at once;
    404 while the login is off."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._key: tuple[str, Settings] | None = None
        self._routes: list[BaseRoute] | None = None
        # Settings refused by oauth_routes_of, logged once
        self._refused: tuple[str | None, Settings] | None = None

    def current(self) -> list[BaseRoute] | None:
        """Routes of the effective settings, or None while the login is off."""
        settings = app_settings.effective_settings(get_settings())
        if not settings.mcp_oauth_enabled:
            return None
        issuer = app_settings.controller_url()
        with self._lock:
            if self._key == (issuer, settings):
                return self._routes
            if self._refused == (issuer, settings):
                return None
            try:
                self._routes = oauth_routes_of(issuer, settings)
            except ValueError as exc:
                logger.error("OAuth login of the MCP clients off, invalid settings: %s", exc)
                self._routes, self._key, self._refused = None, None, (issuer, settings)
                return None
            self._key, self._refused = (issuer, settings), None  # type: ignore[assignment]
            logger.info("OAuth login of the MCP clients on for %s", settings.mcp_url)
            return self._routes

    def matches(self, scope: Scope) -> tuple[Match, Scope]:
        """Claim the OAuth paths; whether the login is on is read in handle (database)."""
        if scope["type"] == "http" and scope["path"] in OAUTH_PATHS:
            return Match.FULL, {}
        return Match.NONE, {}

    def url_path_for(self, name: str, /, **path_params: Any) -> URLPath:
        raise NoMatchFound(name, path_params)

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Serve the request with the route of the current settings; 404 while off."""
        routes = await run_in_threadpool(self.current) or []
        partial: tuple[BaseRoute, Scope] | None = None
        for route in routes:
            match, child = route.matches(scope)
            if match is Match.FULL:
                scope.update(child)
                await route.handle(scope, receive, send)
                return
            if match is Match.PARTIAL and partial is None:
                partial = (route, child)
        if partial is not None:
            scope.update(partial[1])
            await partial[0].handle(scope, receive, send)
            return
        await JSONResponse({"detail": "Not Found"}, status.HTTP_404_NOT_FOUND)(scope, receive, send)


def create_app(
    host: str = "127.0.0.1",
    ui_dir: str | None = None,
    ui: bool = True,
    oidc_login: oidc.OidcLogin | None = None,
    signer: oidc.SessionSigner | None = None,
    swagger: bool | None = None,
) -> FastAPI:
    """Build the controller app (REST API and, when it is built, the Angular application).

    ``ui=False`` (SECREVIEW_WEB_UI=false) serves the REST API only. The single sign-on routes
    under ``/api/v1/auth/oidc`` follow the effective OIDC settings (see OidcLogins);
    ``oidc_login`` (tests) replaces them with a fixed flow.
    ``signer`` (see oidc.session_signer) signs the sessions of the password login; the
    session tokens are checked by the bearer middleware (build_controller_app).
    ``swagger`` (default: SECREVIEW_SWAGGER_ENABLED) serves the Swagger documentation and the
    OpenAPI schema; it needs the Swagger UI files of the web interface build.

    Raises:
        ValueError: If ``ui_dir`` (SECREVIEW_WEB_UI_DIR) is set but holds no application.
    """
    settings = get_settings()
    configured = ui_dir if ui_dir is not None else settings.web_ui_dir
    swagger = settings.swagger_enabled if swagger is None else swagger
    app = FastAPI(
        title="security-review-mcp",
        version=__version__,
        # Served below, with the application icon instead of the FastAPI one
        docs_url=None,
        redoc_url=None,
        # Disabled: neither the schema nor the documentation is served
        openapi_url=OPENAPI_PATH if swagger else None,
    )
    app.state.signer = signer or (
        oidc_login.signer
        if oidc_login
        else oidc.SessionSigner(secret_value(settings.secret_key), settings.session_hours)
    )
    app.state.oidc = OidcLogins(app.state.signer, oidc_login)
    app.state.login_throttle = rate_limit.LoginThrottle()
    app.include_router(auth_routes.router)
    app.include_router(api_router)
    app.include_router(ci_routes.router)
    if settings.ci_client_download_enabled:
        app.include_router(ci_client_routes.router)

    app.state.oauth = OAuthRoutes()
    effective = app_settings.effective_settings(settings)
    if effective.mcp_oauth_enabled:
        # Invalid settings stop the start; those stored later are checked when they are stored
        oauth_routes_of(app_settings.controller_url(), effective)
    app.router.routes.append(app.state.oauth)

    @app.get(HEALTH_PATH, include_in_schema=False)
    async def healthz() -> HealthStatus:
        """Public liveness probe (containers, Kubernetes)."""
        return HealthStatus()

    @app.get(API_HEALTH_PATH, tags=["account"])
    async def api_health() -> HealthStatus:
        """Public liveness probe of the API, polled by the web interface at load."""
        return HealthStatus()

    if settings.metrics_enabled:

        @app.get(METRICS_PATH, include_in_schema=False)
        async def prometheus_metrics(identity: MetricsIdentity) -> Response:
            """Prometheus metrics (``metrics`` or ``admin`` token)."""
            text = await run_in_threadpool(metrics.render)
            return Response(
                text, media_type=metrics.CONTENT_TYPE, headers={"Cache-Control": "no-store"}
            )

    @app.get(FAVICON_PATH, include_in_schema=False)
    async def favicon() -> Response:
        """Public icon of the web interface and of the API documentation."""
        return Response(
            FAVICON,
            media_type="image/svg+xml",
            headers={
                "Cache-Control": "public, max-age=86400",
                # Opened on its own, an SVG is a document: it may run nothing
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
                "X-Content-Type-Options": "nosniff",
            },
        )

    assets = swagger_assets_dir(configured) if swagger else None
    app.state.swagger_served = assets is not None
    if assets is not None:
        app.mount(DOCS_ASSETS_PREFIX, StaticFiles(directory=assets), name="swagger")

        @app.get(DOCS_PATH, include_in_schema=False)
        async def swagger_ui() -> Response:
            """Public Swagger documentation of the REST API, with local files only."""
            page = get_swagger_ui_html(
                openapi_url=OPENAPI_PATH,
                title=f"{app.title} - API",
                swagger_js_url=f"{DOCS_ASSETS_PREFIX}/{SWAGGER_FILES[0]}",
                swagger_css_url=f"{DOCS_ASSETS_PREFIX}/{SWAGGER_FILES[1]}",
                swagger_favicon_url=FAVICON_PATH,
                swagger_ui_parameters=SWAGGER_PARAMETERS,
            )
            html = bytes(page.body).decode()
            page.headers["Content-Security-Policy"] = docs_security_policy(html)
            page.headers["X-Content-Type-Options"] = "nosniff"
            page.headers["Referrer-Policy"] = "no-referrer"
            return page
    elif swagger:
        logger.warning(
            "Swagger documentation disabled: the Swagger UI files of the web interface build "
            "are missing (npm run build)"
        )

    @app.exception_handler(services.NotFoundError)
    async def not_found(_: Request, exc: services.NotFoundError) -> JSONResponse:
        """404 answer for a missing resource."""
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": str(exc)})

    directory = resolve_ui_dir(configured) if ui else None
    if directory is not None:
        app.mount("/ui", SinglePageApp(directory=directory, html=True), name="ui")

        @app.get("/", include_in_schema=False)
        async def root() -> RedirectResponse:
            """Redirect to the web interface."""
            return RedirectResponse("/ui/")
    elif ui:
        logger.warning("Web interface not built: only the REST API is served (/api/v1)")

    # Bounds the body of every request before FastAPI parses it
    app.add_middleware(BodyLimit, limits=body_limit)
    if host in LOOPBACK_HOSTS:
        # Same protection as the MCP endpoint against DNS rebinding on a local server
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]"])
    return app
