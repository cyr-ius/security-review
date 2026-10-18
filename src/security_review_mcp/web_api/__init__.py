"""Controller: REST API (``/api/v1``) and the bundled Angular application (``/ui``).

Served by ``security-review-controller serve``, in its own process, apart from the MCP server
(see http_server). The bearer middleware authenticates the requests and stores the token label
and role in the ASGI scope; ``deps`` checks the permissions of each route. The public
enrollment endpoint is served by the MCP server (see enrollment_api); approving or rejecting
the requests is done here.

The routes are split by domain (``*_routes`` modules) and every answer has a response model
(``schemas``). The services are synchronous (SQLModel sessions), so every call runs in the
thread pool.
"""

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, FastAPI, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import Scope

from .. import __version__, metrics, oidc, services, web_users
from ..config import get_settings
from ..http_server import (
    DOCS_PATH,
    FAVICON_PATH,
    HEALTH_PATH,
    LOOPBACK_HOSTS,
    METRICS_PATH,
    OPENAPI_PATH,
)
from . import (
    access_routes,
    account_routes,
    admin_routes,
    auth_routes,
    ci_routes,
    report_routes,
    rule_routes,
    token_routes,
)
from .auth_routes import OidcLogins
from .deps import MetricsIdentity, current_identity
from .schemas import HealthStatus, Identity

__all__ = [
    "BUNDLED_UI_DIR",
    "FAVICON",
    "Identity",
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

# Every route needs an authenticated identity, even those that do not use it (health)
api_router = APIRouter(prefix="/api/v1", dependencies=[Depends(current_identity)])
for _domain in (
    account_routes,
    report_routes,
    rule_routes,
    token_routes,
    admin_routes,
    access_routes,
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


def create_app(
    host: str = "127.0.0.1",
    ui_dir: str | None = None,
    ui: bool = True,
    oidc_login: oidc.OidcLogin | None = None,
    signer: oidc.SessionSigner | None = None,
) -> FastAPI:
    """Build the controller app (REST API and, when it is built, the Angular application).

    ``ui=False`` (SECREVIEW_WEB_UI=false) serves the REST API only. The single sign-on routes
    under ``/api/v1/auth/oidc`` follow the effective SSO settings (see OidcLogins);
    ``oidc_login`` (tests) replaces them with a fixed flow.
    ``signer`` (see oidc.session_signer) signs the sessions of the password login; the
    session tokens are checked by the bearer middleware (build_controller_app).

    Raises:
        ValueError: If ``ui_dir`` (SECREVIEW_WEB_UI_DIR) is set but holds no application.
    """
    settings = get_settings()
    app = FastAPI(
        title="security-review-mcp",
        version=__version__,
        # Served below, with the application icon instead of the FastAPI one
        docs_url=None,
        redoc_url=None,
        openapi_url=OPENAPI_PATH,
    )
    app.state.signer = signer or (
        oidc_login.signer
        if oidc_login
        else oidc.SessionSigner(settings.session_secret, settings.session_hours)
    )
    app.state.oidc = OidcLogins(app.state.signer, oidc_login)
    app.state.login_throttle = web_users.LoginThrottle()
    app.include_router(auth_routes.router)
    app.include_router(api_router)
    app.include_router(ci_routes.router)

    @app.get(HEALTH_PATH, include_in_schema=False)
    async def healthz() -> HealthStatus:
        """Public liveness probe (containers, Kubernetes)."""
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

    @app.get(DOCS_PATH, include_in_schema=False)
    async def swagger_ui() -> Response:
        """Public Swagger documentation of the REST API."""
        return get_swagger_ui_html(
            openapi_url=OPENAPI_PATH,
            title=f"{app.title} - API",
            swagger_favicon_url=FAVICON_PATH,
        )

    @app.exception_handler(services.NotFoundError)
    async def not_found(_: Request, exc: services.NotFoundError) -> JSONResponse:
        """404 answer for a missing resource."""
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": str(exc)})

    configured = ui_dir if ui_dir is not None else settings.web_ui_dir
    directory = resolve_ui_dir(configured) if ui else None
    if directory is not None:
        app.mount("/ui", SinglePageApp(directory=directory, html=True), name="ui")

        @app.get("/", include_in_schema=False)
        async def root() -> RedirectResponse:
            """Redirect to the web interface."""
            return RedirectResponse("/ui/")
    elif ui:
        logger.warning("Web interface not built: only the REST API is served (/api/v1)")

    if host in LOOPBACK_HOSTS:
        # Same protection as the MCP endpoint against DNS rebinding on a local server
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]"])
    return app
