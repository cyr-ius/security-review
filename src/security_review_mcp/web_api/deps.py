"""Dependencies of the controller REST API: identity of the caller, permissions, project scope.

The bearer middleware (see http_server) authenticates the requests and stores the token label
and role in the ASGI scope; the dependencies below read them and check the permissions of each
route. Every check fails closed.
"""

import logging
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .. import __version__, access_control, audit, services, web_users
from ..http_server import (
    API_ROLES,
    BEARER_CHALLENGE,
    CI_ROUTE_ROLES,
    METRICS_ROLES,
    SCAN_ROUTE_ROLES,
    Role,
)
from ..models import SecurityReportPublic
from .schemas import Identity

logger = logging.getLogger("security_review_mcp.web")

# Declares the bearer scheme in the OpenAPI document (Swagger "Authorize" button). The token
# itself is validated by the bearer middleware: auto_error=False leaves the 401 to
# current_identity, which also covers an app served without that middleware.
bearer_scheme = HTTPBearer(
    auto_error=False,
    description="API token: personal (My account > API tokens) or of a role (Tokens screen)",
)

Permission = access_control.Permission


def _scope_identity(request: Request) -> Identity:
    """Identity set by the bearer middleware once it has validated the token.

    Fails closed: a request that reaches a route without an identity in its scope (app served
    without BearerAuthMiddleware, or a public path mistakenly routed here) gets 401, never an
    implicit administrator.
    """
    state = request.scope.get("state") or {}
    if "auth_role" not in state:
        logger.warning(
            "Rejected API request without an authenticated identity: %s", request.url.path
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid bearer token",
            headers={"WWW-Authenticate": BEARER_CHALLENGE},
        )
    role = Role(state["auth_role"])
    projects = state.get("auth_projects")
    grants = state.get("auth_grants")
    if grants is None:
        grants = access_control.token_grants(role, projects)
    return Identity(
        client=state["auth_client"],
        role=role,
        can_triage=access_control.Permission.FINDINGS_TRIAGE in grants,
        auth_enabled=True,
        projects=None if projects is None else sorted(projects),
        permissions={
            name: None if names is None else sorted(names) for name, names in grants.items()
        },
        local_account=state.get("auth_source") == web_users.AUTH_LOCAL,
        auth_source=state.get("auth_source"),
        must_change_password=bool(state.get("auth_must_change_password")),
        version=__version__,
    )


# Routes a web user who must change its password still reaches
PASSWORD_CHANGE_PATHS = frozenset(
    {"/api/v1/me", "/api/v1/me/password", "/api/v1/me/logout", "/api/v1/me/preferences"}
)


def _identity_with_role(request: Request, allowed: frozenset[Role] | set[Role]) -> Identity:
    """Identity of the caller; 403 when its role does not reach the route.

    A web user whose password was set by someone else only reaches its identity and the change
    of its password (403 elsewhere, pipeline and metrics routes included) until it changes it.
    """
    identity = _scope_identity(request)
    if identity.role not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{identity.role}' cannot access this endpoint",
        )
    if identity.must_change_password and request.url.path not in PASSWORD_CHANGE_PATHS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password change required: change it in My account first",
        )
    return identity


def current_identity(
    request: Request,
    _credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> Identity:
    """Identity of a web session or an ``admin`` or ``api`` token: a ``ci`` or ``metrics`` token
    is refused here even if the bearer middleware let it through (it only reaches its own
    routes)."""
    return _identity_with_role(request, API_ROLES)


def pipeline_identity(
    request: Request,
    _credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> Identity:
    """Identity of the pipeline routes: a ``ci`` token or a web role, scoped to its projects."""
    return _identity_with_role(request, CI_ROUTE_ROLES)


def scan_identity(
    request: Request,
    _credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> Identity:
    """Identity of the pipeline scans, which may store a report: a ``ci`` or ``admin`` token,
    scoped to its projects (a web session or a reader or triager token is refused)."""
    identity = _identity_with_role(request, SCAN_ROUTE_ROLES)
    if identity.auth_source is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The pipeline scans need a ci or admin token, not a web session",
        )
    return identity


def metrics_identity(
    request: Request,
    _credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> Identity:
    """Identity of the Prometheus endpoint: a ``metrics`` or ``admin`` token."""
    return _identity_with_role(request, METRICS_ROLES)


def actor_of(identity: Identity) -> str:
    """Actor written to the audit log: a web user (session) or a bearer token."""
    if identity.auth_source is not None:
        return audit.user_actor(identity.client)
    return audit.token_actor(identity.client)


CurrentIdentity = Annotated[Identity, Depends(current_identity)]
PipelineIdentity = Annotated[Identity, Depends(pipeline_identity)]
ScanIdentity = Annotated[Identity, Depends(scan_identity)]
MetricsIdentity = Annotated[Identity, Depends(metrics_identity)]


def has_permission(identity: Identity, permission: Permission, project: str | None = None) -> bool:
    """True when the caller holds ``permission`` (on ``project`` when one is given)."""
    if permission not in identity.permissions:
        return False
    projects = identity.permissions[permission]
    return project is None or projects is None or project in projects


def permission_scope(identity: Identity, permission: Permission) -> list[str] | None:
    """Projects a permission of the caller reaches: None for every project, [] for none."""
    if permission not in identity.permissions:
        return []
    return identity.permissions[permission]


def require(permission: Permission) -> Callable[[Identity], Identity]:
    """Dependency that refuses (403) a caller without ``permission`` on at least one project."""

    def dependency(identity: CurrentIdentity) -> Identity:
        """Return the identity of a caller that holds the permission."""
        if not has_permission(identity, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' required",
            )
        return identity

    dependency.__name__ = f"require_{permission.value.replace('.', '_')}"
    return dependency


Triager = Annotated[Identity, Depends(require(Permission.FINDINGS_TRIAGE))]
RulesManager = Annotated[Identity, Depends(require(Permission.RULES_MANAGE))]
StandardsManager = Annotated[Identity, Depends(require(Permission.STANDARDS_MANAGE))]
TokensManager = Annotated[Identity, Depends(require(Permission.TOKENS_MANAGE))]
SettingsManager = Annotated[Identity, Depends(require(Permission.SETTINGS_MANAGE))]
UsersManager = Annotated[Identity, Depends(require(Permission.USERS_MANAGE))]
AuditReader = Annotated[Identity, Depends(require(Permission.AUDIT_READ))]


def in_scope(identity: Identity, project: str) -> bool:
    """True when the caller may see this project (always for an unrestricted token)."""
    return identity.projects is None or project in identity.projects


def scoped_project(identity: Identity, requested: str) -> str:
    """Refuse a project outside a project token's scope without disclosing other projects."""
    if not in_scope(identity, requested):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return requested


def ensure_report_scope(identity: Identity, report: SecurityReportPublic) -> None:
    """Hide reports outside a project token's scope, with the answer of a missing report (the
    caller cannot tell which report ids exist in other projects)."""
    if not in_scope(identity, report.project):
        raise services.NotFoundError(f"Report {report.id} not found")


def client_address(request: Request) -> str:
    """Address of the caller, for the login throttling and the logs."""
    return request.client.host if request.client else "unknown"


def unprocessable(exc: ValueError) -> HTTPException:
    """422 answer for an invalid value refused by a service."""
    return HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc))


async def check_report_scope(identity: Identity, report_id: int) -> None:
    """Refuse a report outside the scope of the caller (404, like a missing report)."""
    report = await run_in_threadpool(services.get_report, report_id)
    ensure_report_scope(identity, report)
