"""Schemas of the tokens and of the OAuth connection of the MCP clients."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ...auth import access_control, token_store
from ...config import CONTROLLER_URL_MAX_CHARS, MAX_RETENTION_DAYS
from ...http_server import Role
from ...storage.project_names import ProjectName

# ── Tokens ───────────────────────────────────────────────────────────────────

_ProjectName = ProjectName


class ProjectTokenCreate(BaseModel):
    """A role-specific token scoped to one or several projects, or to every project."""

    label: str = Field(min_length=1, max_length=64)
    # mcp: MCP agent; ci: pipeline token (gate, SARIF, trend and scans of its projects only,
    # see ci_client); api: REST API (Swagger, scripts) with the permissions of access_role_id
    role: Literal["mcp", "ci", "api"] = "mcp"
    # null: every project (refused for a ci token)
    projects: list[_ProjectName] | None = Field(
        min_length=1, max_length=token_store.MAX_PROJECTS_PER_TOKEN
    )
    # Validity in days (null: SECREVIEW_TOKEN_MAX_DAYS, or no expiry when it is 0)
    expires_in_days: int | None = Field(default=None, ge=1, le=MAX_RETENTION_DAYS)
    # Role of an api token (required for it, refused for the others)
    access_role_id: int | None = Field(default=None, ge=1)
    # Per-project permissions of an api token on its projects (refused for the others)
    project_permissions: list[access_control.Permission] = Field(
        default_factory=list, max_length=len(access_control.SCOPED_PERMISSIONS)
    )


class TokenRoleChoice(BaseModel):
    """A role an api token may hold (GET /project-tokens/roles)."""

    id: int
    name: str
    permissions: list[access_control.Permission]


class PersonalTokenCreate(BaseModel):
    """Body of POST /me/tokens: a personal token of the logged-in user, ``api`` (REST API, with
    the rights of the user), ``mcp`` (MCP agent) or ``ci`` (security-review-ci on a workstation),
    the last two on the projects the user may read."""

    label: str = Field(min_length=1, max_length=64)
    role: Literal["api", "mcp", "ci"] = "api"
    # Validity in days (null: SECREVIEW_TOKEN_MAX_DAYS, or no expiry when it is 0)
    expires_in_days: int | None = Field(default=None, ge=1, le=MAX_RETENTION_DAYS)


class OAuthRequestRef(BaseModel):
    """Body of the consent routes: the handle of a pending OAuth request, from the URL of the
    consent screen."""

    request: str = Field(min_length=1, max_length=100)


class OAuthPendingRequest(BaseModel):
    """A pending OAuth request, shown by the consent screen: the MCP client (its name is chosen
    by the client itself) and the host it goes back to."""

    client_id: str
    client_name: str | None = None
    redirect_host: str
    expires_at: str


class OAuthRedirect(BaseModel):
    """Where the browser goes after a decision: the client, with a code or an error."""

    redirect_url: str


class OAuthGrantPublic(BaseModel):
    """An MCP client approved by the logged-in user (never its tokens)."""

    id: str
    client_id: str
    client_name: str | None = None
    created_at: str
    last_used_at: str | None = None
    expires_at: str


class OAuthClientAdmin(BaseModel):
    """A registered MCP client (its name and redirect URIs are chosen by the client)."""

    client_id: str
    client_name: str | None = None
    redirect_uris: list[str]
    created_at: str
    # Grants of the client (0: nobody approved it; deleted a day after its registration)
    grants: int


class OAuthGrantAdmin(OAuthGrantPublic):
    """An MCP client approved by a web user."""

    username: str


class OAuthEnabledSetting(BaseModel):
    """Whether the OAuth login is on: stored value, variable, whether it is set (it then takes
    precedence), effective value."""

    value: bool | None
    env: bool
    env_set: bool
    effective: bool


class OAuthUrlSetting(BaseModel):
    """URL of the MCP endpoint: stored value, variable, whether it is set (it then takes
    precedence), effective value."""

    value: str | None
    env: str | None
    env_set: bool
    effective: str | None


class OAuthSettings(BaseModel):
    """Settings of the OAuth login of the MCP clients that the web interface may change."""

    enabled: OAuthEnabledSetting
    mcp_url: OAuthUrlSetting


class OAuthSettingsUpdate(BaseModel):
    """Body of PUT /oauth/settings: OAuth login of the MCP clients.

    A field left out is unchanged, ``null`` (or an empty URL) removes the stored value. A value
    whose variable is set (SECREVIEW_MCP_OAUTH_ENABLED, SECREVIEW_MCP_URL) is refused: the
    variable takes precedence. The login needs the URL of the MCP endpoint and that of the
    controller; turning it off suspends the grants without revoking them.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    mcp_url: str | None = Field(default=None, max_length=CONTROLLER_URL_MAX_CHARS)


class OAuthGrantsRevoked(BaseModel):
    """Outcome of DELETE /oauth/grants: how many grants were revoked."""

    revoked: int


class OAuthOverview(BaseModel):
    """The OAuth login of the MCP clients: its settings, the registered clients and every grant
    (never a token)."""

    enabled: bool
    mcp_url: str | None = None
    settings: OAuthSettings
    redirect_hosts: list[str]
    redirect_schemes: list[str]
    access_minutes: int
    refresh_days: int
    max_clients: int
    clients: list[OAuthClientAdmin]
    grants: list[OAuthGrantAdmin]


class ProjectTokenProjects(BaseModel):
    """Body of PUT /project-tokens/{id}/projects."""

    # null: every project (refused for a ci token)
    projects: list[_ProjectName] | None = Field(
        min_length=1, max_length=token_store.MAX_PROJECTS_PER_TOKEN
    )


class ProjectTokenRotation(BaseModel):
    """Body of POST /project-tokens/{id}/rotate."""

    # Hours during which the previous secret keeps working (0: it stops at once)
    grace_hours: int = Field(default=0, ge=0, le=token_store.MAX_ROTATION_GRACE_HOURS)
    # Validity of the new secret in days (null: SECREVIEW_TOKEN_MAX_DAYS, or no expiry)
    expires_in_days: int | None = Field(default=None, ge=1, le=MAX_RETENTION_DAYS)


class ProjectToken(BaseModel):
    """Metadata of a token managed in the web interface, never its hash."""

    id: str
    label: str
    role: Role
    # First project of the token (kept for API compatibility)
    project: str | None
    # None: every project (personal mcp or ci token: the projects its user may read now)
    projects: list[str] | None
    created_at: str
    expires_at: str | None
    expired: bool
    rotated_at: str | None
    # End of the grace period of the previous secret after a rotation
    grace_until: str | None
    # api token: its role (role token) and its per-project permissions on its projects, or
    # personal (the rights of the user who created it)
    access_role_id: int | None
    project_permissions: list[str] = []
    personal: bool


class ProjectTokenSecret(ProjectToken):
    """A token just created or rotated: ``token`` is its secret, returned exactly once."""

    token: str
