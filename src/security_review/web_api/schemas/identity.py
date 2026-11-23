"""Schemas of the identity, the login and the About page."""

from typing import Literal

from pydantic import BaseModel, Field

from ...auth import web_users
from ...http_server import Role
from ...storage.models import (
    Severity,
)
from .common import AuthSource

# ── Identity and login ───────────────────────────────────────────────────────


class Identity(BaseModel):
    """Who is calling and what they may do."""

    client: str
    # Role of a token; ``user`` for a web session, whose rights are its ``permissions``
    role: Role
    can_triage: bool
    # Always true: the API answers authenticated requests only (kept for API compatibility)
    auth_enabled: bool
    # Projects whose reports the caller reads; None: every project
    projects: list[str] | None = None
    # Each permission of the caller (see access_control.Permission) with its projects (None:
    # every project)
    permissions: dict[str, list[str] | None] = Field(default_factory=dict)
    # True for a local web user (logged in with a password, which it may change)
    local_account: bool = False
    # Source of the account of a web user ("local" or "oidc"); None for a bearer token
    auth_source: AuthSource | None = None
    # A web user whose password was set by someone else: it must change it before anything else
    must_change_password: bool = False
    # A web user who triages may accept a risk without an expiry date
    # (SECREVIEW_PERMANENT_ACCEPTANCE_ENABLED); always false for a bearer token
    permanent_acceptance: bool = False
    # Lowest severity whose risk acceptance needs a reason and an expiry date
    # (SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY); a less severe finding is accepted by a plain
    # validation. None: every acceptance needs them
    risk_acceptance_min_severity: Severity | None = None
    # A web user may create a personal MCP token (SECREVIEW_PERSONAL_MCP_TOKENS)
    personal_mcp_tokens: bool = True
    # A web user may create a personal MCP or CI token and approve an MCP client with the OAuth
    # login (SECREVIEW_PERSONAL_TOKENS_ENABLED)
    personal_tokens_enabled: bool = True
    # The OAuth login of the MCP clients is on (variable or web interface)
    mcp_oauth: bool = False
    # Default and longest validity in days of a new token (SECREVIEW_TOKEN_MAX_DAYS); 0: none
    token_max_days: int = 0
    version: str


Theme = Literal["light", "dark", "auto"]


class Preferences(BaseModel):
    """Preferences of a web user in the web interface; body of PUT /me/preferences."""

    # auto: the system preference (prefers-color-scheme)
    theme: Theme


class AuthConfig(BaseModel):
    """Login methods offered by the login page (web users only: tokens are for the API)."""

    # Username and password of a local web user (false with SECREVIEW_OIDC_ONLY and OIDC enabled)
    password: bool = True
    oidc: bool
    oidc_display_name: str | None = None


class PasswordLogin(BaseModel):
    """Body of POST /auth/login."""

    username: str = Field(min_length=1, max_length=web_users.MAX_USERNAME_CHARS)
    password: str = Field(min_length=1, max_length=web_users.MAX_PASSWORD_CHARS)


class LoginSession(BaseModel):
    """Session opened by a password login, sent back as a bearer token."""

    session: str
    expires_in: int
    username: str
    # True: only the change of the password is reachable until it is done
    must_change_password: bool = False


class PasswordChange(BaseModel):
    """Body of PUT /me/password: the current password and the new one."""

    current_password: str = Field(min_length=1, max_length=web_users.MAX_PASSWORD_CHARS)
    new_password: str = Field(
        min_length=web_users.MIN_PASSWORD_CHARS, max_length=web_users.MAX_PASSWORD_CHARS
    )


class HealthStatus(BaseModel):
    """Answer of the liveness probes."""

    status: Literal["ok"] = "ok"


class About(BaseModel):
    """What the About page shows: version, links, Swagger and backend status."""

    version: str
    documentation_url: str | None
    repository_url: str | None
    issues_url: str | None
    # The Swagger documentation is served (SECREVIEW_SWAGGER_ENABLED and its files built)
    swagger_url: str | None
    health_url: str


class UpdateStatus(BaseModel):
    """Latest release on GitHub against the running version (SECREVIEW_UPDATE_CHECK_ENABLED)."""

    enabled: bool
    current: str
    latest: str | None
    update_available: bool
    release_url: str | None
    checked_at: str | None
    # Why the latest release is unknown while enabled
    error: Literal["unreachable", "invalid"] | None
