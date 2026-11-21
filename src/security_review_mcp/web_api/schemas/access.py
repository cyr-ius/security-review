"""Schemas of the web users, roles, project members and OIDC mappings."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from ...auth import access_control, token_store, web_users
from .common import AuthSource
from .tokens import _ProjectName

# ── Web users, roles and OIDC mappings ───────────────────────────────────────


class UserRoleRef(BaseModel):
    """A role of a web user."""

    role_id: int
    name: str


class UserProjectItem(BaseModel):
    """A project of a web user, with its per-project permissions there."""

    project: str
    permissions: list[access_control.Permission]


class UserOidcAccess(BaseModel):
    """What the mapping of a value of the roles claim of an OIDC user (last login) gives: roles,
    per-project permissions on every project, projects with their permissions."""

    claim: str
    roles: list[str]
    all_projects_permissions: list[access_control.Permission]
    projects: list[UserProjectItem]


class WebUser(BaseModel):
    """A web user, local or OIDC; never its password hash nor its subject."""

    id: int
    username: str
    auth_source: AuthSource
    # Roles (permissions on the whole controller), per-project permissions on every project and
    # projects with their permissions, given by an administrator
    roles: list[UserRoleRef]
    all_projects_permissions: list[access_control.Permission]
    projects: list[UserProjectItem]
    # Roles and projects of its OIDC mappings (read only, recomputed at each login)
    oidc: list[UserOidcAccess]
    # Each permission with its projects (None: every project); empty: no access
    permissions: dict[str, list[str] | None]
    # True once an OIDC user logged in (bound to its identity provider account)
    sso_linked: bool
    created_at: str | None
    updated_at: str | None
    # None for an OIDC user (no password)
    password_changed_at: str | None
    # Its password was set by someone else: it must change it at its next login
    must_change_password: bool = False
    last_login_at: str | None
    created_by: str | None


class WebUserWithPassword(WebUser):
    """A web user just created or reset: ``password`` is set when it was generated (once)."""

    password: str | None = None


class RevokedUser(BaseModel):
    """A deleted OIDC user: a login never creates it again until the revocation is lifted."""

    username: str
    revoked_at: str | None
    revoked_by: str | None


_ProjectPermissions = list[access_control.Permission]


class UserProjectBinding(BaseModel):
    """A known project given to a web user, with its per-project permissions there."""

    project: _ProjectName
    permissions: _ProjectPermissions = Field(
        default_factory=lambda: [access_control.Permission.REPORTS_READ],
        min_length=1,
        max_length=len(access_control.SCOPED_PERMISSIONS),
    )


_RoleIds = list[Annotated[int, Field(ge=1)]]
_ProjectBindings = list[UserProjectBinding]


class WebUserCreate(BaseModel):
    """A web user with its roles, its per-project permissions on every project and its projects
    with their permissions, the only source of its permissions. A local one without
    ``password`` gets a random one, returned once; an OIDC one (``auth_source="oidc"``) has no
    password and also gets those of its OIDC mappings at each login."""

    # An unknown field (such as the former "group_ids") is refused, not ignored
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=web_users.MAX_USERNAME_CHARS)
    auth_source: AuthSource = "local"
    password: str | None = Field(
        default=None,
        min_length=web_users.MIN_PASSWORD_CHARS,
        max_length=web_users.MAX_PASSWORD_CHARS,
    )
    role_ids: _RoleIds = Field(default_factory=list, max_length=access_control.MAX_ROLES)
    all_projects_permissions: _ProjectPermissions = Field(
        default_factory=list, max_length=len(access_control.SCOPED_PERMISSIONS)
    )
    projects: _ProjectBindings = Field(
        default_factory=list, max_length=access_control.MAX_SESSION_PROJECTS
    )


class WebUserUpdate(BaseModel):
    """Roles and projects an administrator gives to a web user (those of its OIDC mappings are
    kept); a missing field is left unchanged."""

    # An unknown field (such as the former "group_ids") is refused, not ignored
    model_config = ConfigDict(extra="forbid")

    role_ids: _RoleIds | None = Field(default=None, max_length=access_control.MAX_ROLES)
    all_projects_permissions: _ProjectPermissions | None = Field(
        default=None, max_length=len(access_control.SCOPED_PERMISSIONS)
    )
    projects: _ProjectBindings | None = Field(
        default=None, max_length=access_control.MAX_SESSION_PROJECTS
    )


class PasswordReset(BaseModel):
    """New password of a web user, set by an administrator (null: generate one)."""

    password: str | None = Field(
        default=None,
        min_length=web_users.MIN_PASSWORD_CHARS,
        max_length=web_users.MAX_PASSWORD_CHARS,
    )


class PermissionInfo(BaseModel):
    """A permission a role may hold, and whether it can be limited to projects."""

    name: access_control.Permission
    scoped: bool


class RoleWrite(BaseModel):
    """A custom role: a name and the permissions it holds."""

    name: str = Field(min_length=1, max_length=access_control.MAX_ROLE_NAME_CHARS)
    description: str = Field(default="", max_length=access_control.MAX_DESCRIPTION_CHARS)
    permissions: list[access_control.Permission] = Field(
        min_length=1, max_length=len(access_control.Permission)
    )


class AccessRole(BaseModel):
    """A role: a named set of permissions, given to users and by OIDC mappings."""

    id: int
    name: str
    description: str
    permissions: list[access_control.Permission]
    # Built-in role (admin): neither changed nor deleted
    system: bool
    # Users who hold the role, and OIDC mappings that give it
    users: int
    mappings: int
    created_at: str
    updated_at: str
    created_by: str | None


class ProjectMember(BaseModel):
    """A web user who has the project, with its per-project permissions given there (empty
    when it only has every project) and those it holds on every project (read only here)."""

    user_id: int
    username: str
    auth_source: AuthSource
    permissions: list[access_control.Permission]
    all_projects_permissions: list[access_control.Permission]


class ProjectMemberBinding(BaseModel):
    """A web user given the project, with its per-project permissions there."""

    user_id: int = Field(ge=1)
    permissions: _ProjectPermissions = Field(
        default_factory=lambda: [access_control.Permission.REPORTS_READ],
        min_length=1,
        max_length=len(access_control.SCOPED_PERMISSIONS),
    )


class ProjectMembersUpdate(BaseModel):
    """Body of PUT /access/projects/{project}/members: every user who has the project."""

    members: list[ProjectMemberBinding] = Field(max_length=access_control.MAX_PROJECT_MEMBERS)


class OidcRoleMapping(BaseModel):
    """A value of the OIDC roles claim that gives roles, per-project permissions on every
    project and projects with their permissions (a project not known yet is ignored until it is
    created)."""

    id: int
    claim: str
    role_ids: list[int]
    roles: list[str]
    all_projects_permissions: list[access_control.Permission]
    projects: list[UserProjectItem]
    created_at: str
    created_by: str | None


class OidcRoleMappingWrite(BaseModel):
    """An OIDC mapping: a value of the roles claim, the roles, the per-project permissions on
    every project and the projects with their permissions it gives."""

    claim: str = Field(min_length=1, max_length=access_control.MAX_CLAIM_CHARS)
    role_ids: _RoleIds = Field(default_factory=list, max_length=access_control.MAX_ROLES)
    all_projects_permissions: _ProjectPermissions = Field(
        default_factory=list, max_length=len(access_control.SCOPED_PERMISSIONS)
    )
    projects: _ProjectBindings = Field(
        default_factory=list, max_length=token_store.MAX_PROJECTS_PER_TOKEN
    )


class OidcMappingsUpdate(BaseModel):
    """Body of PUT /oidc/mappings: every OIDC mapping."""

    mappings: list[OidcRoleMappingWrite] = Field(max_length=access_control.MAX_OIDC_MAPPINGS)


class OidcMappingCatalog(BaseModel):
    """The OIDC mappings and the OIDC settings that use them."""

    oidc_enabled: bool
    roles_claim: str
    # Values of the claim mapped to admin on every project at the login of a user who holds one
    admin_groups: list[str]
    mappings: list[OidcRoleMapping]


class KnownProject(BaseModel):
    """A known project (GET /access/projects), to give roles on it."""

    name: str
