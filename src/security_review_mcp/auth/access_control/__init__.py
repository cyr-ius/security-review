"""Access control of the web interface: permissions, roles, and the roles and projects of the
users.

- A **permission** (Permission) allows one kind of action. ``reports.read``, ``reports.write``
  and ``findings.triage`` are *per project* (SCOPED_PERMISSIONS): they are given with a project,
  or with every project. The other permissions concern the whole controller (SITE_PERMISSIONS).
  ``reports.write`` lets the tokens of a user save reports and propose a status for a finding
  on the project (MCP agent, pipeline scans); it implies ``reports.read`` there.
- A **role** (AccessRole) is a named set of permissions on the whole controller: a role holds
  no per-project permission. The built-in role ``admin`` (every permission on the whole
  controller) can be neither changed nor deleted, because the code relies on it: it is given to
  the first administrator and by SECREVIEW_OIDC_ADMIN_GROUPS. Its permissions are those of
  SYSTEM_ROLES, so that a new permission reaches it without a migration.
- A user holds **roles** (UserRole), **per-project permissions on every project**
  (``WebUser.all_projects_permissions``) and **projects** (UserProject), each with its own
  per-project permissions. An administrator gives them (see set_user_roles, set_user_projects
  and set_project_members).
- An OIDC user also holds the roles, permissions on every project and projects of the
  **mappings** (OidcRoleMapping) that name a value of its roles claim (a project not known yet is
  ignored until it is created); they add up with those of the user. The values of the claim named
  by a mapping are kept at each login (UserOidcClaim, see sync_oidc_claims); a change of the
  mappings applies at once. ``SECREVIEW_OIDC_ADMIN_GROUPS`` names values of the claim that hold
  ``admin``: at a login, a listed value of the claim without a mapping gets one (``admin`` and
  every per-project permission on every project), so that a deployment that only uses OIDC gets
  its first administrator.
- The MCP agent of a user **requests** a project its token does not reach (see
  request_project): a new project is created at once for a user with ``projects.create``;
  otherwise, and always for a project that already exists, the request waits
  (``ProjectEnrollment``) until a user with ``projects.create`` approves it, which gives the
  requesting user the review of the project (``reports.read`` and ``reports.write``, created
  for a new project), or rejects it; a
  request nobody approved within SECREVIEW_PROJECT_ENROLLMENT_TTL_DAYS is deleted.
- A user with ``projects.create`` may create a **new** project (see create_project): the
  controller creates it and gives its review to the user, so that its personal ``mcp`` token
  saves reports there. A project already known (see storage.projects) is refused: the
  permission never grants the reading of an existing project.
- A user with ``projects.autojoin`` whose MCP agent requests a project that already exists
  joins it at once (see request_project), with its review. A user with ``users.manage``
  who reads a project may block this autojoin on it (see set_autojoin_blocked): the requests
  then wait for an approval as the others do. ``projects.create`` never blocks nor allows it.
- A user with ``projects.delete`` may delete a project and everything that refers to it (see
  delete_project): its reports, findings and comments, the project of the users, of the mappings
  and of the tokens (a token left without project is revoked). The audit log keeps its events.
  The same permission renames a project (see rename_project): every reference follows the new
  name, and the fingerprints of its findings are recomputed so that their triage carries on.
- No permission gives the personal ``mcp`` and ``ci`` tokens: every web user may create them
  while SECREVIEW_PERSONAL_TOKENS_ENABLED is true (see token_store). They read the projects of
  ``reports.read`` and write only to those of ``reports.write``.

The grants of a user (see user_grants) are the permissions of all its roles (its own and those
of its mappings) on the whole controller, with its per-project permissions on every project and
on each of its projects. At least one user keeps ``users.manage``: a change that would remove
the last one is refused (see _guard_managers), and an OIDC login never removes it (see
sync_oidc_claims).

``users.manage`` and ``settings.manage`` are **protected** (PROTECTED_PERMISSIONS): only an
administrator, who holds every permission on the whole controller (is_administrator), creates,
changes or deletes a role that holds one, gives or takes away such a role (to a user or in an OIDC
mapping), changes the OIDC settings, or changes, deletes or resets the password of a user who
holds one. A holder of ``users.manage`` who is not an administrator manages the other roles and
users; each refusal is written to the audit log (ProtectedAccessDenied, record_protected_denial).

The bearer tokens are for machines and keep their fixed roles (see http_server.TOKEN_ROLES):
token_grants gives every permission to an ``admin`` token, none to the others. An ``api`` token
follows this model instead: a personal token holds the grants of its user (user_grants), a role
token the permissions of its role and its per-project permissions on its projects
(role_token_grants), both read at each request. A role used by a token cannot be deleted.

The package is split by domain (core, roles, users, members, projects, oidc_mappings) and
re-exports their public names. The limits are re-exported as values: a test patches a limit in
the module that reads it (``core.MAX_SESSION_PROJECTS``, ``projects.MAX_PENDING_PROJECTS``...).
"""

from . import core, members, oidc_mappings, projects, roles, users  # noqa: F401
from .core import (  # noqa: F401
    ADMIN_ROLE,
    ALL_PERMISSIONS,
    IMPLIED_PERMISSIONS,
    MAX_CLAIM_CHARS,
    MAX_DESCRIPTION_CHARS,
    MAX_OIDC_MAPPINGS,
    MAX_PROJECT_MEMBERS,
    MAX_ROLE_NAME_CHARS,
    MAX_ROLES,
    MAX_SESSION_PROJECTS,
    OIDC_ACTOR,
    PROTECTED_PERMISSIONS,
    REVIEW_PERMISSIONS,
    SCOPED_PERMISSIONS,
    SITE_PERMISSIONS,
    SYSTEM_ROLES,
    Grants,
    Permission,
    ProtectedAccessDenied,
    StaleVersion,
    allows,
    check_protected_user,
    clean_claim,
    clean_description,
    clean_permissions,
    clean_project_permissions,
    clean_projects,
    clean_role_name,
    combine,
    holds_protected,
    is_administrator,
    list_permissions,
    managers,
    parse_groups,
    record_protected_denial,
    scope,
    token_grants,
    user_grants,
)
from .members import (  # noqa: F401
    forget_user,
    list_project_members,
    project_members_version,
    set_project_members,
)
from .oidc_mappings import (  # noqa: F401
    list_oidc_mappings,
    oidc_mappings_version,
    set_oidc_mappings,
    sync_oidc_claims,
)
from .projects import (  # noqa: F401
    ENROLLMENT_ACTOR,
    ENROLLMENT_WINDOW_SECONDS,
    MAX_ADDRESS_CHARS,
    MAX_ENROLLMENTS_PER_REQUESTER,
    MAX_PENDING_PROJECTS,
    MAX_REQUESTED_BY_CHARS,
    AccessGrantDenied,
    EnrollmentThrottled,
    adopt_project,
    approve_enrollment,
    autojoin_blocked_projects,
    create_project,
    delete_project,
    enrollment_next_steps,
    list_enrollments,
    pending_project_count,
    project_exists,
    reject_enrollment,
    rename_project,
    request_project,
    set_autojoin_blocked,
)
from .roles import (  # noqa: F401
    create_role,
    delete_role,
    ensure_system_roles,
    list_roles,
    list_token_roles,
    role_token_grants,
    role_token_scope,
    update_role,
)
from .users import (  # noqa: F401
    add_user_project,
    set_user_projects,
    set_user_roles,
    user_access,
)
