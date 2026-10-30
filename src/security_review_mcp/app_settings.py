"""Settings changed by an administrator in the web interface (table ``appsetting``).

A stored value applies when its variable is not set, for both processes since they share the
database: the language of the review reports (read by the MCP server when it builds a review
prompt), the public URL of the controller (read by the MCP server for the clients without a
token, and by the connectors; SECREVIEW_PUBLIC_URL set on the controller is copied here at
start, see sync_controller_url; the MCP server reads it there only), the OAuth login of the MCP
clients (see set_mcp_oauth), the proxy of the outgoing connections, the single sign-on settings
and the syslog server of the audit log (read by the controller, see effective_settings). A
variable that is set (environment or ``.env`` file) always wins: the web interface cannot change
it, and a value stored before is ignored (see env_set).

The proxy URL and the OIDC client secret are secrets: they are stored as given, but never
returned by the API nor logged (``masked_url``, PASSWORD_MASK).

The MCP server imports this module for the report language and the controller URL: the OIDC and
syslog modules of the controller are imported in the functions that use them, never at the top
(tests/test_server.py checks that the MCP server does not load them).
"""

from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from pydantic import SecretStr
from sqlmodel import Session, select

from .config import (
    Settings,
    check_controller_url,
    check_mcp_url,
    check_report_language,
    get_settings,
    web_ui_url,
)
from .observability import audit
from .proxy import PASSWORD_MASK, check_no_proxy, check_proxy_url, describe_proxy, masked_url
from .storage.database import session_scope
from .storage.models import AppSetting, utcnow

REPORT_LANGUAGE = "report_language"
# Key of the public URL of the controller, also the name of its Settings field
CONTROLLER_URL = "controller_url"
# Key of the URL of the MCP endpoint while the OAuth login of the MCP clients is enabled (see
# sync_mcp_oauth): the MCP server then answers a client without a token with a 401 that starts it
MCP_OAUTH_RESOURCE = "mcp_oauth_resource"
# Keys of the OAuth login settings set in the web interface, also the names of their Settings
# fields (see set_mcp_oauth)
MCP_OAUTH_ENABLED = "mcp_oauth_enabled"
MCP_URL = "mcp_url"
# Key stored ("false") while SECREVIEW_PERSONAL_MCP_TOKENS is false (see sync_personal_mcp_tokens):
# the MCP server then no longer tells a client without a valid token to create one
PERSONAL_MCP_TOKENS = "personal_mcp_tokens"
# Key stored ("false") while SECREVIEW_PERSONAL_TOKENS_ENABLED is false (see
# sync_personal_mcp_tokens): the personal mcp and ci tokens and the OAuth grants are then refused
# by both processes (see token_store)
PERSONAL_TOKENS_ENABLED = "personal_tokens_enabled"
# Author of the URL copied from SECREVIEW_PUBLIC_URL by the controller (see
# sync_controller_url)
ENV_ACTOR = "environment"
# Keys of the proxy settings, also the names of their Settings fields. A stored proxy "" means a
# direct connection (when HTTPS_PROXY and HTTP_PROXY are not set).
PROXY = "proxy"
NO_PROXY = "no_proxy"
# Keys of the syslog settings of the audit log, also the names of their Settings fields
SYSLOG_ADDRESS = "audit_syslog_address"
SYSLOG_FACILITY = "audit_syslog_facility"


def env_set(settings: Settings, field: str) -> bool:
    """True when the variable of a Settings field is set (environment or ``.env`` file): it then
    wins over the value stored in the web interface. An empty proxy or syslog address variable
    counts as unset, as an empty SECREVIEW_PUBLIC_URL."""
    if field in (PROXY, NO_PROXY, SYSLOG_ADDRESS, CONTROLLER_URL, MCP_URL):
        return getattr(settings, field) is not None
    return field in settings.model_fields_set


def _check_not_env(settings: Settings, field: str, variable: str) -> None:
    """Refuse to store a value that its set variable would hide.

    Raises:
        ValueError: If the variable of ``field`` is set.
    """
    if env_set(settings, field):
        raise ValueError(f"{variable} is set: it takes precedence, change the variable instead")


def _stored() -> dict[str, str]:
    """Return every stored setting."""
    with session_scope() as session:
        return {row.key: row.value for row in session.exec(select(AppSetting)).all()}


def _apply(session: Session, values: dict[str, str | None], updated_by: str) -> None:
    """Add the given values to ``session``; None removes the setting (the variable applies
    again)."""
    for key, value in values.items():
        row = session.get(AppSetting, key)
        if value is None:
            if row is not None:
                session.delete(row)
            continue
        if row is None:
            row = AppSetting(key=key)
        row.value = value
        row.updated_at = utcnow()
        row.updated_by = updated_by[:64]
        session.add(row)


def _write(values: dict[str, str | None], updated_by: str) -> None:
    """Store the given values; None removes the setting (the variable applies again)."""
    with session_scope() as session:
        _apply(session, values, updated_by)


# ── Report language ──────────────────────────────────────────────────────────


def report_language(settings: Settings | None = None) -> str:
    """Language of the review reports: SECREVIEW_REPORT_LANGUAGE when set, else the stored one,
    else "" (the agent chooses)."""
    settings = settings or get_settings()
    if env_set(settings, REPORT_LANGUAGE):
        return settings.report_language
    return _stored().get(REPORT_LANGUAGE, settings.report_language)


def set_report_language(
    value: str | None, updated_by: str, settings: Settings | None = None
) -> None:
    """Store the report language; "" lets the agent choose, None removes the stored value.

    Raises:
        ValueError: If the value is not a plain language name or code, or if
            SECREVIEW_REPORT_LANGUAGE is set.
    """
    if value is not None:
        _check_not_env(settings or get_settings(), REPORT_LANGUAGE, "SECREVIEW_REPORT_LANGUAGE")
        value = check_report_language(value)
    _write({REPORT_LANGUAGE: value}, updated_by)


# ── Public URL of the controller ─────────────────────────────────────────────


def controller_url() -> str | None:
    """Public root URL of the controller as stored: copied from SECREVIEW_PUBLIC_URL by the
    controller at start, or set in the web interface; None when unknown.

    The MCP server reads it here only: its own SECREVIEW_PUBLIC_URL is ignored.
    """
    with session_scope() as session:
        row = session.get(AppSetting, CONTROLLER_URL)
        return row.value if row is not None else None


def web_url() -> str | None:
    """Address of the web interface (stored controller URL + /ui); None: no link is given."""
    return web_ui_url(controller_url())


def _store_controller_url(value: str | None, actor: str) -> None:
    """Store the URL (None removes it) and record the change in the audit log, in the same
    transaction: the URL is shown to the clients without a token, every change leaves a trace."""
    with session_scope() as session:
        row = session.get(AppSetting, CONTROLLER_URL)
        if (row.value if row is not None else None) == value:
            return
        _apply(session, {CONTROLLER_URL: value}, actor)
        audit.record(
            session,
            audit.AuditAction.CONTROLLER_URL_CHANGED,
            actor,
            "setting",
            CONTROLLER_URL,
            details={"url": value},
        )


def set_controller_url(value: str | None, actor: str, settings: Settings | None = None) -> None:
    """Store the public root URL of the controller; None or "" removes the stored value.

    Raises:
        ValueError: If the value is not an http(s) root URL without credentials, or if
            SECREVIEW_PUBLIC_URL is set on the controller (it is copied at start).
    """
    _check_not_env(settings or get_settings(), CONTROLLER_URL, "SECREVIEW_PUBLIC_URL")
    _store_controller_url(check_controller_url(value), actor)


def sync_controller_url(settings: Settings | None = None) -> None:
    """Copy SECREVIEW_PUBLIC_URL, when set, to the database (controller start): the MCP
    server then reads it there and needs no variable. Unset: the stored value is kept."""
    settings = settings or get_settings()
    if env_set(settings, CONTROLLER_URL):
        _store_controller_url(settings.controller_url, ENV_ACTOR)


# ── OAuth login of the MCP clients ───────────────────────────────────────────


def mcp_oauth_resource() -> str | None:
    """URL of the MCP endpoint while the controller serves the OAuth login of the MCP clients,
    None otherwise. The MCP server reads it here (see server.OAuthDiscovery)."""
    with session_scope() as session:
        row = session.get(AppSetting, MCP_OAUTH_RESOURCE)
        return row.value if row is not None else None


def mcp_oauth_on(session: Session) -> bool:
    """Whether the controller serves the OAuth login of the MCP clients (MCP_OAUTH_RESOURCE
    stored). While it is off, the grants are kept but their access tokens are refused."""
    return session.get(AppSetting, MCP_OAUTH_RESOURCE) is not None


def _mcp_oauth_overrides(stored: dict[str, str]) -> dict[str, Any]:
    """Stored settings of the OAuth login, keyed by Settings field."""
    overrides: dict[str, Any] = {}
    if MCP_OAUTH_ENABLED in stored:
        overrides[MCP_OAUTH_ENABLED] = stored[MCP_OAUTH_ENABLED] == "true"
    if MCP_URL in stored:
        overrides[MCP_URL] = stored[MCP_URL]
    return overrides


def _oauth_resource_of(effective: Settings) -> str | None:
    """URL published for the MCP server (MCP_OAUTH_RESOURCE): the MCP endpoint while the login
    is on, None otherwise.

    Raises:
        ValueError: If the login is on without the URL of the MCP endpoint or of the controller,
            its issuer.
    """
    if not effective.mcp_oauth_enabled:
        return None
    if not effective.mcp_url:
        raise ValueError("the OAuth login of the MCP clients needs the URL of the MCP endpoint")
    if controller_url() is None:
        raise ValueError(
            "the OAuth login of the MCP clients needs the public URL of the controller: set "
            "SECREVIEW_PUBLIC_URL or the Controller server address in the settings"
        )
    return effective.mcp_url


def sync_mcp_oauth(settings: Settings | None = None) -> None:
    """Store the URL of the MCP endpoint while the OAuth login is on (SECREVIEW_MCP_OAUTH_ENABLED
    or the web interface), remove it otherwise (controller start): the MCP server follows the
    controller without a variable of its own.

    Raises:
        ValueError: If OAuth is enabled while the URL of the controller, its issuer, is unknown.
    """
    effective = effective_settings(settings)
    _write({MCP_OAUTH_RESOURCE: _oauth_resource_of(effective)}, ENV_ACTOR)


def set_mcp_oauth(
    values: dict[str, Any],
    actor: str,
    settings: Settings | None = None,
    check: Callable[[str, Settings], object] | None = None,
) -> bool:
    """Store the settings of the OAuth login of the MCP clients: ``enabled`` (bool) and
    ``mcp_url`` (URL of the MCP endpoint); None (or an empty URL) removes the stored value, the
    names left out are unchanged. The URL published for the MCP server follows, and the change is
    recorded in the audit log, in the same transaction. Turning the login off suspends the grants
    without revoking them: their access tokens are refused until it is turned on again (see
    oauth_server.revoke_all_grants to revoke them). ``check`` (the controller) is called with
    the issuer and the effective settings before a login turned on is stored.

    Return whether the login is on afterwards.

    Raises:
        ValueError: If a name is unknown, a value is invalid, its variable is set
            (SECREVIEW_MCP_OAUTH_ENABLED, SECREVIEW_MCP_URL), if the login would be on without
            the URL of the MCP endpoint or of the controller, or if ``check`` refuses the
            settings; nothing is stored then.
    """
    settings = settings or get_settings()
    changes: dict[str, str | None] = {}
    for name, value in values.items():
        if name == "enabled":
            if value is not None:
                _check_not_env(settings, MCP_OAUTH_ENABLED, "SECREVIEW_MCP_OAUTH_ENABLED")
                if not isinstance(value, bool):
                    raise ValueError("enabled must be true or false")
                value = "true" if value else "false"
            changes[MCP_OAUTH_ENABLED] = value
        elif name == "mcp_url":
            url = check_mcp_url(value) if value is not None else None
            if url is not None:
                _check_not_env(settings, MCP_URL, "SECREVIEW_MCP_URL")
            changes[MCP_URL] = url
        else:
            raise ValueError(f"unknown OAuth setting: {name}")
    if not changes:
        return effective_settings(settings).mcp_oauth_enabled
    stored = _stored()
    for key, value in changes.items():
        if value is None:
            stored.pop(key, None)
        else:
            stored[key] = value
    effective = settings.model_copy(update=_overrides(stored, settings))
    resource = _oauth_resource_of(effective)
    if resource is not None and check is not None:
        check(controller_url(), effective)  # type: ignore[arg-type]
    with session_scope() as session:
        _apply(session, changes | {MCP_OAUTH_RESOURCE: resource}, actor)
        audit.record(
            session,
            audit.AuditAction.MCP_OAUTH_CHANGED,
            actor,
            "setting",
            "mcp_oauth",
            details={key.removeprefix("mcp_oauth_"): value for key, value in changes.items()},
        )
    return effective.mcp_oauth_enabled


def describe_mcp_oauth(settings: Settings | None = None) -> dict:
    """Describe the settings of the OAuth login that the web interface may change: stored
    values, variables (and whether they are set) and effective values."""
    settings = settings or get_settings()
    raw = _stored()
    stored = _mcp_oauth_overrides(raw)
    effective = settings.model_copy(update=_overrides(raw, settings))
    return {
        name: {
            "value": stored.get(key),
            "env": getattr(settings, key),
            "env_set": env_set(settings, key),
            "effective": getattr(effective, key),
        }
        for name, key in (("enabled", MCP_OAUTH_ENABLED), ("mcp_url", MCP_URL))
    }


def personal_mcp_tokens() -> bool:
    """False while the controller offers no personal MCP token (SECREVIEW_PERSONAL_MCP_TOKENS or
    SECREVIEW_PERSONAL_TOKENS_ENABLED); the MCP server reads it here to advise the clients
    without a valid token."""
    with session_scope() as session:
        row = session.get(AppSetting, PERSONAL_MCP_TOKENS)
        return row is None or row.value != "false"


def personal_tokens_enabled(session: Session, settings: Settings | None = None) -> bool:
    """False while SECREVIEW_PERSONAL_TOKENS_ENABLED is false in this process or in the
    controller, which stores it (fail closed when the two processes disagree)."""
    settings = settings or get_settings()
    if not settings.personal_tokens_enabled:
        return False
    row = session.get(AppSetting, PERSONAL_TOKENS_ENABLED)
    return row is None or row.value != "false"


def sync_personal_mcp_tokens(settings: Settings | None = None) -> None:
    """Store SECREVIEW_PERSONAL_MCP_TOKENS=false and SECREVIEW_PERSONAL_TOKENS_ENABLED=false,
    remove them otherwise (controller start). No personal MCP token is offered when either one
    is false."""
    settings = settings or get_settings()
    offered = settings.personal_mcp_tokens and settings.personal_tokens_enabled
    _write(
        {
            PERSONAL_MCP_TOKENS: None if offered else "false",
            PERSONAL_TOKENS_ENABLED: None if settings.personal_tokens_enabled else "false",
        },
        ENV_ACTOR,
    )


# ── Proxy of the outgoing connections ────────────────────────────────────────


def _proxy_overrides(stored: dict[str, str]) -> dict[str, str]:
    """Stored proxy settings, keyed by Settings field."""
    return {key: stored[key] for key in (PROXY, NO_PROXY) if key in stored}


def _keep_password(url: str, previous: str | None) -> str:
    """Put back the stored password when ``url`` carries PASSWORD_MASK for the same proxy."""
    parts = urlsplit(url)
    if parts.password != PASSWORD_MASK:  # secreview:ignore PY-025 compared with the mask constant
        return url
    old = urlsplit(previous) if previous else None
    same_proxy = old is not None and (old.username, old.hostname, old.port) == (
        parts.username,
        parts.hostname,
        parts.port,
    )
    if not same_proxy or old.password is None:
        raise ValueError("enter the proxy password again")
    return previous  # type: ignore[return-value]


def set_proxy(
    values: dict[str, str | None], updated_by: str, settings: Settings | None = None
) -> None:
    """Store the proxy settings: ``url`` (``""``: direct connection) and ``no_proxy``; None
    removes the stored value, the names left out are unchanged. A URL sent back with the
    password masked (``***``) keeps the stored password.

    Raises:
        ValueError: If a name is unknown, a value is invalid, or its variable is set
            (HTTPS_PROXY / HTTP_PROXY, NO_PROXY); nothing is stored then.
    """
    settings = settings or get_settings()
    changes: dict[str, str | None] = {}
    for name, value in values.items():
        if name == "url":
            if value is not None:
                _check_not_env(settings, PROXY, "HTTPS_PROXY (or HTTP_PROXY)")
            if value is None or value.strip() == "":
                changes[PROXY] = None if value is None else ""
            else:
                url = check_proxy_url(value)
                changes[PROXY] = _keep_password(url, _stored().get(PROXY))
        elif name == NO_PROXY:
            if value is not None:
                _check_not_env(settings, NO_PROXY, "NO_PROXY")
            changes[NO_PROXY] = None if value is None else check_no_proxy(value)
        else:
            raise ValueError(f"unknown proxy setting: {name}")
    _write(changes, updated_by)


def _describe_proxy(settings: Settings, stored: dict[str, str], effective: Settings) -> dict:
    """Stored values, variables and effective proxy (passwords masked)."""
    url = describe_proxy(effective)
    if url is None:
        source = "none"
    else:
        source = "environment" if env_set(settings, PROXY) else "web"
    return {
        "url": {
            "value": masked_url(stored[PROXY]) if PROXY in stored else None,
            "env": masked_url(settings.proxy) if settings.proxy else None,
            "env_set": env_set(settings, PROXY),
        },
        "no_proxy": {
            "value": stored.get(NO_PROXY),
            "env": settings.no_proxy,
            "env_set": env_set(settings, NO_PROXY),
        },
        "effective": {
            "url": url,
            "no_proxy": effective.no_proxy if url is not None else None,
            "source": source,
        },
    }


# ── Effective settings ───────────────────────────────────────────────────────


def _overrides(stored: dict[str, str], settings: Settings) -> dict[str, Any]:
    """Every stored value (controller URL, OAuth login, proxy, OIDC and syslog) whose variable is
    not set."""
    overrides = (
        _proxy_overrides(stored)
        | _oidc_overrides(stored)
        | _syslog_overrides(stored)
        | _mcp_oauth_overrides(stored)
    )
    if CONTROLLER_URL in stored:
        overrides[CONTROLLER_URL] = stored[CONTROLLER_URL]
    return {key: value for key, value in overrides.items() if not env_set(settings, key)}


def effective_settings(settings: Settings | None = None) -> Settings:
    """Return ``settings`` with the controller URL, proxy, OIDC and syslog values stored in the web
    interface applied where their variable is not set (read by the controller at each OSV
    download, login, batch of audit events and export; the connections of the connectors are read by
    connectors.connections)."""
    settings = settings or get_settings()
    overrides = _overrides(_stored(), settings)
    return settings.model_copy(update=overrides) if overrides else settings


# ── Single sign-on (OIDC) ────────────────────────────────────────────────────

# Settings of the OIDC login an administrator may change in the web interface, by short name
# (stored under the name of the Settings field, ``oidc_<name>``) and type. oidc_cafile (a file
# of the deployment) and the session settings stay variables only.
OIDC_FIELDS: dict[str, type] = {
    "enabled": bool,
    "issuer": str,
    "client_id": str,
    "client_secret": str,
    "redirect_uri": str,
    "scope": str,
    "roles_claim": str,
    "username_claim": str,
    "admin_groups": str,
    "auto_create_users": bool,
    "display_name": str,
}
OIDC_SECRET = "client_secret"
# Bound of a stored value (AppSetting.value)
MAX_OIDC_VALUE_CHARS = 500


def _oidc_key(name: str) -> str:
    """Key of an OIDC setting in the table, also the name of its Settings field."""
    return f"oidc_{name}"


def _oidc_overrides(stored: dict[str, str]) -> dict[str, Any]:
    """Typed values of the stored OIDC settings, keyed by Settings field."""
    overrides: dict[str, Any] = {}
    for name, kind in OIDC_FIELDS.items():
        key = _oidc_key(name)
        if key in stored:
            if kind is bool:
                overrides[key] = stored[key] == "true"
            elif name == OIDC_SECRET:
                overrides[key] = SecretStr(stored[key])
            else:
                overrides[key] = stored[key]
    return overrides


def _check_oidc_value(name: str, value: Any) -> str:
    """Return the stored form of one OIDC value, or raise ValueError."""
    if OIDC_FIELDS[name] is bool:
        if not isinstance(value, bool):
            raise ValueError(f"OIDC setting {name} must be true or false")
        return "true" if value else "false"
    if not isinstance(value, str):
        raise ValueError(f"OIDC setting {name} must be a string")
    text = value if name == OIDC_SECRET else value.strip()
    if len(text) > MAX_OIDC_VALUE_CHARS:
        raise ValueError(f"OIDC setting {name} too long (max {MAX_OIDC_VALUE_CHARS} chars)")
    if not text.isprintable():
        raise ValueError(f"OIDC setting {name} must not contain control characters")
    return text


def _oidc_changes(
    values: dict[str, Any], settings: Settings
) -> tuple[dict[str, str | None], Settings]:
    """Check ``values`` (see set_oidc); return the stored form of the changes and the effective
    settings they would give. Raise ValueError on an invalid value or a value whose variable is
    set."""
    changes: dict[str, str | None] = {}
    for name, value in values.items():
        if name == OIDC_SECRET and value == PASSWORD_MASK:
            continue
        if name not in OIDC_FIELDS:
            raise ValueError(f"unknown OIDC setting: {name}")
        key = _oidc_key(name)
        if value is not None:
            _check_not_env(settings, key, f"SECREVIEW_{key.upper()}")
        changes[key] = None if value is None else _check_oidc_value(name, value)
    stored = _stored()
    for key, value in changes.items():
        if value is None:
            stored.pop(key, None)
        else:
            stored[key] = value
    return changes, settings.model_copy(update=_overrides(stored, settings))


def _validate_oidc(effective: Settings) -> None:
    """Raise ValueError when ``effective`` cannot enable a login."""
    from .auth.oidc import validate_settings  # controller only, see the module docstring

    try:
        validate_settings(effective)
    except ValueError as exc:
        raise ValueError(f"invalid OIDC settings: {exc}") from None


def set_oidc(values: dict[str, Any], updated_by: str, settings: Settings | None = None) -> None:
    """Store OIDC settings: ``values`` maps short names to a value, or to None to remove the
    stored value; the names left out are unchanged. A client secret equal to PASSWORD_MASK
    (sent back as shown) keeps the stored one.

    Raises:
        ValueError: If a value is invalid, if its SECREVIEW_OIDC_* variable is set, or if the
            resulting settings enable an invalid login (nothing is stored then).
    """
    changes, effective = _oidc_changes(values, settings or get_settings())
    if effective.oidc_enabled:
        _validate_oidc(effective)
    _write(changes, updated_by)


def oidc_candidate(values: dict[str, Any], settings: Settings | None = None) -> Settings:
    """Return the effective settings ``values`` would give (see set_oidc), without storing
    them, to test the provider.

    Raises:
        ValueError: If a value is invalid or the settings cannot enable a login.
    """
    _, effective = _oidc_changes(values, settings or get_settings())
    _validate_oidc(effective)
    return effective


def _shown(name: str, value: Any) -> Any:
    """Value of an OIDC setting as returned by the API: a set client secret is masked."""
    if isinstance(value, SecretStr):
        value = value.get_secret_value()
    if name == OIDC_SECRET and value:
        return PASSWORD_MASK
    return value


def describe_oidc(settings: Settings | None = None) -> dict:
    """Describe each OIDC setting (stored value, variable, whether it is set, effective value),
    without secret."""
    from .auth.oidc import CALLBACK_PATH  # controller only, see the module docstring

    settings = settings or get_settings()
    raw = _stored()
    stored = _oidc_overrides(raw)
    effective = settings.model_copy(update=_overrides(raw, settings))
    fields = {
        name: {
            "value": _shown(name, stored[_oidc_key(name)]) if _oidc_key(name) in stored else None,
            "env": _shown(name, getattr(settings, _oidc_key(name))),
            "env_set": env_set(settings, _oidc_key(name)),
            "effective": _shown(name, getattr(effective, _oidc_key(name))),
        }
        for name in OIDC_FIELDS
    }
    return {
        "fields": fields,
        "cafile": settings.oidc_cafile,
        "callback_path": CALLBACK_PATH,
    }


# ── Syslog server of the audit log ───────────────────────────────────────────


def _syslog_overrides(stored: dict[str, str]) -> dict[str, Any]:
    """Stored syslog settings, keyed by Settings field."""
    return {key: stored[key] for key in (SYSLOG_ADDRESS, SYSLOG_FACILITY) if key in stored}


def set_audit_syslog(
    values: dict[str, str | None], actor: str, settings: Settings | None = None
) -> None:
    """Store the syslog settings of the audit log: ``address`` and ``facility``; None (or an
    empty address) removes the stored value, the names left out are unchanged.

    The change is recorded in the audit log, in the same transaction: stopping the forwarding
    leaves a trace. Only udp://, tcp:// and tls:// addresses may be set here; a Unix socket is a
    file of the deployment and stays a variable, as the CA file of tls://.

    Raises:
        ValueError: If a name is unknown, a value is invalid, or its variable is set
            (SECREVIEW_AUDIT_SYSLOG_ADDRESS, SECREVIEW_AUDIT_SYSLOG_FACILITY); nothing is stored
            then.
    """
    from .observability.audit_syslog import check_web_address, facility  # controller only

    settings = settings or get_settings()
    changes: dict[str, str | None] = {}
    for name, value in values.items():
        if name == "address":
            if value is None or value.strip() == "":
                changes[SYSLOG_ADDRESS] = None
            else:
                _check_not_env(settings, SYSLOG_ADDRESS, "SECREVIEW_AUDIT_SYSLOG_ADDRESS")
                changes[SYSLOG_ADDRESS] = check_web_address(value)
        elif name == "facility":
            if value is not None:
                _check_not_env(settings, SYSLOG_FACILITY, "SECREVIEW_AUDIT_SYSLOG_FACILITY")
                facility(value)
                value = value.strip().lower()
            changes[SYSLOG_FACILITY] = value
        else:
            raise ValueError(f"unknown syslog setting: {name}")
    if not changes:
        return
    with session_scope() as session:
        _apply(session, changes, actor)
        audit.record(
            session,
            audit.AuditAction.AUDIT_SYSLOG_CHANGED,
            actor,
            "setting",
            "audit_syslog",
            details={key.removeprefix("audit_syslog_"): value for key, value in changes.items()},
        )


def describe_audit_syslog(settings: Settings | None = None) -> dict:
    """Describe the syslog settings: stored values, variables (and whether they are set) and
    effective destination."""
    from .observability.audit_syslog import FACILITIES  # controller only

    settings = settings or get_settings()
    stored = _stored()
    effective = settings.model_copy(update=_overrides(stored, settings))
    if not effective.audit_syslog_address:
        source = "none"
    else:
        source = "environment" if env_set(settings, SYSLOG_ADDRESS) else "web"
    return {
        "address": {
            "value": stored.get(SYSLOG_ADDRESS),
            "env": settings.audit_syslog_address,
            "env_set": env_set(settings, SYSLOG_ADDRESS),
        },
        "facility": {
            "value": stored.get(SYSLOG_FACILITY),
            "env": settings.audit_syslog_facility,
            "env_set": env_set(settings, SYSLOG_FACILITY),
        },
        "effective": {
            "address": effective.audit_syslog_address,
            "facility": effective.audit_syslog_facility,
            "source": source,
        },
        "facilities": sorted(FACILITIES),
    }


# ── Description for the web interface ────────────────────────────────────────


def describe(settings: Settings | None = None) -> dict:
    """Describe the stored settings, the variables and the effective values (no password)."""
    settings = settings or get_settings()
    stored = _stored()
    effective = settings.model_copy(update=_overrides(stored, settings))
    return {
        "report_language": {
            "value": stored.get(REPORT_LANGUAGE),
            "env": settings.report_language,
            "env_set": env_set(settings, REPORT_LANGUAGE),
            "effective": report_language(settings),
        },
        "controller_url": {
            "value": stored.get(CONTROLLER_URL),
            "env": settings.controller_url,
            "env_set": env_set(settings, CONTROLLER_URL),
            "effective": effective.controller_url,
        },
        "proxy": _describe_proxy(settings, stored, effective),
        "osv": {
            "download_enabled": settings.osv_auto_update,
            "update_interval_hours": settings.osv_update_interval_hours,
            "url": settings.osv_url,
            "ecosystems": settings.osv_ecosystems,
            "cafile": settings.osv_cafile,
            "max_download_mb": settings.osv_max_download_mb,
        },
    }
