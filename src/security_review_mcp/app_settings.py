"""Settings changed by an administrator in the web interface (table ``appsetting``).

A stored value overrides the matching ``SECREVIEW_*`` variable, for both processes since they
share the database: the language of the review reports (read by the MCP server when it builds a
review prompt), the proxy of the outgoing connections and the single sign-on settings (read by
the controller, see effective_settings). Without a stored value, the variable applies.

The proxy URL and the OIDC client secret are secrets: they are stored as given, but never
returned by the API nor logged (``masked_url``, PASSWORD_MASK).
"""

import urllib.request
from typing import Any
from urllib.parse import urlsplit

from sqlmodel import select

from .config import Settings, check_report_language, get_settings
from .database import session_scope
from .models import AppSetting, utcnow
from .oidc import CALLBACK_PATH, DEFAULT_ROLES, validate_settings
from .proxy import PASSWORD_MASK, check_no_proxy, check_proxy_url, describe_proxy, masked_url

REPORT_LANGUAGE = "report_language"
# Keys of the proxy settings, also the names of their Settings fields. A stored proxy "" means a
# direct connection, despite SECREVIEW_PROXY and HTTPS_PROXY.
PROXY = "proxy"
NO_PROXY = "no_proxy"


def _stored() -> dict[str, str]:
    """Return every stored setting."""
    with session_scope() as session:
        return {row.key: row.value for row in session.exec(select(AppSetting)).all()}


def _write(values: dict[str, str | None], updated_by: str) -> None:
    """Store the given values; None removes the setting (the variable applies again)."""
    with session_scope() as session:
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


# ── Report language ──────────────────────────────────────────────────────────


def report_language() -> str:
    """Language of the review reports: the stored one, else SECREVIEW_REPORT_LANGUAGE."""
    stored = _stored()
    if REPORT_LANGUAGE in stored:
        return stored[REPORT_LANGUAGE]
    return get_settings().report_language


def set_report_language(value: str | None, updated_by: str) -> None:
    """Store the report language; "" lets the agent choose, None restores the variable.

    Raises:
        ValueError: If the value is not a plain language name or code.
    """
    _write({REPORT_LANGUAGE: None if value is None else check_report_language(value)}, updated_by)


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


def set_proxy(values: dict[str, str | None], updated_by: str) -> None:
    """Store the proxy settings: ``url`` (``""``: direct connection) and ``no_proxy``; None
    applies the variable again, the names left out are unchanged. A URL sent back with the
    password masked (``***``) keeps the stored password.

    Raises:
        ValueError: If a name is unknown or a value is invalid (nothing is stored then).
    """
    changes: dict[str, str | None] = {}
    for name, value in values.items():
        if name == "url":
            if value is None or value.strip() == "":
                changes[PROXY] = None if value is None else ""
            else:
                url = check_proxy_url(value)
                changes[PROXY] = _keep_password(url, _stored().get(PROXY))
        elif name == NO_PROXY:
            changes[NO_PROXY] = None if value is None else check_no_proxy(value)
        else:
            raise ValueError(f"unknown proxy setting: {name}")
    _write(changes, updated_by)


def _describe_proxy(settings: Settings, stored: dict[str, str], effective: Settings) -> dict:
    """Stored values, variables and effective proxy (passwords masked)."""
    url, kind = describe_proxy(effective)
    if kind == "proxy":
        source = "web" if PROXY in stored else "SECREVIEW_PROXY"
    elif kind == "none":
        source = "none"
    else:
        source = "environment"
    environment = urllib.request.getproxies()
    return {
        "url": {
            "value": masked_url(stored[PROXY]) if PROXY in stored else None,
            "env": masked_url(settings.proxy) if settings.proxy else None,
        },
        "no_proxy": {"value": stored.get(NO_PROXY), "env": settings.no_proxy},
        "environment": {
            name: masked_url(environment[key])
            if key in environment and key != "no"
            else environment.get(key)
            for name, key in (("https_proxy", "https"), ("http_proxy", "http"), ("no_proxy", "no"))
        },
        "effective": {
            "url": url,
            "no_proxy": effective.no_proxy if kind == "proxy" else None,
            "source": source,
        },
    }


# ── Effective settings ───────────────────────────────────────────────────────


def _overrides(stored: dict[str, str]) -> dict[str, Any]:
    """Every stored value that overrides a Settings field (proxy and SSO)."""
    return _proxy_overrides(stored) | _oidc_overrides(stored)


def effective_settings(settings: Settings | None = None) -> Settings:
    """Return ``settings`` with the proxy and SSO values stored in the web interface applied
    over the ``SECREVIEW_*`` variables (read by the controller at each OSV download and login)."""
    settings = settings or get_settings()
    overrides = _overrides(_stored())
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
    "scopes": str,
    "roles_claim": str,
    "username_claim": str,
    "admin_groups": str,
    "triager_groups": str,
    "reader_groups": str,
    "default_role": str,
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
            overrides[key] = stored[key] == "true" if kind is bool else stored[key]
    return overrides


def _check_oidc_value(name: str, value: Any) -> str:
    """Return the stored form of one OIDC value, or raise ValueError."""
    if OIDC_FIELDS[name] is bool:
        if not isinstance(value, bool):
            raise ValueError(f"SSO setting {name} must be true or false")
        return "true" if value else "false"
    if not isinstance(value, str):
        raise ValueError(f"SSO setting {name} must be a string")
    text = value if name == OIDC_SECRET else value.strip()
    if len(text) > MAX_OIDC_VALUE_CHARS:
        raise ValueError(f"SSO setting {name} too long (max {MAX_OIDC_VALUE_CHARS} chars)")
    if not text.isprintable():
        raise ValueError(f"SSO setting {name} must not contain control characters")
    if name == "default_role" and text not in DEFAULT_ROLES:
        raise ValueError("SSO default role must be empty, reader or triager")
    return text


def _oidc_changes(
    values: dict[str, Any], settings: Settings
) -> tuple[dict[str, str | None], Settings]:
    """Check ``values`` (see set_oidc); return the stored form of the changes and the effective
    settings they would give. Raise ValueError on an invalid value."""
    changes: dict[str, str | None] = {}
    for name, value in values.items():
        if name == OIDC_SECRET and value == PASSWORD_MASK:
            continue
        if name not in OIDC_FIELDS:
            raise ValueError(f"unknown SSO setting: {name}")
        changes[_oidc_key(name)] = None if value is None else _check_oidc_value(name, value)
    stored = _stored()
    for key, value in changes.items():
        if value is None:
            stored.pop(key, None)
        else:
            stored[key] = value
    return changes, settings.model_copy(update=_overrides(stored))


def _validate_oidc(effective: Settings) -> None:
    """Raise ValueError when ``effective`` cannot enable a login."""
    try:
        validate_settings(effective)
    except ValueError as exc:
        raise ValueError(f"invalid SSO settings: {exc}") from None


def set_oidc(values: dict[str, Any], updated_by: str, settings: Settings | None = None) -> None:
    """Store OIDC settings: ``values`` maps short names to a value, or to None to apply the
    variable again; the names left out are unchanged. A client secret equal to PASSWORD_MASK
    (sent back as shown) keeps the stored one.

    Raises:
        ValueError: If a value is invalid, or if the resulting settings enable an invalid login
            (nothing is stored then).
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
    if name == OIDC_SECRET and value:
        return PASSWORD_MASK
    return value


def describe_oidc(settings: Settings | None = None) -> dict:
    """Describe each OIDC setting (stored value, variable, effective value), without secret."""
    settings = settings or get_settings()
    raw = _stored()
    stored = _oidc_overrides(raw)
    effective = settings.model_copy(update=_overrides(raw))
    fields = {
        name: {
            "value": _shown(name, stored[_oidc_key(name)]) if _oidc_key(name) in stored else None,
            "env": _shown(name, getattr(settings, _oidc_key(name))),
            "effective": _shown(name, getattr(effective, _oidc_key(name))),
        }
        for name in OIDC_FIELDS
    }
    return {
        "fields": fields,
        "cafile": settings.oidc_cafile,
        "callback_path": CALLBACK_PATH,
    }


# ── Description for the web interface ────────────────────────────────────────


def describe(settings: Settings | None = None) -> dict:
    """Describe the stored settings, the variables and the effective values (no password)."""
    settings = settings or get_settings()
    stored = _stored()
    effective = settings.model_copy(update=_overrides(stored))
    return {
        "report_language": {
            "value": stored.get(REPORT_LANGUAGE),
            "env": settings.report_language,
            "effective": report_language(),
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
