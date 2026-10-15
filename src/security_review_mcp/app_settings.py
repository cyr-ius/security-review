"""Settings changed by an administrator in the web interface (table ``appsetting``).

A stored value overrides the matching ``SECREVIEW_*`` variable, for both processes since they
share the database: the language of the review reports (read by the MCP server when it builds a
review prompt), the proxy of the OSV download and the single sign-on settings (read by the
controller). Without a stored value, the variable applies.

The proxy URL and the OIDC client secret are secrets: they are stored as given, but never
returned by the API nor logged (``masked_url``, PASSWORD_MASK).
"""

import urllib.request
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

from sqlmodel import select

from .config import Settings, check_report_language, get_settings
from .database import session_scope
from .models import AppSetting, utcnow
from .oidc import CALLBACK_PATH, DEFAULT_ROLES, validate_settings

REPORT_LANGUAGE = "report_language"
OSV_PROXY_MODE = "osv_proxy_mode"
OSV_PROXY_URL = "osv_proxy_url"

# env: SECREVIEW_OSV_PROXY, else HTTPS_PROXY / NO_PROXY; custom: the stored URL; none: direct
ProxyMode = Literal["env", "custom", "none"]
PROXY_MODES: tuple[ProxyMode, ...] = ("env", "custom", "none")
MAX_PROXY_URL_CHARS = 500
# Replaces the password of a proxy URL returned by the API; sent back unchanged, it keeps the
# stored password
PASSWORD_MASK = "***"


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


# ── Proxy of the OSV download ────────────────────────────────────────────────


def masked_url(url: str) -> str:
    """Return ``url`` with its password replaced by PASSWORD_MASK, so that it can be shown."""
    parts = urlsplit(url)
    if parts.password is None:
        return url
    host = parts.netloc.rpartition("@")[2]
    return parts._replace(netloc=f"{parts.username}:{PASSWORD_MASK}@{host}").geturl()


def check_proxy_url(url: str) -> str:
    """Return the stripped proxy URL, or raise ValueError if it is not http://host[:port]."""
    url = url.strip()
    if len(url) > MAX_PROXY_URL_CHARS:
        raise ValueError(f"proxy URL too long (max {MAX_PROXY_URL_CHARS} chars)")
    if any(c.isspace() or not c.isprintable() for c in url):
        raise ValueError("proxy URL must not contain spaces or control characters")
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018  (raises ValueError on an invalid port)
    except ValueError as exc:
        raise ValueError(f"invalid proxy URL: {exc}") from exc
    if parts.scheme != "http" or not parts.hostname:
        raise ValueError("proxy URL must be an http://[user:password@]host:port URL")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError("proxy URL must not have a path, a query or a fragment")
    return url


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


def set_osv_proxy(mode: ProxyMode, url: str | None, updated_by: str) -> None:
    """Store how the controller reaches the OSV exports.

    Raises:
        ValueError: If the mode is unknown, or the URL is missing or invalid in custom mode.
    """
    if mode not in PROXY_MODES:
        raise ValueError(f"proxy mode must be one of {list(PROXY_MODES)}")
    if mode != "custom":
        _write({OSV_PROXY_MODE: None if mode == "env" else mode, OSV_PROXY_URL: None}, updated_by)
        return
    if not url or not url.strip():
        raise ValueError("a proxy URL is required in custom mode")
    url = _keep_password(check_proxy_url(url), _stored().get(OSV_PROXY_URL))
    _write({OSV_PROXY_MODE: mode, OSV_PROXY_URL: url}, updated_by)


@dataclass(frozen=True)
class ProxyChoice:
    """Proxy used by the OSV download and where it comes from.

    ``source`` is ``web`` (URL set in the web interface), ``none`` (direct connection chosen in
    the web interface), ``SECREVIEW_OSV_PROXY``, or ``environment`` (urllib applies
    HTTPS_PROXY / NO_PROXY, possibly no proxy at all).
    """

    url: str | None
    source: str


def proxy_choice(settings: Settings) -> ProxyChoice:
    """Resolve the proxy of the OSV download: web interface, then SECREVIEW_OSV_PROXY, then env."""
    stored = _stored()
    mode = stored.get(OSV_PROXY_MODE, "env")
    if mode == "custom" and stored.get(OSV_PROXY_URL):
        return ProxyChoice(stored[OSV_PROXY_URL], "web")
    if mode == "none":
        return ProxyChoice(None, "none")
    if settings.osv_proxy:
        return ProxyChoice(settings.osv_proxy, "SECREVIEW_OSV_PROXY")
    return ProxyChoice(None, "environment")


def _environment_proxies() -> dict[str, str | None]:
    """Standard proxy variables seen by urllib (HTTPS_PROXY, HTTP_PROXY, NO_PROXY), masked."""
    proxies = urllib.request.getproxies()
    return {
        name: masked_url(proxies[key]) if key in proxies and key != "no" else proxies.get(key)
        for name, key in (("https_proxy", "https"), ("http_proxy", "http"), ("no_proxy", "no"))
    }


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


def oidc_settings(settings: Settings | None = None) -> Settings:
    """Return ``settings`` with the OIDC values stored in the web interface applied over the
    ``SECREVIEW_OIDC_*`` variables."""
    settings = settings or get_settings()
    overrides = _oidc_overrides(_stored())
    return settings.model_copy(update=overrides) if overrides else settings


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
    return changes, settings.model_copy(update=_oidc_overrides(stored))


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
    stored = _oidc_overrides(_stored())
    effective = settings.model_copy(update=stored) if stored else settings
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
    choice = proxy_choice(settings)
    if choice.url:
        effective_proxy = masked_url(choice.url)
    elif choice.source == "environment":
        effective_proxy = _environment_proxies()["https_proxy"]
    else:
        effective_proxy = None
    return {
        "report_language": {
            "value": stored.get(REPORT_LANGUAGE),
            "env": settings.report_language,
            "effective": report_language(),
        },
        "osv_proxy": {
            "mode": stored.get(OSV_PROXY_MODE, "env"),
            "url": masked_url(stored[OSV_PROXY_URL]) if OSV_PROXY_URL in stored else None,
            "env": {
                "secreview_osv_proxy": masked_url(settings.osv_proxy)
                if settings.osv_proxy
                else None,
                **_environment_proxies(),
            },
            "effective": {"url": effective_proxy, "source": choice.source},
        },
        "osv": {
            "download_enabled": settings.osv_auto_update,
            "update_interval_hours": settings.osv_update_interval_hours,
            "url": settings.osv_url,
            "ecosystems": settings.osv_ecosystems,
            "cafile": settings.osv_cafile,
            "max_download_mb": settings.osv_max_download_mb,
        },
    }
