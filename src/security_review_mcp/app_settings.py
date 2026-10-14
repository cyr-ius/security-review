"""Settings changed by an administrator in the web interface (table ``appsetting``).

A stored value overrides the matching ``SECREVIEW_*`` variable, for both processes since they
share the database: the language of the review reports (read by the MCP server when it builds a
review prompt) and the proxy of the OSV download (read by the controller). Without a stored
value, the variable applies.

The proxy URL may hold credentials: they are stored as given, but never returned by the API nor
logged (``masked_url``).
"""

import urllib.request
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

from sqlmodel import select

from .config import Settings, check_report_language, get_settings
from .database import session_scope
from .models import AppSetting, utcnow

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
    if parts.password != PASSWORD_MASK:
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
