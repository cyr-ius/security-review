"""HTTP proxy of the outgoing connections of the controller (OSV download, OIDC provider).

The effective proxy is ``Settings.proxy`` and ``Settings.no_proxy``, read from the standard
``HTTPS_PROXY`` (else ``HTTP_PROXY``) and ``NO_PROXY`` variables, or from the web interface for
those not set (see app_settings.effective_settings):

- ``proxy`` None or ``""`` (direct connection set in the web interface): no proxy;
- otherwise every connection goes through that proxy, except to the hosts of ``no_proxy`` and
  the loopback interface. A ``no_proxy`` entry is a domain (covering its subdomains), an IP
  address or ``*``. An address only matches a URL whose host is that address: host names are
  never resolved. Address ranges (CIDR) are not supported: such an entry matches no host.

The opener always gets an explicit handler, so urllib never reads the variables on its own.

A proxy URL may hold credentials: masked_url hides the password before it is shown or logged.
"""

import ipaddress
import urllib.request
from urllib.parse import urlsplit

from .config import Settings

MAX_PROXY_URL_CHARS = 500
MAX_NO_PROXY_CHARS = 500
# Replaces the password of a proxy URL that is shown; sent back unchanged, it keeps the stored one
PASSWORD_MASK = "***"
# Always reached without proxy
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
# Characters of a no_proxy entry: host name, IP address (v4 or bracketed v6), port, wildcard
_NO_PROXY_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.-_*:[]")


def masked_url(url: str) -> str:
    """Return ``url`` with its password replaced by PASSWORD_MASK, so that it can be shown."""
    parts = urlsplit(url)
    if parts.password is None:
        return url
    host = parts.netloc.rpartition("@")[2]
    return parts._replace(netloc=f"{parts.username}:{PASSWORD_MASK}@{host}").geturl()


def check_proxy_url(url: str, name: str = "proxy URL") -> str:
    """Return the stripped proxy URL, or raise ValueError if it is not http://host[:port]."""
    url = url.strip()
    if len(url) > MAX_PROXY_URL_CHARS:
        raise ValueError(f"{name} too long (max {MAX_PROXY_URL_CHARS} chars)")
    if any(c.isspace() or not c.isprintable() for c in url):
        raise ValueError(f"{name} must not contain spaces or control characters")
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018  (raises ValueError on an invalid port)
    except ValueError as exc:
        raise ValueError(f"invalid {name}: {exc}") from exc
    if parts.scheme != "http" or not parts.hostname:
        raise ValueError(f"{name} must be an http://[user:password@]host:port URL")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError(f"{name} must not have a path, a query or a fragment")
    return url


def parse_no_proxy(value: str) -> tuple[str, ...]:
    """Return the entries of a comma-separated no_proxy list, lowercased, without port."""
    entries = []
    for item in value.split(","):
        entry = item.strip().lower()
        if not entry:
            continue
        if entry.startswith("["):
            entry = entry[1:].partition("]")[0]
        elif entry.count(":") == 1:
            entry = entry.partition(":")[0]
        entries.append(entry)
    return tuple(entries)


def check_no_proxy(value: str, name: str = "no_proxy") -> str:
    """Return the normalized no_proxy list, or raise ValueError on an invalid entry."""
    value = value.strip()
    if len(value) > MAX_NO_PROXY_CHARS:
        raise ValueError(f"{name} too long (max {MAX_NO_PROXY_CHARS} chars)")
    items = [item.strip() for item in value.split(",") if item.strip()]
    for item in items:
        if not set(item.lower()) <= _NO_PROXY_CHARS:
            raise ValueError(
                f"{name}: invalid entry {item!r} (host names, IP addresses or * expected; "
                "address ranges are not supported)"
            )
    return ",".join(items)


def _address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The IP address ``value`` is, or None for a host name."""
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def bypasses(host: str, entries: tuple[str, ...]) -> bool:
    """True when ``host`` is reached without proxy: loopback, ``*``, or a no_proxy entry.

    A domain entry matches the host itself and its subdomains (``example.com`` and
    ``.example.com`` both cover ``api.example.com``); an address entry matches a host that is
    that IP address (a host name is never resolved).
    """
    host = host.lower().strip("[]")
    if host in LOOPBACK_HOSTS:
        return True
    address = _address(host)
    if address is not None and address.is_loopback:
        return True
    for entry in entries:
        if entry == "*":
            return True
        entry_address = _address(entry)
        if entry_address is not None:
            if address == entry_address:
                return True
            continue
        domain = entry.lstrip("*.")
        if domain and (host == domain or host.endswith(f".{domain}")):
            return True
    return False


class _ProxyHandler(urllib.request.ProxyHandler):
    """Send every request through one proxy, except to the hosts it bypasses."""

    def __init__(self, url: str, no_proxy: tuple[str, ...]) -> None:
        super().__init__({"http": url, "https": url})
        self.no_proxy = no_proxy

    def proxy_open(self, req, proxy, type):  # noqa: A002, ANN001, ANN201
        """Leave a bypassed host to the next handlers (direct connection)."""
        if bypasses(urlsplit(req.full_url).hostname or "", self.no_proxy):
            return None
        return super().proxy_open(req, proxy, type)


def proxy_handler(settings: Settings) -> urllib.request.ProxyHandler:
    """Handler of the effective proxy for urllib.build_opener.

    Without proxy, a handler without proxies: it replaces urllib's default one, which would read
    the environment variables again, bypassing a direct connection set in the web interface.
    """
    if not settings.proxy:
        return urllib.request.ProxyHandler({})
    return _ProxyHandler(settings.proxy, parse_no_proxy(settings.no_proxy or ""))


def describe_proxy(settings: Settings) -> str | None:
    """Effective proxy URL (masked), or None for a direct connection."""
    return masked_url(settings.proxy) if settings.proxy else None
