"""Search for a newer release on GitHub, shown on the About page of the controller (optional).

Disabled by default (SECREVIEW_UPDATE_CHECK_ENABLED): it is an outgoing connection of the
controller, made only when a user opens the About page, at most once per CACHE_SECONDS per
process. It requests the latest release of the GitHub repository over HTTPS only (redirects to
another scheme refused), through the proxy of the controller (see proxy), with a timeout and a
bounded answer. The MCP server never calls it.

Only the tag and the URL of the release are kept: nothing from the answer is logged.
"""

import json
import logging
import re
import ssl
import threading
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from . import __version__
from .config import Settings
from .deps.versions import compare_versions
from .oidc import _HttpsRedirectOnly
from .proxy import masked_url, proxy_handler

logger = logging.getLogger("security_review_mcp.update_check")

GITHUB_REPOSITORY = "cyr-ius/security-review-mcp"
LATEST_RELEASE_URL = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/releases/latest"
RELEASES_PAGE = f"https://github.com/{GITHUB_REPOSITORY}/releases/"
HTTP_TIMEOUT = 10
MAX_RESPONSE_BYTES = 512 * 1024
# A successful answer is kept 6 hours, a failure 15 minutes
CACHE_SECONDS = 6 * 3600
FAILURE_CACHE_SECONDS = 15 * 60
# Tag of a release: vX.Y.Z, possibly with a pre-release suffix
_TAG = re.compile(r"v?(\d{1,4}\.\d{1,4}\.\d{1,4}(?:[-.+][0-9A-Za-z.-]{1,40})?)")

_lock = threading.Lock()
_cache: dict[str, Any] | None = None
_cache_until = 0.0


class UpdateCheckError(Exception):
    """The latest release could not be read: ``code`` is shown, the message only logged."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _opener(settings: Settings) -> urllib.request.OpenerDirector:
    """HTTPS opener with the proxy of the controller."""
    handlers: list[urllib.request.BaseHandler] = [
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _HttpsRedirectOnly(),
    ]
    if (handler := proxy_handler(settings)) is not None:
        handlers.append(handler)
    return urllib.request.build_opener(*handlers)


def fetch_latest(settings: Settings) -> tuple[str, str]:
    """Return the version and the page URL of the latest release.

    Raises:
        UpdateCheckError: If GitHub cannot be reached or sends an unexpected answer.
    """
    request = urllib.request.Request(
        LATEST_RELEASE_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"security-review-mcp/{__version__}",
        },
    )
    try:
        with _opener(settings).open(request, timeout=HTTP_TIMEOUT) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise UpdateCheckError("unreachable", f"GitHub answered HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError) as exc:
        message = str(exc)
        if settings.proxy:
            # The error may name the proxy: never show its credentials
            message = message.replace(settings.proxy, masked_url(settings.proxy))
        raise UpdateCheckError("unreachable", f"GitHub unreachable: {message}") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise UpdateCheckError("invalid", "GitHub answer too large")
    try:
        document = json.loads(raw)
    except ValueError:
        raise UpdateCheckError("invalid", "GitHub sent invalid JSON") from None
    tag = document.get("tag_name") if isinstance(document, dict) else None
    match = _TAG.fullmatch(tag) if isinstance(tag, str) else None
    if match is None:
        raise UpdateCheckError("invalid", "GitHub sent no release tag")
    version = match.group(1)
    page = document.get("html_url")
    # Only a link to the releases of this repository is passed on to the browser
    if not (isinstance(page, str) and page.startswith(RELEASES_PAGE) and urlsplit(page).netloc):
        page = f"{RELEASES_PAGE}tag/{tag}"
    return version, page


def check(settings: Settings, now: float | None = None) -> dict[str, Any]:
    """Describe the latest release against the running version, cached per process.

    ``latest`` and ``release_url`` are None while disabled or when GitHub cannot be reached
    (``error`` is then ``unreachable`` or ``invalid``; the detail is only logged).
    """
    global _cache, _cache_until
    result: dict[str, Any] = {
        "enabled": settings.update_check_enabled,
        "current": __version__,
        "latest": None,
        "update_available": False,
        "release_url": None,
        "checked_at": None,
        "error": None,
    }
    if not settings.update_check_enabled:
        return result
    moment = time.monotonic() if now is None else now
    with _lock:
        if _cache is not None and moment < _cache_until:
            return result | _cache
        try:
            latest, page = fetch_latest(settings)
            found: dict[str, Any] = {
                "latest": latest,
                "update_available": compare_versions(latest, __version__) > 0,
                "release_url": page,
                "error": None,
            }
            ttl = CACHE_SECONDS
        except UpdateCheckError as exc:
            logger.warning("Search for a new version failed: %s", exc)
            found = {"error": exc.code}
            ttl = FAILURE_CACHE_SECONDS
        found["checked_at"] = datetime.now(UTC).isoformat()
        _cache, _cache_until = found, moment + ttl
        return result | found


def clear_cache() -> None:
    """Forget the last answer (tests, change of settings)."""
    global _cache, _cache_until
    with _lock:
        _cache, _cache_until = None, 0.0
