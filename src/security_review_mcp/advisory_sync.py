"""Download of the OSV advisory exports by the controller (opt-in).

When ``SECREVIEW_OSV_AUTO_UPDATE`` is enabled, ``security-review-controller serve`` downloads
the per-ecosystem ``all.zip`` archives published by osv.dev (or a mirror) once a day and imports
them with advisories.import_advisories; ``security-review-controller advisories update`` does
the same on demand. This is the only outgoing connection of the controller: the MCP server
never makes one. The download goes through an optional HTTP proxy, only over HTTPS, and its size
is bounded by ``SECREVIEW_OSV_MAX_DOWNLOAD_MB``.
"""

import logging
import ssl
import tempfile
import threading
import urllib.error
import urllib.request
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote, urlsplit

from . import __version__, advisories
from .config import Settings, get_settings

logger = logging.getLogger(__name__)

DOWNLOAD_TIMEOUT = 60
CHUNK_BYTES = 1024 * 1024
# Delay before trying again when an update failed or imported nothing
RETRY_SECONDS = 3600


class _HttpsRedirectOnly(urllib.request.HTTPRedirectHandler):
    """Follow redirects (mirrors may serve the archive from object storage) to HTTPS only."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        """Refuse a redirect to another scheme than HTTPS (plain HTTP, ftp, file...)."""
        if urlsplit(newurl).scheme != "https":
            raise urllib.error.HTTPError(
                req.full_url, code, "redirect to a non-HTTPS URL refused", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def safe_url(url: str) -> str:
    """Return ``url`` without its user information, so that it can be logged."""
    parts = urlsplit(url)
    return parts._replace(netloc=parts.netloc.rpartition("@")[2]).geturl()


def ecosystems_of(settings: Settings) -> list[str]:
    """Return the canonical ecosystems of ``SECREVIEW_OSV_ECOSYSTEMS`` (comma separated)."""
    names = [name.strip() for name in settings.osv_ecosystems.split(",") if name.strip()]
    if not names:
        raise ValueError("SECREVIEW_OSV_ECOSYSTEMS is empty")
    canonical = []
    for name in names:
        ecosystem = advisories.canonical_ecosystem(name)
        if ecosystem is None:
            supported = sorted(advisories.SUPPORTED_ECOSYSTEMS.values())
            raise ValueError(f"SECREVIEW_OSV_ECOSYSTEMS: unsupported {name!r}; use {supported}")
        canonical.append(ecosystem)
    return list(dict.fromkeys(canonical))


def validate_settings(settings: Settings) -> None:
    """Check the download settings; raise ValueError with the name of the wrong variable."""
    url = urlsplit(settings.osv_url)
    if url.scheme != "https" or not url.hostname:
        raise ValueError("SECREVIEW_OSV_URL must be an https:// URL")
    if url.username or url.password:
        raise ValueError("SECREVIEW_OSV_URL must not contain credentials")
    if settings.osv_proxy:
        proxy = urlsplit(settings.osv_proxy)
        if proxy.scheme != "http" or not proxy.hostname:
            raise ValueError("SECREVIEW_OSV_PROXY must be an http://[user:password@]host:port URL")
    if settings.osv_cafile and not Path(settings.osv_cafile).is_file():
        raise ValueError(f"SECREVIEW_OSV_CAFILE: file not found: {settings.osv_cafile}")
    if settings.osv_update_interval_hours < 1:
        raise ValueError("SECREVIEW_OSV_UPDATE_INTERVAL_HOURS must be at least 1")
    if settings.osv_max_download_mb < 1:
        raise ValueError("SECREVIEW_OSV_MAX_DOWNLOAD_MB must be at least 1")
    ecosystems_of(settings)


def build_opener(settings: Settings) -> urllib.request.OpenerDirector:
    """Build the HTTPS opener: CA bundle, HTTPS-only redirects and the optional proxy.

    Without ``SECREVIEW_OSV_PROXY``, urllib applies the standard ``HTTPS_PROXY`` and
    ``NO_PROXY`` environment variables.
    """
    context = ssl.create_default_context(cafile=settings.osv_cafile)
    handlers: list[urllib.request.BaseHandler] = [
        urllib.request.HTTPSHandler(context=context),
        _HttpsRedirectOnly(),
    ]
    if settings.osv_proxy:
        proxies = {"http": settings.osv_proxy, "https": settings.osv_proxy}
        handlers.append(urllib.request.ProxyHandler(proxies))
    return urllib.request.build_opener(*handlers)


def export_url(settings: Settings, ecosystem: str) -> str:
    """Return the URL of the ``all.zip`` export of an ecosystem."""
    return f"{settings.osv_url.rstrip('/')}/{quote(ecosystem)}/all.zip"


def download_export(
    opener: urllib.request.OpenerDirector, url: str, target: Path, max_bytes: int
) -> int:
    """Stream ``url`` into ``target`` and return its size; refuse more than ``max_bytes``."""
    request = urllib.request.Request(
        url, headers={"User-Agent": f"security-review-mcp/{__version__}"}
    )
    with opener.open(request, timeout=DOWNLOAD_TIMEOUT) as response, target.open("wb") as output:
        declared = response.headers.get("Content-Length")
        if declared and declared.isdigit() and int(declared) > max_bytes:
            raise ValueError(f"{url}: {declared} bytes, more than the {max_bytes} allowed")
        size = 0
        while chunk := response.read(CHUNK_BYTES):
            size += len(chunk)
            if size > max_bytes:
                raise ValueError(f"{url}: more than the {max_bytes} bytes allowed")
            output.write(chunk)
    return size


def update_advisories(
    settings: Settings | None = None, ecosystems: list[str] | None = None
) -> dict:
    """Download and import the OSV export of each ecosystem.

    An ecosystem that fails (network, size, archive) does not stop the others: its entry holds
    an ``error`` instead of the import counters. The archives are written in a private temporary
    directory, removed afterwards.
    """
    settings = settings or get_settings()
    validate_settings(settings)
    wanted = ecosystems or ecosystems_of(settings)
    opener = build_opener(settings)
    max_bytes = settings.osv_max_download_mb * 1024 * 1024
    if settings.osv_proxy:
        logger.info("OSV download through the proxy %s", safe_url(settings.osv_proxy))
    results: dict[str, dict] = {}
    with tempfile.TemporaryDirectory(prefix="secreview-osv-") as directory:
        for ecosystem in wanted:
            url = export_url(settings, ecosystem)
            archive = Path(directory) / f"{ecosystem}.zip"
            try:
                size = download_export(opener, url, archive, max_bytes)
                logger.info("Downloaded %s (%d bytes)", url, size)
                stats = advisories.import_advisories(archive, {ecosystem})
                results[ecosystem] = {"downloaded_bytes": size, **stats}
            except (OSError, ValueError, zipfile.BadZipFile) as exc:
                logger.warning("OSV update of %s failed: %s", ecosystem, exc)
                results[ecosystem] = {"error": f"{type(exc).__name__}: {exc}"}
            finally:
                archive.unlink(missing_ok=True)
    return {"source": settings.osv_url, "ecosystems": results}


# ── Daily update in the controller ───────────────────────────────────────────


def seconds_until_due(
    last_imported_at: datetime | None, interval_hours: int, now: datetime | None = None
) -> float:
    """Seconds before the next update: 0 when the database is empty or older than the interval.

    The age of the database decides, so that a restart or a second controller replica does not
    download the exports again before the interval has elapsed.
    """
    if last_imported_at is None:
        return 0.0
    now = now or datetime.now(UTC)
    elapsed = (now - last_imported_at).total_seconds()
    return max(0.0, interval_hours * 3600 - elapsed)


class AdvisoryUpdater:
    """Background thread of the controller that keeps the advisory database up to date."""

    def __init__(self, settings: Settings) -> None:
        """Prepare the updater; ``start`` launches the thread."""
        self.settings = settings
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self.run, name="osv-updater", daemon=True)

    def next_delay(self) -> float:
        """Seconds to wait before the next update, from the age of the database."""
        last = advisories.last_imported_at()
        return seconds_until_due(last, self.settings.osv_update_interval_hours)

    def run(self) -> None:
        """Update when due, then wait for the next due date, until ``stop`` is called."""
        try:
            delay = self.next_delay()
        except Exception:
            logger.exception("Cannot read the advisory database; next OSV update in 1 hour")
            delay = RETRY_SECONDS
        while not self._stop.wait(delay):
            try:
                result = update_advisories(self.settings)
                failed = sorted(e for e, stats in result["ecosystems"].items() if "error" in stats)
                if failed:
                    logger.warning("OSV update incomplete, failed ecosystems: %s", failed)
                else:
                    logger.info("OSV advisories updated")
                delay = max(self.next_delay(), RETRY_SECONDS)
            except Exception:
                logger.exception("OSV update failed; next attempt in 1 hour")
                delay = RETRY_SECONDS

    def start(self) -> None:
        """Start the background thread."""
        logger.info(
            "Daily OSV update enabled (every %d h, from %s)",
            self.settings.osv_update_interval_hours,
            self.settings.osv_url,
        )
        self._thread.start()

    def stop(self) -> None:
        """Ask the thread to stop; a download in progress finishes or times out first."""
        self._stop.set()
