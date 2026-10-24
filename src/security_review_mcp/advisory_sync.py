"""Download of the OSV advisory exports by the controller (opt-in).

When ``SECREVIEW_OSV_AUTO_UPDATE`` is enabled, ``security-review-controller serve`` downloads
the per-ecosystem ``all.zip`` archives published by osv.dev (or a mirror) once a day and imports
them with advisories.import_advisories, and an administrator may start an update from the web
interface; ``security-review-controller advisories update`` does the same on demand. The MCP
server never makes an outgoing connection. The download goes through the proxy of the
controller (see proxy, effective settings read at each update), only over HTTPS, and its size
is bounded by ``SECREVIEW_OSV_MAX_DOWNLOAD_MB``.

Every update is recorded in the ``advisoryupdate`` table (history shown in the web interface).
One update at a time runs in a controller process.
"""

import json
import logging
import ssl
import tempfile
import threading
import urllib.error
import urllib.request
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote, urlsplit

from sqlmodel import col, select

from . import __version__, advisories, app_settings
from .config import Settings, get_settings
from .database import session_scope
from .models import AdvisoryUpdate, utcnow
from .proxy import check_proxy_url, proxy_handler

logger = logging.getLogger("security_review_mcp.advisory_sync")

DOWNLOAD_TIMEOUT = 60
CHUNK_BYTES = 1024 * 1024
# Delay before trying again when an update failed or imported nothing
RETRY_SECONDS = 3600
# Updates kept in the history
HISTORY_SIZE = 50
# A "running" update older than this was interrupted (controller stopped during the download)
RUNNING_TIMEOUT = timedelta(hours=6)
MAX_ERROR_CHARS = 500

# One update at a time in this process (daily thread, web interface)
_lock = threading.Lock()
# Thread of the last update started from the web interface (joined by the tests)
_web_worker: threading.Thread | None = None


class UpdateInProgress(RuntimeError):
    """An OSV update is already running."""


class DownloadDisabled(RuntimeError):
    """The OSV download is disabled (SECREVIEW_OSV_AUTO_UPDATE=false)."""


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
    if settings.proxy:
        check_proxy_url(settings.proxy, "HTTPS_PROXY / HTTP_PROXY")
    if settings.osv_cafile and not Path(settings.osv_cafile).is_file():
        raise ValueError(f"SECREVIEW_OSV_CAFILE: file not found: {settings.osv_cafile}")
    if settings.osv_update_interval_hours < 1:
        raise ValueError("SECREVIEW_OSV_UPDATE_INTERVAL_HOURS must be at least 1")
    if settings.osv_max_download_mb < 1:
        raise ValueError("SECREVIEW_OSV_MAX_DOWNLOAD_MB must be at least 1")
    ecosystems_of(settings)


def build_opener(settings: Settings) -> urllib.request.OpenerDirector:
    """Build the HTTPS opener: CA bundle, HTTPS-only redirects and the proxy of ``settings``
    (effective settings, see proxy.proxy_handler)."""
    context = ssl.create_default_context(cafile=settings.osv_cafile)
    handlers: list[urllib.request.BaseHandler] = [
        urllib.request.HTTPSHandler(context=context),
        _HttpsRedirectOnly(),
        proxy_handler(settings),
    ]
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
    # The proxy set in the web interface applies from the next update
    settings = app_settings.effective_settings(settings or get_settings())
    validate_settings(settings)
    wanted = ecosystems or ecosystems_of(settings)
    opener = build_opener(settings)
    max_bytes = settings.osv_max_download_mb * 1024 * 1024
    if settings.proxy:
        logger.info("OSV download through the proxy %s", safe_url(settings.proxy))
    else:
        logger.info("OSV download without proxy")
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


# ── Recorded updates (history) ───────────────────────────────────────────────


def _scrub(text: str, settings: Settings) -> str:
    """Remove the proxy credentials from an error message and bound its length."""
    for url in (settings.proxy, app_settings.effective_settings(settings).proxy):
        if url:
            text = text.replace(url, safe_url(url))
    return text[:MAX_ERROR_CHARS]


def _begin(settings: Settings, trigger: str, triggered_by: str | None) -> int:
    """Record the start of an update and drop the oldest entries of the history."""
    with session_scope() as session:
        entry = AdvisoryUpdate(
            trigger=trigger,
            triggered_by=triggered_by[:64] if triggered_by else None,
            source=settings.osv_url[:500],
        )
        session.add(entry)
        session.flush()
        old = session.exec(
            select(AdvisoryUpdate)
            .order_by(col(AdvisoryUpdate.started_at).desc(), col(AdvisoryUpdate.id).desc())
            .offset(HISTORY_SIZE)
        ).all()
        for row in old:
            session.delete(row)
        return entry.id  # type: ignore[return-value]


def _finish(update_id: int, status: str, results: dict) -> None:
    """Record the end of an update."""
    with session_scope() as session:
        entry = session.get(AdvisoryUpdate, update_id)
        if entry is None:  # dropped from the history meanwhile
            return
        entry.status = status
        entry.finished_at = utcnow()
        entry.results = json.dumps(results)
        session.add(entry)


def _execute(update_id: int, settings: Settings) -> dict:
    """Run a recorded update and store its outcome; an unexpected error is stored and raised."""
    try:
        result = update_advisories(settings)
    except Exception as exc:
        _finish(update_id, "failed", {"error": _scrub(f"{type(exc).__name__}: {exc}", settings)})
        raise
    ecosystems = result["ecosystems"]
    for stats in ecosystems.values():
        if "error" in stats:
            stats["error"] = _scrub(stats["error"], settings)
    failed = sum("error" in stats for stats in ecosystems.values())
    status = "success" if not failed else "failed" if failed == len(ecosystems) else "partial"
    _finish(update_id, status, ecosystems)
    return result


def run_update(settings: Settings, trigger: str, triggered_by: str | None = None) -> dict:
    """Download and import the OSV exports now, and record the update in the history.

    Raises:
        ValueError: If the download settings are invalid (nothing is recorded).
        UpdateInProgress: If another update runs in this process.
    """
    validate_settings(settings)
    if not _lock.acquire(blocking=False):
        raise UpdateInProgress("an OSV update is already running")
    try:
        return _execute(_begin(settings, trigger, triggered_by), settings)
    finally:
        _lock.release()


def running_update() -> AdvisoryUpdate | None:
    """Return the update in progress (any controller replica), if any."""
    since = utcnow() - RUNNING_TIMEOUT
    with session_scope() as session:
        return session.exec(
            select(AdvisoryUpdate)
            .where(AdvisoryUpdate.status == "running", AdvisoryUpdate.started_at >= since)
            .order_by(col(AdvisoryUpdate.started_at).desc())
        ).first()


def start_web_update(settings: Settings, triggered_by: str) -> int:
    """Start an update in a background thread on behalf of an administrator; return its id.

    Raises:
        DownloadDisabled: If SECREVIEW_OSV_AUTO_UPDATE is false.
        ValueError: If the download settings are invalid.
        UpdateInProgress: If an update already runs (in this process or another replica).
    """
    global _web_worker
    if not settings.osv_auto_update:
        raise DownloadDisabled("the OSV download is disabled (SECREVIEW_OSV_AUTO_UPDATE=false)")
    validate_settings(settings)
    if not _lock.acquire(blocking=False):
        raise UpdateInProgress("an OSV update is already running")
    try:
        if running_update() is not None:
            raise UpdateInProgress("an OSV update is already running")
        update_id = _begin(settings, "web", triggered_by)
    except BaseException:
        _lock.release()
        raise

    def work() -> None:
        """Run the update, then let the next one start."""
        try:
            _execute(update_id, settings)
            logger.info("OSV update %d started by %s finished", update_id, triggered_by)
        except Exception:
            logger.exception("OSV update %d failed", update_id)
        finally:
            _lock.release()

    _web_worker = threading.Thread(target=work, name="osv-web-update", daemon=True)
    _web_worker.start()
    return update_id


def _public(entry: AdvisoryUpdate, now: datetime) -> dict:
    """An entry of the history as returned by the API."""
    started = entry.started_at if entry.started_at.tzinfo else entry.started_at.replace(tzinfo=UTC)
    status = entry.status
    if status == "running" and now - started > RUNNING_TIMEOUT:
        status = "interrupted"
    return {
        "id": entry.id,
        "trigger": entry.trigger,
        "triggered_by": entry.triggered_by,
        "status": status,
        "source": entry.source,
        "started_at": entry.started_at.isoformat(),
        "finished_at": entry.finished_at.isoformat() if entry.finished_at else None,
        "results": json.loads(entry.results or "{}"),
    }


def list_updates(limit: int = 20) -> list[dict]:
    """Return the most recent updates, newest first."""
    now = utcnow()
    with session_scope() as session:
        rows = session.exec(
            select(AdvisoryUpdate)
            .order_by(col(AdvisoryUpdate.started_at).desc(), col(AdvisoryUpdate.id).desc())
            .limit(max(1, min(limit, HISTORY_SIZE)))
        ).all()
        return [_public(row, now) for row in rows]


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
                result = run_update(self.settings, "schedule")
                failed = sorted(e for e, stats in result["ecosystems"].items() if "error" in stats)
                if failed:
                    logger.warning("OSV update incomplete, failed ecosystems: %s", failed)
                else:
                    logger.info("OSV advisories updated")
                delay = max(self.next_delay(), RETRY_SECONDS)
            except UpdateInProgress:
                logger.info("OSV update already running; next check in 1 hour")
                delay = RETRY_SECONDS
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
