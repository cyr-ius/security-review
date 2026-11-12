"""Where the controller runs the rules and OpenGrep: in its own process, or on the scan engines.

Without SECREVIEW_SCAN_ENGINE_TOKEN (default) the controller scans itself (engines.local). With
it, the scan engines enroll with the controller, each one with its own URL, and the files go to
an active engine, the one with the most free OpenGrep slots first (engines.remote); an engine
busy or unreachable is replaced by the next one. When no engine scanned the files, the scan is
refused (SECREVIEW_SCAN_ENGINE_FALLBACK=refuse, default: 503 with Retry-After, the controller
stays unloaded) or run here (``local``). Busy engines are never replaced by a local scan: they
are alive and ask the clients to come back later.
"""

import logging
from collections import Counter
from collections.abc import Sequence

from starlette.types import ASGIApp

from ..config import Settings, get_settings, secret_value
from . import local
from .local import Source

logger = logging.getLogger("security_review_mcp.engines")

# Outcomes of the scans sent to the engines by this process (secreview_scan_engine_requests_total)
ENGINE_OUTCOMES = ("scanned", "busy", "unavailable", "fallback", "refused")
ENGINE_REQUESTS: Counter[str] = Counter()
# Engines tried for one scan before giving up
MAX_ATTEMPTS = 3


def engine_routes(settings: Settings) -> dict[str, ASGIApp]:
    """Routes of the controller where the scan engines enroll and get their access tokens:
    none without SECREVIEW_SCAN_ENGINE_TOKEN (see engines.enrollment)."""
    token = secret_value(settings.scan_engine_token)
    if not token:
        return {}
    # Imported here: only the controller enrolls the engines
    from . import enrollment

    return enrollment.routes(token)


def scan(sources: Sequence[Source], fragment: bool = False) -> dict:
    """Scan ``sources`` here or on the scan engines (see the module docstring).

    Returns:
        ``files`` (one entry per source, in the same order) and ``engines``, as local.scan.

    Raises:
        ValueError: If an engine refused the files.
        opengrep.OpenGrepError: If OpenGrep cannot run, is busy, or no engine scanned the files
            (remote.ScanEngineError, a busy error: 503 with Retry-After).
    """
    settings = get_settings()
    token = secret_value(settings.scan_engine_token)
    if not token:
        return local.scan(sources, fragment)
    # Imported here: only the controller sends scans to the engines
    from ..auth import engine_clients
    from . import remote

    busy = False
    for engine_id, url in engine_clients.active_engines(fragment)[:MAX_ATTEMPTS]:
        try:
            result = remote.scan(
                url,
                token,
                sources,
                fragment,
                settings.scan_engine_timeout_seconds,
                settings.max_scan_request_mb * 1024 * 1024,
            )
        except ValueError:
            ENGINE_REQUESTS["refused"] += 1
            raise
        except remote.ScanEngineBusyError:
            busy = True
            continue
        except remote.ScanEngineUnavailableError:
            logger.warning("Scan engine %s did not scan the files: trying the next one", engine_id)
            continue
        ENGINE_REQUESTS["scanned"] += 1
        return result
    if busy:
        ENGINE_REQUESTS["busy"] += 1
        raise remote.ScanEngineBusyError("The scan engines are busy with other scans; retry later")
    if settings.scan_engine_fallback != "local":
        ENGINE_REQUESTS["unavailable"] += 1
        raise remote.ScanEngineUnavailableError(remote.UNAVAILABLE)
    ENGINE_REQUESTS["fallback"] += 1
    logger.warning("No scan engine scanned the files: scanning on the controller")
    return local.scan(sources, fragment)
