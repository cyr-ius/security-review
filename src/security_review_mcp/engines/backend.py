"""Where the controller runs the rules and OpenGrep: in its own process, or on the scan engines.

Without SECREVIEW_SCAN_ENGINE_URL (default) the controller scans itself (engines.local). With
it, the files go to the scan engines (engines.remote); when no engine answers, the scan is
refused (SECREVIEW_SCAN_ENGINE_FALLBACK=refuse, default: 503 with Retry-After, the controller
stays unloaded) or run here (``local``). A busy engine is never replaced by a local scan: the
engines are alive and ask the clients to come back later.
"""

import logging
from collections import Counter
from collections.abc import Sequence

from ..config import Settings, get_settings, secret_value
from . import local
from .local import Source

logger = logging.getLogger("security_review_mcp.engines")

# Outcomes of the scans sent to the engines by this process (secreview_scan_engine_requests_total)
ENGINE_OUTCOMES = ("scanned", "busy", "unavailable", "fallback", "refused")
ENGINE_REQUESTS: Counter[str] = Counter()


def validate_settings(settings: Settings) -> None:
    """Refuse the scan engines without their shared secret (checked at the start of the
    controller).

    Raises:
        ValueError: If SECREVIEW_SCAN_ENGINE_URL is set without SECREVIEW_SCAN_ENGINE_TOKEN.
    """
    if settings.scan_engine_url and settings.scan_engine_token is None:
        raise ValueError("SECREVIEW_SCAN_ENGINE_URL needs SECREVIEW_SCAN_ENGINE_TOKEN")


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
    if not settings.scan_engine_url or not token:
        return local.scan(sources, fragment)
    # Imported here: only the controller sends scans to the engines
    from . import remote

    try:
        result = remote.scan(
            settings.scan_engine_url,
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
        ENGINE_REQUESTS["busy"] += 1
        raise
    except remote.ScanEngineUnavailableError:
        if settings.scan_engine_fallback != "local":
            ENGINE_REQUESTS["unavailable"] += 1
            raise
        ENGINE_REQUESTS["fallback"] += 1
        logger.warning("No scan engine answered: scanning on the controller")
        return local.scan(sources, fragment)
    ENGINE_REQUESTS["scanned"] += 1
    return result
