"""Scan engine (``security-review-scan-engine``): runs the rules and OpenGrep for the controller.

Optional (SECREVIEW_SCAN_ENGINE_TOKEN on the controller): with many developers, the code scans of
``security-review-ci`` and the fragments of scan_code take the CPU and the memory of the
controller. The engines take this work over, as many replicas as needed behind one address;
the controller keeps the authentication, the scan tickets, the reports and the verdicts.

An engine serves ``POST /engine/v1/scan`` to the controller only (shared secret
SECREVIEW_SCAN_ENGINE_TOKEN, compared by its SHA-256 digest in constant time, checked before the
body is read) and ``/healthz``. It keeps no state but its counters, reads no database and loads
none of the modules of the controller.

At its start it enrolls with the controller at SECREVIEW_CONTROLLER_URL with the URL where the
controller reaches it (SECREVIEW_SCAN_ENGINE_ADVERTISE_URL, or its IP address and port), then
gets an OAuth access token of its own and sends a heartbeat with its free OpenGrep slots and
its counters (engines.controller_client); no address to configure on the controller. When it
stops (SIGTERM: rolling update, node drained, scale down), it tells the controller, which
forgets it at once: it enrolls as a new client at its next start, on any node. Before
each scan it brings its copy of the internal rules and of the OpenGrep rules of the controller
up to date (engines.rule_sync).
That is its only outgoing connection, to the controller only.
"""

import argparse
import logging
import socket
import threading
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, status
from starlette.concurrency import run_in_threadpool
from starlette.types import ASGIApp

from .. import __version__, http_server
from ..config import Settings, configure_logging, get_settings, secret_value
from ..rules import registry, scanner
from . import controller_client, local, opengrep, rule_sync
from .protocol import (
    ENGINE_SCAN_PATH,
    MAX_ENGINE_COUNTER,
    EngineAuth,
    EngineHeartbeat,
    EngineRequest,
    EngineResponse,
)

logger = logging.getLogger("security_review_mcp.engines")

PROGRAM = "security-review-scan-engine"

__all__ = ["EngineAuth", "build_app", "create_app", "main"]


# What this engine did since it started, sent with each heartbeat (see EngineHeartbeat)
_counters: Counter[str] = Counter()
# What it is doing now (gauges): scans by pool ("codebase", "fragment") and their "files"
_processing: Counter[str] = Counter()
_counters_lock = threading.Lock()
_controller_client: controller_client.ControllerClient | None = None

# Copy of the rules of the controller, set by main (None: the rules of this process, in tests)
_rules: rule_sync.RuleCache | None = None


def _notify_controller() -> None:
    """Wake the heartbeat thread after the current workload changes."""
    client = _controller_client
    if client is not None:
        with _counters_lock:
            active = _processing["codebase"] + _processing["fragment"] > 0
        client.notify_activity_change(active)


@contextmanager
def _processing_scan(pool: str, files: int) -> Iterator[None]:
    """Count a scan of ``pool`` and its files as running while the block runs, waking the
    heartbeat when it starts and ends."""
    with _counters_lock:
        _processing.update({pool: 1, "files": files})
    _notify_controller()
    try:
        yield
    finally:
        with _counters_lock:
            _processing.subtract({pool: 1, "files": files})
        _notify_controller()


def _own_url(host: str, port: int, tls: object) -> str:
    """URL of this engine when SECREVIEW_SCAN_ENGINE_ADVERTISE_URL is unset: the IP address of
    its host name (the pod or container IP), or the loopback address it listens on."""
    if host in http_server.LOOPBACK_HOSTS:
        address = "127.0.0.1"
    else:
        try:
            address = socket.gethostbyname(socket.gethostname())
        except OSError:
            address = "127.0.0.1"
    return f"{'https' if tls else 'http'}://{address}:{port}"


def _count(**increments: int) -> None:
    """Add to the counters sent with the heartbeat."""
    with _counters_lock:
        _counters.update(increments)


def _status() -> EngineHeartbeat:
    """Free OpenGrep slots of this engine, its capacity and its counters, sent with each
    heartbeat."""
    settings = get_settings()
    codebase, fragment = opengrep.free_slots()
    with _counters_lock:
        counters = {name: min(value, MAX_ENGINE_COUNTER) for name, value in _counters.items()}
        processing = dict(_processing)
    return EngineHeartbeat(
        free_codebase_slots=codebase,
        free_fragment_slots=fragment,
        codebase_slots=settings.opengrep_max_concurrent_scans,
        fragment_slots=settings.opengrep_max_concurrent_fragment_scans,
        processing_files=processing.get("files", 0),
        processing_codebase_scans=processing.get("codebase", 0),
        processing_fragment_scans=processing.get("fragment", 0),
        **counters,
    )


def _scan(sources: list[local.Source], fragment: bool) -> dict:
    """Scan ``sources`` with the rules of the controller, brought up to date first (see
    engines.rule_sync)."""
    if _rules is None:
        return local.scan(sources, fragment)
    with _rules.use() as opengrep_rules:
        return local.scan(sources, fragment, opengrep_rules)


def _sources(request: EngineRequest, settings: Settings) -> list[local.Source]:
    """The files of ``request``, bounded as on the controller and with a known language.

    Raises:
        ValueError: If a bound is exceeded or a language is unknown.
    """
    if request.fragment and len(request.sources) != 1:
        raise ValueError("A fragment scan has exactly one file")
    if len(request.sources) > settings.max_scan_files:
        raise ValueError(
            f"Too many files ({len(request.sources)}); the limit is {settings.max_scan_files} "
            "(SECREVIEW_MAX_SCAN_FILES)"
        )
    limit = settings.max_content_chars if request.fragment else settings.max_scan_file_chars
    sources: list[local.Source] = []
    for source in request.sources:
        if len(source.content) > limit:
            raise ValueError(f"A file is larger than {limit} characters")
        language = scanner.normalize_language(source.language)
        sources.append(local.Source(source.path, language, source.content))
    return sources


def create_app() -> FastAPI:
    """Build the application of the engine (without its authentication, see build_app)."""
    app = FastAPI(
        title="Security Review scan engine",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.post(ENGINE_SCAN_PATH, response_model_exclude_unset=True)
    async def scan(request: EngineRequest) -> EngineResponse:
        """Scan the files sent by the controller with the rules, then OpenGrep when enabled.

        422 when the files exceed the bounds, 429 when OpenGrep is busy (the controller asks
        the client to retry), 500 when OpenGrep cannot run (generic message).
        """
        try:
            sources = _sources(request, get_settings())
            pool = "fragment" if request.fragment else "codebase"
            with _processing_scan(pool, len(sources)):
                result = await run_in_threadpool(_scan, sources, request.fragment)
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
        except opengrep.OpenGrepBusyError as exc:
            _count(busy_refusals=1)
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, str(exc)) from exc
        except opengrep.OpenGrepError as exc:
            _count(failed_scans=1)
            # Generic message, never the output of OpenGrep
            logger.warning("OpenGrep failed on the scan engine: %s", exc)
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR, "OpenGrep cannot run on the scan engine"
            ) from exc
        scan_counter = "fragment_scans" if request.fragment else "codebase_scans"
        _count(**{scan_counter: 1, "scanned_files": len(sources)})
        logger.debug("Scanned %d file(s) with %s", len(sources), ", ".join(result["engines"]))
        return EngineResponse.model_validate(result)

    return app


def build_app(token: str, settings: Settings) -> ASGIApp:
    """The HTTP app of the engine: ``/healthz`` open, everything else behind the shared secret,
    then bounded by SECREVIEW_MAX_SCAN_REQUEST_MB, with the security headers on every answer."""
    limit = settings.max_scan_request_mb * 1024 * 1024

    def body_limit(_path: str) -> tuple[int, str]:
        """Bound of a scan request (the controller has already bounded it)."""
        return limit, "SECREVIEW_MAX_SCAN_REQUEST_MB)"

    app: ASGIApp = http_server.BodyLimit(create_app(), body_limit)
    app = EngineAuth(app, token)
    app = http_server.PathDispatcher(app, {http_server.HEALTH_PATH: http_server.health_app})
    return http_server.SecurityHeadersMiddleware(app)


def main(argv: list[str] | None = None) -> None:
    """Run ``security-review-scan-engine``: serve the scans of the controller."""
    settings = get_settings()
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description="Scan engine of the Controller server: runs the rules and OpenGrep.",
    )
    http_server.add_listen_arguments(parser, settings)
    parser.add_argument("--version", action="version", version=f"{PROGRAM} {__version__}")
    args = parser.parse_args(argv)
    settings = http_server.with_tls_arguments(settings, args)
    configure_logging(settings.log_level)
    token = secret_value(settings.scan_engine_token)
    if not token:
        parser.error("SECREVIEW_SCAN_ENGINE_TOKEN is required (the secret of the controller)")
    if not settings.controller_url:
        parser.error(
            "SECREVIEW_CONTROLLER_URL is required: the internal address of the controller, where "
            "the engine enrolls and reads the rules"
        )
    try:
        tls = http_server.tls_options(settings)
    except ValueError as exc:
        parser.error(str(exc))
    global _controller_client, _rules
    # Never the database: no rule until the controller gives them
    registry.publish([], ["no rule received from the Controller server yet"])
    advertised = settings.scan_engine_advertise_url or _own_url(args.host, args.port, tls)
    client = controller_client.ControllerClient(
        settings.controller_url, token, advertised, status=_status
    )
    _controller_client = client
    client.start()
    _rules = rule_sync.RuleCache(
        client,
        Path(settings.opengrep_rules_dir).expanduser() if settings.opengrep_enabled else None,
    )
    try:
        _rules.refresh()
    except opengrep.OpenGrepError as exc:
        # The controller may start after the engine: the next scan tries again
        logger.warning("%s; retrying at the next scan", exc)
    logger.info(
        "Scan engine %s listening on %s:%d (OpenGrep %s)",
        __version__,
        args.host,
        args.port,
        "enabled" if settings.opengrep_enabled else "disabled",
    )
    if tls is None and args.host not in http_server.LOOPBACK_HOSTS:
        logger.warning(
            "Listening on %s without TLS: keep the scan engines on an internal network, or set "
            "SECREVIEW_TLS_CERTFILE and SECREVIEW_TLS_KEYFILE",
            args.host,
        )
    try:
        uvicorn.run(
            build_app(token, settings),
            host=args.host,
            port=args.port,
            log_level=settings.log_level.lower(),
            **(tls.uvicorn_kwargs() if tls else {}),
        )
    finally:
        # The scans in progress are over: the controller forgets this engine at once
        client.leave()


if __name__ == "__main__":
    main()
