"""Scan engine (``security-review-scan-engine``): runs the rules and OpenGrep for the controller.

Optional (SECREVIEW_SCAN_ENGINE_URL on the controller): with many developers, the code scans of
``security-review-ci`` and the fragments of scan_code take the CPU and the memory of the
controller. The engines take this work over, as many replicas as needed behind one address;
the controller keeps the authentication, the scan tickets, the reports and the verdicts.

An engine serves ``POST /engine/v1/scan`` to the controller only (shared secret
SECREVIEW_SCAN_ENGINE_TOKEN, compared by its SHA-256 digest in constant time, checked before the
body is read) and ``/healthz``. It keeps no state, writes nothing to the database (it reads the
rules: a read-only database account is enough), opens no outgoing connection and loads none of
the modules of the controller. Its OpenGrep rules are the directory SECREVIEW_OPENGREP_RULES_DIR,
the volume of the controller mounted read-only.
"""

import argparse
import hashlib
import hmac
import json
import logging

import uvicorn
from fastapi import FastAPI, HTTPException, status
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from .. import __version__, http_server
from ..config import Settings, configure_logging, get_settings, secret_value
from ..rules import registry, scanner
from ..storage.database import SchemaError, check_db
from . import local, opengrep
from .protocol import ENGINE_SCAN_PATH, EngineRequest, EngineResponse

logger = logging.getLogger("security_review_mcp.engines")

PROGRAM = "security-review-scan-engine"


class EngineAuth:
    """Refuse (401) every request but ``/healthz`` without the shared secret of the engines."""

    def __init__(self, app: ASGIApp, token: str) -> None:
        self.app = app
        self.digest = hashlib.sha256(token.encode()).digest()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") == http_server.HEALTH_PATH:
            await self.app(scope, receive, send)
            return
        scheme, _, credentials = Headers(scope=scope).get("authorization", "").partition(" ")
        presented = hashlib.sha256(credentials.strip().encode()).digest()
        if scheme.lower() == "bearer" and hmac.compare_digest(presented, self.digest):
            await self.app(scope, receive, send)
            return
        body = json.dumps({"detail": "Missing or invalid scan engine token"}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"www-authenticate", b'Bearer realm="secreview-scan-engine"'),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


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
            result = await run_in_threadpool(local.scan, sources, request.fragment)
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
        except opengrep.OpenGrepBusyError as exc:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, str(exc)) from exc
        except opengrep.OpenGrepError as exc:
            # Generic message, never the output of OpenGrep
            logger.warning("OpenGrep failed on the scan engine: %s", exc)
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR, "OpenGrep cannot run on the scan engine"
            ) from exc
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
    try:
        # Never migrates: the controller does
        check_db()
        tls = http_server.tls_options(settings)
    except (ValueError, SchemaError) as exc:
        parser.error(str(exc))
    registry.reload()
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
    uvicorn.run(
        build_app(token, settings),
        host=args.host,
        port=args.port,
        log_level=settings.log_level.lower(),
        **(tls.uvicorn_kwargs() if tls else {}),
    )


if __name__ == "__main__":
    main()
