"""Health check of the Docker image: ``python -m security_review_mcp.healthcheck``.

The image runs the HTTP MCP server by default (``serve``), the MCP server in stdio
(``serve --transport stdio``, no port) or the controller (``security-review-controller serve``).
The check reads the command of the container (process 1) and, for the two HTTP processes only,
requests ``/healthz`` on the loopback interface; in stdio there is nothing to check and it
succeeds. Exit code 0: healthy, 1: unhealthy (Docker convention).

Only the standard library and the settings are imported, so that the check stays fast.
"""

import ssl
import sys
import urllib.request
from pathlib import Path

from .config import get_settings

# Same path as http_server.HEALTH_PATH (not imported: it loads the whole web stack)
HEALTH_PATH = "/healthz"
TIMEOUT_SECONDS = 3
# Script or module of the controller in its command line (`python -m` included)
CONTROLLER_PROGRAMS = frozenset({"security-review-controller", "security_review_mcp.controller"})
# Command line of the main process of the container
PROCESS_CMDLINE = Path("/proc/1/cmdline")


def container_command(path: Path = PROCESS_CMDLINE) -> list[str]:
    """Arguments of the main process of the container, or [] when they cannot be read."""
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    return [part.decode(errors="replace") for part in raw.split(b"\0") if part]


def _option(args: list[str], name: str) -> str | None:
    """Value of ``--name value`` or ``--name=value`` in ``args``, the last one winning."""
    value = None
    for index, arg in enumerate(args):
        if arg == name and index + 1 < len(args):
            value = args[index + 1]
        elif arg.startswith(f"{name}="):
            value = arg.partition("=")[2]
    return value


def health_url(args: list[str]) -> str | None:
    """URL of /healthz for the HTTP process started by ``args``; None in stdio.

    The port, the transport and TLS come from the command line, else from the SECREVIEW_*
    settings.
    """
    settings = get_settings()
    # Only `serve` listens (not `enroll`, `db upgrade`...)
    if "serve" not in args:
        return None
    # Both programs have a `serve` command: only the controller's is always HTTP
    controller = any(Path(arg).name in CONTROLLER_PROGRAMS for arg in args)
    transport = _option(args, "--transport") or settings.transport
    if not controller and transport != "streamable-http":
        return None
    port = _option(args, "--port") or str(settings.port)
    scheme = "https" if server_certificate(args) else "http"
    return f"{scheme}://127.0.0.1:{int(port)}{HEALTH_PATH}"


def server_certificate(args: list[str]) -> str | None:
    """Certificate file served by the process (``--tls-certfile`` or SECREVIEW_TLS_CERTFILE)."""
    return _option(args, "--tls-certfile") or get_settings().tls_certfile


def client_certificate_required() -> bool:
    """True with mutual TLS: the check, which has no client certificate, cannot request."""
    return bool(get_settings().tls_client_ca)


def tls_context(certfile: str) -> ssl.SSLContext:
    """TLS context that trusts only the certificate of the process itself.

    The request goes to 127.0.0.1 while the certificate names the public host: the host name is
    not checked, but the certificate must be the one of ``certfile`` (partial chain, verified
    by default since Python 3.13), so nothing else on the port is trusted.
    """
    context = ssl.create_default_context(cafile=certfile)
    context.check_hostname = False
    return context


def check(url: str, certfile: str | None = None) -> bool:
    """True when ``url`` answers 200 within TIMEOUT_SECONDS (HTTPS: from ``certfile``)."""
    context = tls_context(certfile) if url.startswith("https://") and certfile else None
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT_SECONDS, context=context) as response:
            return response.status == 200
    except OSError, ValueError:
        return False


def main(argv: list[str] | None = None) -> int:
    """Check the process of the container (``argv``: its command, read from /proc by default)."""
    args = container_command() if argv is None else argv
    url = health_url(args)
    if url is None or client_certificate_required():
        # stdio: nothing listens; mutual TLS: no client certificate to present (rely on the
        # orchestrator probes, see docs/advanced/docker)
        return 0
    healthy = check(url, server_certificate(args))
    if not healthy:
        print(f"unhealthy: no answer from {url}", file=sys.stderr)
    return 0 if healthy else 1


if __name__ == "__main__":
    sys.exit(main())
