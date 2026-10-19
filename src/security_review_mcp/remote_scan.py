"""Client side of a shared MCP server for commit hooks and pipelines: scan dependency files
with the advisory database of the server instead of a local one.

Used by ``security-review-mcp scan-deps``. The CLI reads the files chosen by the operator and
sends their content to the ``scan_dependencies`` tool of the server URL given by the operator,
with its bearer token. Like ``enroll``, this is a client command: the MCP server itself never
opens an outgoing connection.
"""

import functools
import json
import ssl
from collections.abc import Callable

import anyio
import httpx2
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.types import Implementation

from . import enrollment
from .http_server import ENROLLMENT_SERVER_TITLE

MCP_PATH = "/mcp"
TOOL_NAME = "scan_dependencies"
DEFAULT_TIMEOUT = 60.0
# Bound of the error messages taken from the server or from the HTTP stack
MAX_ERROR_CHARS = 500

# Advice given when the server does not accept the token
ENROLL_HINT = "sign in to the web interface and create a new personal MCP token"
# Explanation added to the refusals of the MCP endpoint
_REFUSAL_HINTS = {
    401: f": missing or invalid token (SECREVIEW_TOKEN or --token-stdin); {ENROLL_HINT}",
    403: ": the token is not allowed to call this tool",
}

# Builds the HTTP client from the request headers (tests pass an in-process ASGI transport)
HttpClientFactory = Callable[[dict[str, str]], httpx2.AsyncClient]


def mcp_url(server_url: str, allow_http: bool = False) -> str:
    """Return the MCP endpoint of a server given by its base or MCP URL."""
    return enrollment.server_endpoint(server_url, MCP_PATH, "a dependency scan", allow_http)


def _http_client_factory(cafile: str | None, timeout: float) -> HttpClientFactory:
    """Return a factory of HTTP clients that verify the server certificate with ``cafile``."""
    context = ssl.create_default_context(cafile=cafile)

    def build(headers: dict[str, str]) -> httpx2.AsyncClient:
        """Build an HTTP client sending ``headers`` (redirects are handled by the SDK)."""
        return httpx2.AsyncClient(headers=headers, verify=context, timeout=httpx2.Timeout(timeout))

    return build


def _leaf(error: BaseException) -> BaseException:
    """Return the first exception of nested exception groups (raised by the task groups)."""
    while isinstance(error, BaseExceptionGroup) and error.exceptions:
        error = error.exceptions[0]
    return error


def _tool_text(result: object) -> str:
    """Join the text blocks of a tool result."""
    blocks = getattr(result, "content", None) or []
    return "".join(getattr(block, "text", "") for block in blocks)


def _scan_result(result: object) -> dict | None:
    """Return the scan result of a tool answer (structured content or JSON text), or None."""
    data = getattr(result, "structured_content", None)
    if data is None:
        try:
            data = json.loads(_tool_text(result))
        except ValueError:
            return None
    if not isinstance(data, dict) or "vulnerability_check" not in data:
        return None
    return data


async def _scan(
    url: str, files: list[tuple[str, str]], http_client: httpx2.AsyncClient, refused: list[int]
) -> list[dict]:
    """Call the scan tool of the server once per file and return the scan results.

    The HTTP status of the answers refused by the server (401, 403...) is added to
    ``refused``: the SDK only reports them as a generic error.
    """

    async def record_refusal(response: httpx2.Response) -> None:
        """Remember the status of a refused HTTP answer."""
        if response.status_code >= 400:
            refused.append(response.status_code)

    http_client.event_hooks["response"].append(record_refusal)
    results: list[dict] = []
    transport = streamable_http_client(url, http_client=http_client)
    client_info = Implementation(name="security-review-mcp scan-deps", version="1")
    async with http_client, Client(transport, client_info=client_info) as client:
        if client.server_info.title == ENROLLMENT_SERVER_TITLE:
            # A server with enrollment answers a request without a token with its enrollment
            # server instead of a 401
            raise ValueError(f"{url} received no token (SECREVIEW_TOKEN or --token-stdin)")
        for filename, content in files:
            result = await client.call_tool(TOOL_NAME, {"content": content, "filename": filename})
            if result.is_error:
                detail = _tool_text(result)[:MAX_ERROR_CHARS] or "no detail"
                raise ValueError(f"The server refused {filename}: {detail}")
            data = _scan_result(result)
            if data is None:
                raise ValueError(f"Unexpected answer from {url} for {filename}")
            results.append(data)
    return results


async def scan_files_async(
    server_url: str,
    files: list[tuple[str, str]],
    token: str | None = None,
    cafile: str | None = None,
    allow_http: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
    http_client_factory: HttpClientFactory | None = None,
) -> list[dict]:
    """Scan ``files`` (file name, content) with the ``scan_dependencies`` tool of a server.

    The token is only sent to the MCP endpoint of ``server_url``, which refuses plain HTTP
    (except on a loopback address or with ``allow_http``) and redirects to another origin.

    Raises:
        ValueError: Invalid URL, unreachable server, request refused or unexpected answer.
    """
    url = mcp_url(server_url, allow_http)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    factory = http_client_factory or _http_client_factory(cafile, timeout)
    refused: list[int] = []
    try:
        return await _scan(url, files, factory(headers), refused)
    except Exception as exc:  # the SDK raises exception groups, HTTP and protocol errors
        error = _leaf(exc)
        if isinstance(error, ValueError):
            raise error from exc
        if refused:
            hint = _REFUSAL_HINTS.get(refused[-1], "")
            raise ValueError(f"The server refused the request ({refused[-1]}){hint}") from exc
        # The message never holds the token: it is only in the request headers
        detail = str(error)[:MAX_ERROR_CHARS] or type(error).__name__
        raise ValueError(f"Cannot scan with {url}: {detail}") from exc


def scan_files(
    server_url: str,
    files: list[tuple[str, str]],
    token: str | None = None,
    cafile: str | None = None,
    allow_http: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[dict]:
    """Run scan_files_async from synchronous code (the CLI)."""
    return anyio.run(
        functools.partial(
            scan_files_async,
            server_url,
            files,
            token=token,
            cafile=cafile,
            allow_http=allow_http,
            timeout=timeout,
        )
    )
