"""HTTP client given to the connectors (see api.HttpClient): the only way they reach a system.

Every request goes to the configured URL of the connection only (a path relative to it), over
HTTPS with certificate verification (SECREVIEW_TICKETING_CAFILE for an internal authority),
through the outgoing proxy, with a timeout; redirects are refused (they would carry the
credentials elsewhere) and the answer, a JSON object, is bounded. A failure raises
TicketingError with a short code and a bounded excerpt of the error message of the system,
without the secrets of the connection nor those that redact_secrets recognizes.
"""

import json
import ssl
import urllib.error
import urllib.request
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlencode, urlsplit

from .. import __version__
from ..config import Settings
from ..proxy import masked_url, proxy_handler
from ..rules.scanner import redact_secrets
from .api import TicketingError

HTTP_TIMEOUT = 15
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_ERROR_BYTES = 16 * 1024
MAX_ERROR_CHARS = 300
METHODS = frozenset({"GET", "POST", "PUT", "PATCH"})


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: it would send the credentials (and the finding) elsewhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        """Fail instead of following the redirect."""
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def _opener(settings: Settings) -> urllib.request.OpenerDirector:
    """HTTPS opener with the proxy of the controller and the optional CA bundle."""
    context = ssl.create_default_context(cafile=settings.ticketing_cafile)
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context), _NoRedirect(), proxy_handler(settings)
    )


def _error_messages(document: Any) -> list[str]:
    """Error messages of a Jira-like or ServiceNow-like JSON error answer."""
    messages: list[str] = []
    if not isinstance(document, dict):
        return messages
    messages += [str(m) for m in document.get("errorMessages") or [] if m]
    errors = document.get("errors")
    if isinstance(errors, dict):
        messages += [f"{key}: {value}" for key, value in errors.items()]
    error = document.get("error")
    if isinstance(error, dict):
        messages += [str(error[key]) for key in ("message", "detail") if error.get(key)]
    elif isinstance(error, str):
        messages.append(error)
    if isinstance(document.get("message"), str):
        messages.append(document["message"])
    return messages


class ConnectionClient:
    """HTTP client of one connection (implements api.HttpClient)."""

    def __init__(
        self,
        settings: Settings,
        name: str,
        base_url: str,
        headers: Mapping[str, str],
        secrets: Iterable[str],
    ) -> None:
        """``headers`` authenticate the requests; ``secrets`` are removed from the errors."""
        self.settings = settings
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.headers = dict(headers)
        self.secrets = [secret for secret in secrets if secret]
        self._origin = urlsplit(self.base_url)

    def scrub(self, text: str) -> str:
        """``text`` without the secrets of the connection nor the proxy credentials."""
        for secret in self.secrets:
            text = text.replace(secret, "***")
        if self.settings.proxy:
            text = text.replace(self.settings.proxy, masked_url(self.settings.proxy))
        return redact_secrets(text)

    def _url(self, path: str, query: Mapping[str, str] | None) -> str:
        """Absolute URL of ``path``, refused outside the configured URL."""
        if (
            not path.startswith("/")
            or any(c in path for c in "?#\\")
            or any(c.isspace() or not c.isprintable() for c in path)
            or "/../" in f"{path}/"
            or "/./" in f"{path}/"
            # Encoded dots and slashes, which the remote server may decode
            or any(encoded in path.lower() for encoded in ("%2e", "%2f", "%5c"))
        ):
            raise TicketingError("invalid", f"{self.name}: invalid request path")
        url = f"{self.base_url}{path}"
        parts = urlsplit(url)
        if (parts.scheme, parts.netloc) != (self._origin.scheme, self._origin.netloc):
            raise TicketingError("invalid", f"{self.name}: request outside the configured URL")
        if query:
            url += f"?{urlencode(dict(query))}"
        return url

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Mapping[str, Any] | None = None,
        query: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send a request to the system and return its JSON answer (see api.HttpClient)."""
        if method not in METHODS:
            raise TicketingError("invalid", f"{self.name}: method {method} not allowed")
        headers = {
            "Accept": "application/json",
            "User-Agent": f"security-review-mcp/{__version__}",
            **self.headers,
        }
        data = None
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self._url(path, query), data=data, headers=headers, method=method
        )
        try:
            with _opener(self.settings).open(request, timeout=HTTP_TIMEOUT) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            self._raise_http(exc)
        except (urllib.error.URLError, OSError) as exc:
            raise TicketingError(
                "unreachable", self.scrub(f"{self.name} unreachable: {exc}")[:MAX_ERROR_CHARS]
            ) from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise TicketingError("invalid", f"{self.name} answer too large")
        try:
            document = json.loads(raw)
        except ValueError:
            raise TicketingError("invalid", f"{self.name} sent invalid JSON") from None
        if not isinstance(document, dict):
            raise TicketingError("invalid", f"{self.name} sent an unexpected answer")
        return document

    def _raise_http(self, exc: urllib.error.HTTPError) -> None:
        """Raise the TicketingError of an HTTP error answer."""
        raw = exc.read(MAX_ERROR_BYTES) if exc.fp else b""
        try:
            messages = _error_messages(json.loads(raw))
        except ValueError:
            messages = []
        text = "".join(c if c.isprintable() else " " for c in "; ".join(messages))
        excerpt = self.scrub(text)[:MAX_ERROR_CHARS]
        detail = f"HTTP {exc.code}" + (f": {excerpt}" if excerpt else "")
        if exc.code in (401, 403):
            code, message = "auth", f"{self.name} refused the credentials ({detail})"
        elif 300 <= exc.code < 500:
            code, message = "refused", f"{self.name} refused the request ({detail})"
        else:
            code, message = "unreachable", f"{self.name} answered {detail}"
        raise TicketingError(code, message) from None
