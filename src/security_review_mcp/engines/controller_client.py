"""Client of the controller used by a scan engine: enrollment, access token, bounded requests.

A scan engine reads no database. At its start it enrolls with the controller at
SECREVIEW_CONTROLLER_URL with the shared secret SECREVIEW_SCAN_ENGINE_TOKEN (``POST
/engine/v1/enroll``), giving the URL where the controller sends it the scans, and gets its own
OAuth client, kept in memory only. It exchanges it for an
access token (``client_credentials``, ``POST /engine/v1/token``), renewed before it expires,
with which it reads the rules through the REST API of the controller (``/api/v1/engine/``). A
background thread sends a heartbeat every HEARTBEAT_SECONDS with its free OpenGrep slots: the
controller sends the scans to the engines whose heartbeat is recent.

When an administrator revokes the engine, the controller refuses its client (``invalid_client``):
the engine does not enroll again by itself, its scans fail until it restarts. To shut every
engine out, change the shared secret.

The only outgoing connection of an engine: to SECREVIEW_CONTROLLER_URL only, without proxy (the
controller is an internal service) nor redirect, with a time limit and bounded answers. The
secrets and tokens are never logged.
"""

import base64
import http.client
import json
import logging
import socket
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from urllib.parse import quote, urlencode

from pydantic import BaseModel, ValidationError

from .. import __version__
from .opengrep import OpenGrepError
from .protocol import (
    ENGINE_ENROLL_PATH,
    ENGINE_HEARTBEAT_PATH,
    ENGINE_TOKEN_PATH,
    EngineHeartbeat,
    EnrollRequest,
    EnrollResponse,
    TokenResponse,
)

logger = logging.getLogger("security_review_mcp.engines")

# Time limit of each request to the controller: the scans wait for the synchronization
TIMEOUT_SECONDS = 30
# Bound of the answers of the enrollment and of the token endpoint
MAX_AUTH_RESPONSE_BYTES = 64 * 1024
# The token is renewed once this share of its validity has passed
RENEW_AT = 0.8
# How often the engine sends its heartbeat (the controller stops sending it scans after 90 s)
HEARTBEAT_SECONDS = 30
# While it scans, and at most this often when scans start or finish (a burst sends one heartbeat)
ACTIVE_HEARTBEAT_SECONDS = 5
MIN_HEARTBEAT_SECONDS = 1.0


class ControllerError(OpenGrepError):
    """The controller could not be reached or refused the engine (no secret in the message).

    An OpenGrepError: the scan engine answers 500 and the controller treats it as unavailable.
    """


class RevokedError(ControllerError):
    """The controller refuses the client of the engine: it was revoked (restart to enroll)."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: the secrets are only sent to the configured URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        return None


# No proxy (the controller is an internal service) and no redirect
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


class ControllerClient:
    """Enrollment and access token of this engine, and its requests to the controller."""

    def __init__(
        self,
        controller_url: str,
        shared_secret: str,
        url: str,
        name: str | None = None,
        status: Callable[[], EngineHeartbeat] | None = None,
    ) -> None:
        self.controller_url = controller_url
        self.shared_secret = shared_secret
        # Where the controller sends the scans to this engine
        self.url = url
        # Free slots sent with each heartbeat
        self.status = status or (
            lambda: EngineHeartbeat(free_codebase_slots=0, free_fragment_slots=0)
        )
        self.name = (name or socket.gethostname() or "scan-engine")[:200]
        # Guards the credentials and the token below
        self._lock = threading.Lock()
        self._client: EnrollResponse | None = None
        self._token: str | None = None
        self._renew_at = 0.0
        self._revoked = False
        self._stop = threading.Event()
        self._activity_condition = threading.Condition()
        self._activity_generation = 0
        self._active = False
        self._thread: threading.Thread | None = None

    @property
    def revoked(self) -> bool:
        """True once the controller refused the client of the engine."""
        return self._revoked

    @property
    def client_id(self) -> str | None:
        """Client id of the engine once enrolled."""
        return self._client.client_id if self._client else None

    def access_token(self, force: bool = False) -> str:
        """A valid access token, enrolling and renewing it as needed.

        Raises:
            RevokedError: If the engine was revoked.
            ControllerError: If the controller cannot be reached or refuses the engine.
        """
        with self._lock:
            if self._revoked:
                raise RevokedError("The scan engine was revoked: restart it to enroll again")
            if self._client is None:
                self._client = self._enroll()
            if force or self._token is None or time.monotonic() >= self._renew_at:
                answer = self._new_token(self._client)
                self._token = answer.access_token
                self._renew_at = time.monotonic() + answer.expires_in * RENEW_AT
            return self._token

    def request(
        self, method: str, path: str, body: bytes | None, headers: dict[str, str], limit: int
    ) -> bytes | None:
        """Send an authenticated request to the REST API of the controller and return the body
        of the answer (at most ``limit`` bytes); None for a ``304``. A ``401`` renews the
        token once (the controller may have replaced it).

        Raises:
            ControllerError: If the controller cannot be reached, refuses the request or sends
                an answer above ``limit``.
        """
        for attempt in range(2):
            token = self.access_token(force=attempt > 0)
            status, raw = self._send(
                method, path, body, {**headers, "Authorization": f"Bearer {token}"}, limit
            )
            if status != 401:
                break
        if status == 304:
            return None
        if not 200 <= status < 300:
            raise ControllerError(f"the Controller server answered HTTP {status}")
        return raw

    def beat(self) -> None:
        """Send the heartbeat of the engine with its free slots.

        Raises:
            ControllerError: If the controller cannot be reached or refuses the engine.
        """
        body = self.status().model_dump_json().encode()
        headers = {"Content-Type": "application/json"}
        self.request("POST", ENGINE_HEARTBEAT_PATH, body, headers, MAX_AUTH_RESPONSE_BYTES)

    def start(self) -> None:
        """Enroll now (a failure is retried at the first scan) and keep the token fresh in the
        background."""
        try:
            self.beat()
            logger.info("Enrolled with the Controller server as %s (%s)", self.client_id, self.url)
        except ControllerError as exc:
            logger.warning("Enrollment with the Controller server failed: %s; retrying", exc)
        self._thread = threading.Thread(
            target=self._heartbeat, name="secreview-engine-token", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the background renewal."""
        self._stop.set()
        with self._activity_condition:
            self._activity_condition.notify_all()

    def notify_activity_change(self, active: bool) -> None:
        """Wake the heartbeat thread after a scan starts or finishes."""
        with self._activity_condition:
            self._active = active
            self._activity_generation += 1
            self._activity_condition.notify_all()

    def _heartbeat(self) -> None:
        """Send the heartbeat (renewing the token as needed) until stopped or revoked."""
        generation = 0
        last_beat = time.monotonic()
        while not self._stop.is_set():
            with self._activity_condition:
                if self._activity_generation == generation:
                    active = self._active
                    delay = ACTIVE_HEARTBEAT_SECONDS if active else HEARTBEAT_SECONDS
                    self._activity_condition.wait(delay)
            # Scans starting and finishing in a burst share one heartbeat
            if self._stop.wait(max(0.0, last_beat + MIN_HEARTBEAT_SECONDS - time.monotonic())):
                return
            with self._activity_condition:
                generation = self._activity_generation
            last_beat = time.monotonic()
            try:
                self.beat()
            except RevokedError:
                return
            except ControllerError as exc:
                logger.warning("Could not send the heartbeat of the scan engine: %s", exc)

    def _enroll(self) -> EnrollResponse:
        """Enroll with the shared secret."""
        body = (
            EnrollRequest(name=self.name, version=__version__[:40], url=self.url)
            .model_dump_json()
            .encode()
        )
        headers = {
            "Authorization": f"Bearer {self.shared_secret}",
            "Content-Type": "application/json",
        }
        status, raw = self._send("POST", ENGINE_ENROLL_PATH, body, headers, MAX_AUTH_RESPONSE_BYTES)
        if status == 401:
            raise ControllerError(
                "the Controller server refused the enrollment: check SECREVIEW_SCAN_ENGINE_TOKEN"
            )
        if status == 422:
            raise ControllerError(
                "the Controller server refused the URL of the engine: check "
                "SECREVIEW_SCAN_ENGINE_ADVERTISE_URL and SECREVIEW_SCAN_ENGINE_NETWORKS"
            )
        if status != 201:
            raise ControllerError(f"the Controller server answered HTTP {status} to the enrollment")
        return _parse(raw, EnrollResponse)

    def _new_token(self, client: EnrollResponse) -> TokenResponse:
        """Exchange the client of the engine for an access token (client_credentials)."""
        basic = base64.b64encode(
            f"{quote(client.client_id, safe='')}:{quote(client.client_secret, safe='')}".encode()
        ).decode()
        headers = {
            "Authorization": f"Basic {basic}",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        body = urlencode({"grant_type": "client_credentials"}).encode()
        status, raw = self._send("POST", ENGINE_TOKEN_PATH, body, headers, MAX_AUTH_RESPONSE_BYTES)
        if status in (400, 401) and _oauth_error(raw) == "invalid_client":
            self._revoked = True
            self._client, self._token = None, None
            logger.error(
                "The Controller server revoked this scan engine: restart it to enroll again"
            )
            raise RevokedError("The scan engine was revoked: restart it to enroll again")
        if status != 200:
            raise ControllerError(f"the Controller server answered HTTP {status} to the token")
        return _parse(raw, TokenResponse)

    def _send(
        self, method: str, path: str, body: bytes | None, headers: dict[str, str], limit: int
    ) -> tuple[int, bytes]:
        """Send one request; the status and the body of the answer (an error status included).

        Raises:
            ControllerError: If the controller cannot be reached or the answer is too large.
        """
        request = urllib.request.Request(
            f"{self.controller_url}{path}",
            data=body,
            method=method,
            headers={
                **headers,
                "Accept": "application/json",
                "User-Agent": f"secreview-scan-engine/{__version__}",
            },
        )
        try:
            with _OPENER.open(request, timeout=TIMEOUT_SECONDS) as response:
                status, raw = response.status, response.read(limit + 1)
        except urllib.error.HTTPError as exc:
            try:
                status, raw = exc.code, exc.read(MAX_AUTH_RESPONSE_BYTES)
            except OSError, http.client.HTTPException:
                status, raw = exc.code, b""
            finally:
                exc.close()
        except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
            # The reason names the error, never a secret
            raise ControllerError(
                f"the Controller server cannot be reached ({type(exc).__name__})"
            ) from None
        if len(raw) > limit:
            raise ControllerError("the answer of the Controller server is too large")
        return status, raw


def _parse[T: BaseModel](raw: bytes, model: type[T]) -> T:
    """Validate an answer of the controller.

    Raises:
        ControllerError: If the answer is not the expected JSON.
    """
    try:
        return model.model_validate_json(raw)
    except ValidationError:
        raise ControllerError("the Controller server sent an unexpected answer") from None


def _oauth_error(raw: bytes) -> str | None:
    """The ``error`` of an OAuth error answer, None when absent."""
    try:
        error = json.loads(raw).get("error")
    except ValueError, AttributeError:
        return None
    return error if isinstance(error, str) else None
