"""Messages exchanged by the controller and the scan engines, and their shared secret.

``POST /engine/v1/scan`` (served by an engine, with the shared secret
SECREVIEW_SCAN_ENGINE_TOKEN): the controller sends the files it has bounded, with their language;
the engine answers the matches of each file, in the same order. The answer is validated by the
controller as well: an engine is an internal service, but its answer becomes findings.

Served by the controller to the engines, which read no database (see engines.enrollment,
web_api.engine_routes and engines.controller_client):

- ``POST /engine/v1/enroll`` (shared secret): the engine gives the URL where the controller
  sends it the scans, and gets its own OAuth client;
- ``POST /engine/v1/token`` (``client_credentials``): an access token of the ``engine`` role;
- ``GET /api/v1/engine/rules`` (access token): the active internal rules (``ETag``, ``304``);
- ``/api/v1/engine/opengrep-rules`` (access token): ``GET`` the SHA-256 of each OpenGrep rule
  (``ETag``, ``304``), ``POST`` the content of the rules the engine lacks;
- ``POST /api/v1/engine/heartbeat`` (access token): the free OpenGrep slots of the engine, every
  30 seconds, with its capacity and its counters; the controller sends the scans to the engines
  whose heartbeat is recent.
"""

import hashlib
import hmac
import json
import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from ..rules.opengrep_rule_store import MAX_RULE_CHARS, RULE_ID
from ..storage.models import Severity
from .local import MAX_MATCHES_PER_FILE

ENGINE_SCAN_PATH = "/engine/v1/scan"
# Enrollment of an engine (shared secret) and its access tokens (client_credentials)
ENGINE_ENROLL_PATH = "/engine/v1/enroll"
ENGINE_TOKEN_PATH = "/engine/v1/token"
# Rules of the controller read by the engines with their access token (see ENGINE_API_PREFIX)
ENGINE_RULES_PATH = "/api/v1/engine/rules"
ENGINE_OPENGREP_RULES_PATH = "/api/v1/engine/opengrep-rules"
# Heartbeat of an engine (access token): its free OpenGrep slots
ENGINE_HEARTBEAT_PATH = "/api/v1/engine/heartbeat"
# An engine that stops (access token, DELETE): the controller forgets it at once
ENGINE_SELF_PATH = "/api/v1/engine/self"
# Rules of one manifest or rule set, and OpenGrep rules asked for in one POST
MAX_ENGINE_RULES = 5000
RULE_FETCH_BATCH = 20
_SHA256 = re.compile(r"[0-9a-f]{64}")
# Bounds of the slots and of the counters an engine reports in its heartbeat
MAX_ENGINE_SLOTS = 1024
MAX_ENGINE_COUNTER = 10**12
# Bound of a path label (same as the scans of security-review-ci)
MAX_ENGINE_PATH_CHARS = 500


class EngineSource(BaseModel):
    """A file to scan."""

    path: str = Field(min_length=1, max_length=MAX_ENGINE_PATH_CHARS)
    language: str = Field(min_length=1, max_length=40)
    # Bounded by SECREVIEW_MAX_SCAN_FILE_CHARS (SECREVIEW_MAX_CONTENT_CHARS for a fragment)
    content: str


class EngineRequest(BaseModel):
    """Files of one scan: a codebase scan, or one ``fragment`` of scan_code."""

    fragment: bool = False
    # Bounded by SECREVIEW_MAX_SCAN_FILES once received
    sources: list[EngineSource]


class EngineMatch(BaseModel):
    """A match of a rule or of an OpenGrep rule (secrets masked in the excerpt)."""

    rule_id: str = Field(min_length=1, max_length=60)
    title: str
    severity: Severity
    cwe: str | None = Field(default=None, max_length=20)
    line: int = Field(ge=1)
    excerpt: str
    advice: str
    # OpenGrep only
    line_end: int | None = Field(default=None, ge=1)
    description: str | None = None


class EngineFile(BaseModel):
    """Matches of one file."""

    matches: list[EngineMatch] = Field(max_length=MAX_MATCHES_PER_FILE)
    suppressed: list[EngineMatch]
    truncated: bool


class EngineResponse(BaseModel):
    """Matches of each file, in the order of the request, and the engines that ran."""

    files: list[EngineFile]
    engines: list[Literal["rules", "opengrep"]] = Field(min_length=1, max_length=2)


class EnrollRequest(BaseModel):
    """An engine that enrolls: its name (host name) and version, shown to the administrators."""

    name: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=40)
    # Root URL where the controller sends the scans: an IP address (see engine_clients)
    url: str = Field(min_length=1, max_length=500)


class EngineHeartbeat(BaseModel):
    """Free OpenGrep slots of an engine (codebase scans, scan_code fragments), its capacity and
    what it did since it started (Scan engines page).

    The capacity and the counters default to 0: an older engine sends only its free slots.
    """

    free_codebase_slots: int = Field(ge=0, le=MAX_ENGINE_SLOTS)
    free_fragment_slots: int = Field(ge=0, le=MAX_ENGINE_SLOTS)
    # Slots of each pool (SECREVIEW_OPENGREP_MAX_CONCURRENT_SCANS / _FRAGMENT_SCANS of the engine)
    codebase_slots: int = Field(default=0, ge=0, le=MAX_ENGINE_SLOTS)
    fragment_slots: int = Field(default=0, ge=0, le=MAX_ENGINE_SLOTS)
    # Since the engine started (it enrolls again at each start): scans done, files scanned,
    # scans failed (OpenGrep could not run) and scans refused because every slot was taken
    codebase_scans: int = Field(default=0, ge=0, le=MAX_ENGINE_COUNTER)
    fragment_scans: int = Field(default=0, ge=0, le=MAX_ENGINE_COUNTER)
    scanned_files: int = Field(default=0, ge=0, le=MAX_ENGINE_COUNTER)
    # Files in scans currently running; unlike the counters above, this can decrease.
    processing_files: int = Field(default=0, ge=0, le=MAX_ENGINE_COUNTER)
    processing_codebase_scans: int = Field(default=0, ge=0, le=MAX_ENGINE_COUNTER)
    processing_fragment_scans: int = Field(default=0, ge=0, le=MAX_ENGINE_COUNTER)
    failed_scans: int = Field(default=0, ge=0, le=MAX_ENGINE_COUNTER)
    busy_refusals: int = Field(default=0, ge=0, le=MAX_ENGINE_COUNTER)


class EnrollResponse(BaseModel):
    """OAuth client of an enrolled engine; the secret is given once."""

    client_id: str
    client_secret: str


class TokenResponse(BaseModel):
    """Access token of an engine (RFC 6749 §5.1)."""

    access_token: str
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: int = Field(ge=1)


class EngineRule(BaseModel):
    """An active internal rule, as in a TOML pack (validated again by the engine)."""

    id: str = Field(min_length=1, max_length=60)
    title: str
    severity: Severity
    cwe: str = Field(default="", max_length=20)
    languages: list[str] = Field(min_length=1, max_length=50)
    pattern: str = Field(min_length=1)
    advice: str = ""
    ignore_case: bool = True


class EngineRuleSet(BaseModel):
    """The active internal rules of the controller (disabled rules left out)."""

    rules: list[EngineRule] = Field(max_length=MAX_ENGINE_RULES)


class RuleManifest(BaseModel):
    """SHA-256 of each OpenGrep rule of the controller, by rule id."""

    rules: dict[str, str] = Field(max_length=MAX_ENGINE_RULES)

    @field_validator("rules")
    @classmethod
    def _check_rules(cls, value: dict[str, str]) -> dict[str, str]:
        """Accept rule ids (they become file names) and SHA-256 digests only."""
        for rule_id, digest in value.items():
            if not RULE_ID.fullmatch(rule_id) or not _SHA256.fullmatch(digest):
                raise ValueError("Invalid OpenGrep rule manifest")
        return value


class RuleFetch(BaseModel):
    """OpenGrep rules an engine asks for."""

    ids: list[str] = Field(min_length=1, max_length=RULE_FETCH_BATCH)

    @field_validator("ids")
    @classmethod
    def _check_ids(cls, value: list[str]) -> list[str]:
        """Accept rule ids only."""
        if not all(RULE_ID.fullmatch(rule_id) for rule_id in value):
            raise ValueError("Invalid OpenGrep rule identifier")
        return value


class RuleContents(BaseModel):
    """Content of the OpenGrep rules asked for (a rule deleted meanwhile is missing)."""

    rules: dict[str, str] = Field(max_length=RULE_FETCH_BATCH)

    @field_validator("rules")
    @classmethod
    def _check_rules(cls, value: dict[str, str]) -> dict[str, str]:
        """Accept rule ids and contents within the bound of a rule file."""
        for rule_id, content in value.items():
            if not RULE_ID.fullmatch(rule_id) or len(content) > MAX_RULE_CHARS:
                raise ValueError("Invalid OpenGrep rule")
        return value


def rule_digest(content: str) -> str:
    """SHA-256 of an OpenGrep rule file."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def manifest_digest(manifest: dict[str, str] | list) -> str:
    """Digest of a whole manifest or rule set: the ``ETag`` of the controller, the snapshot of
    an engine."""
    return hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()


class EngineAuth:
    """Refuse (401) every request but ``/healthz`` without the shared secret of the engines,
    before its body is read (SECREVIEW_SCAN_ENGINE_TOKEN, compared by its SHA-256 digest in
    constant time): the scans on an engine, the enrollments on the controller."""

    def __init__(self, app: ASGIApp, token: str, health_path: str = "/healthz") -> None:
        self.app = app
        self.digest = hashlib.sha256(token.encode()).digest()
        self.health_path = health_path

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") == self.health_path:
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
