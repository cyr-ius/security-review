"""Messages exchanged by the controller and the scan engines (``POST /engine/v1/scan``).

The controller sends the files it has bounded, with their language; the engine answers the
matches of each file, in the same order. The answer is validated by the controller as well:
an engine is an internal service, but its answer becomes findings.
"""

from typing import Literal

from pydantic import BaseModel, Field

from ..storage.models import Severity
from .local import MAX_MATCHES_PER_FILE

ENGINE_SCAN_PATH = "/engine/v1/scan"
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
