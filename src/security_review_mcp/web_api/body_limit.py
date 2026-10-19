"""Bound of the request bodies of the controller (413 above), before FastAPI parses them.

Every route takes a small JSON body (MAX_BODY_BYTES), including the public ones (login, OIDC),
except the pack imports, which carry a TOML file, and the pipeline scans, which carry the files
of a whole codebase (SECREVIEW_MAX_SCAN_REQUEST_MB). http_server.BodyLimit applies these bounds
inside the bearer middleware, so a request to a protected route without a valid token is
refused before its body is read.
"""

from .. import standards
from ..config import get_settings

# Body of any route of the controller, unless a prefix below gives another bound
MAX_BODY_BYTES = 512 * 1024
PACK_PREFIX = "/api/v1/packs/"
# The TOML text of a pack is escaped in a JSON string (quotes, backslashes, new lines)
MAX_PACK_BODY_BYTES = 2 * standards.MAX_PACK_BYTES
SCAN_PREFIX = "/api/v1/ci/scan/"


def body_limit(path: str) -> tuple[int, str]:
    """Bound (in bytes) of the body of a request to ``path``, and the hint of its 413 answer."""
    if path.startswith(SCAN_PREFIX):
        limit = get_settings().max_scan_request_mb * 1024 * 1024
        return limit, "SECREVIEW_MAX_SCAN_REQUEST_MB): exclude files or raise the limit"
    if path.startswith(PACK_PREFIX):
        return MAX_PACK_BODY_BYTES, "TOML pack)"
    return MAX_BODY_BYTES, "JSON request)"
