"""MkDocs hooks of the documentation (declared in ``mkdocs.yml``).

``{{ release_tag }}`` in a page becomes the tag of the version of ``pyproject.toml``
(``v3.0.0``) and ``{{ release_version }}`` the version itself (``3.0.0``, for a pinned package):
the copied commands fetch the files and the package of the release they document, and follow
every new version without editing the pages. A placeholder preceded by a backslash stays as
the placeholder itself, for the pages that document it.
"""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLACEHOLDER = re.compile(r"(\\?)\{\{ release_(tag|version) \}\}")


def _release_version() -> str:
    """Return the version declared in ``pyproject.toml``."""
    with (ROOT / "pyproject.toml").open("rb") as file:
        return tomllib.load(file)["project"]["version"]


RELEASE_VERSION = _release_version()
VALUES = {"tag": "v" + RELEASE_VERSION, "version": RELEASE_VERSION}


def on_page_markdown(markdown: str, **kwargs: object) -> str:
    """Replace the release placeholders in the Markdown of each page."""
    return PLACEHOLDER.sub(
        lambda match: match.group(0)[1:] if match.group(1) else VALUES[match.group(2)], markdown
    )
