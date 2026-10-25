"""MkDocs hooks of the documentation (declared in ``mkdocs.yml``).

``{{ release_tag }}`` in a page becomes the tag of the version of ``pyproject.toml``
(``v3.0.0``): the copied commands fetch the files of the release they document, and the links
follow every new version without editing the pages. ``\\{{ release_tag }}`` stays as the
placeholder itself, for the pages that document it.
"""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLACEHOLDER = re.compile(r"(\\?)\{\{ release_tag \}\}")


def _release_tag() -> str:
    """Return the git tag of the version declared in ``pyproject.toml``."""
    with (ROOT / "pyproject.toml").open("rb") as file:
        return "v" + tomllib.load(file)["project"]["version"]


RELEASE_TAG = _release_tag()


def on_page_markdown(markdown: str, **kwargs: object) -> str:
    """Replace the release placeholder in the Markdown of each page."""
    return PLACEHOLDER.sub(
        lambda match: match.group(0)[1:] if match.group(1) else RELEASE_TAG, markdown
    )
