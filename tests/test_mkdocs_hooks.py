import importlib.util
import re
import tomllib
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_release_placeholders_become_the_tag_and_the_version():
    # The copied commands of the docs fetch the manifests of the documented release
    spec = importlib.util.spec_from_file_location("mkdocs_hooks", ROOT / "scripts/mkdocs_hooks.py")
    hooks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hooks)
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]
    page = (
        "blob/{{ release_tag }}/examples, security-review=={{ release_version }} "
        "and `\\{{ release_tag }}`"
    )
    assert hooks.on_page_markdown(page) == (
        f"blob/v{version}/examples, security-review=={version} and `{{{{ release_tag }}}}`"
    )


def _anchor(title: str) -> str:
    """Anchor of a Markdown heading, as the toc extension of MkDocs makes it (ASCII only)."""
    text = re.sub(r"`|\*\*|\[([^\]]*)\]\([^)]*\)", r"\1", title)
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    text = re.sub(r"[^\w\s-]", "", text).strip().lower()
    return re.sub(r"[-\s]+", "-", text)


def test_the_help_links_of_the_web_interface_reach_a_heading_in_both_languages():
    # A renamed heading silently breaks the help link (?) of a page of the web interface
    links = (ROOT / "web/src/app/core/constants/doc-links.ts").read_text(encoding="utf-8")
    entries = re.findall(
        r"(\w+): \{\s*path: '([^']+)',?(?:\s*anchor: \{\s*en: '([^']+)',\s*fr: '([^']+)',?\s*\})?",
        links[links.index("export const DOC_LINKS") :],
    )
    assert len(entries) > 10
    for topic, path, *anchors in entries:
        for suffix, anchor in zip((".md", ".fr.md"), anchors, strict=True):
            page = ROOT / "docs" / (path.rstrip("/") + suffix)
            if not page.exists():  # a section: its index page
                page = ROOT / "docs" / path / ("index" + suffix)
            assert page.exists(), f"{topic}: {page} is missing"
            headings = re.findall(r"^#+ (.+)$", page.read_text(encoding="utf-8"), re.MULTILINE)
            if anchor:
                assert anchor in {_anchor(h) for h in headings}, f"{topic}: #{anchor} in {page}"
