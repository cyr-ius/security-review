"""Agent Skills served over MCP (SEP-2640): the standards and checklists as skills.

Each enabled development standard and each checklist domain is exposed as a one-file skill
(its ``SKILL.md``) under the ``skill://`` scheme:

- ``skill://secreview/standards/<name>/SKILL.md``
- ``skill://secreview/checklists/<name>/SKILL.md``

The content lives in the database and an administrator can change it at any time, so every
skill is rendered on each call, from the current rows. Its digest is computed on the same
bytes as the ones ``resources/read`` returns: a change made between a listing and a read shows
up as a digest mismatch, which makes the host fetch the entry again (``skills/get``) and ask
the user to approve the new content. The skills are therefore never marked ``"dynamic"``.

This module only builds the entries and the file contents; the ``skills/list``,
``skills/get`` methods and the ``skill://`` resource are wired in ``server.py``.
"""

import hashlib
import json
import logging
import re

from . import standards
from .config import get_settings
from .reports.services import NotFoundError
from .rules import registry
from .rules.rules_loader import ALL_LANGUAGES_DOMAIN

logger = logging.getLogger("security_review_mcp")

SCHEME = "skill://"
# Organizational prefix of the skills of this server (first segment of every skill path)
PREFIX = "secreview"
KINDS = ("standards", "checklists")
# Agent Skills limits: name and description of the frontmatter
MAX_NAME_CHARS = 64
MAX_DESCRIPTION_CHARS = 1024
# SEP-2640 limit on the total size of a skill's files
MAX_SKILL_BYTES = 16 * 1024 * 1024
# Longest skill URI accepted from a client (prefix, kind, name and file name)
MAX_URI_CHARS = 200
# Skill name of the checklist items that apply to every language (domain "*")
ALL_LANGUAGES_NAME = "all-languages"

_URI_RE = re.compile(
    rf"skill://{PREFIX}/(?P<kind>standards|checklists)/(?P<name>[a-z0-9-]{{1,{MAX_NAME_CHARS}}})/SKILL\.md"
)
# Valid Agent Skills name: lowercase letters, digits and single hyphens, not at either end
_NAME_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_WHITESPACE_RE = re.compile(r"\s+")


# ── Names and URIs ───────────────────────────────────────────────────────────


def skill_name(key: str) -> str | None:
    """Turn a standard slug or a checklist domain into an Agent Skills name.

    ``node.js`` gives ``node-js``, ``c++`` gives ``c-plus-plus``, ``c#`` gives ``c-sharp`` and
    the domain ``*`` gives ``all-languages``. Returns ``None`` when no valid name comes out.
    """
    if key == ALL_LANGUAGES_DOMAIN:
        return ALL_LANGUAGES_NAME
    text = key.lower().replace("+", "-plus-").replace("#", "-sharp-")
    name = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return name if len(name) <= MAX_NAME_CHARS and _NAME_RE.fullmatch(name) else None


def skill_uri(kind: str, name: str) -> str:
    """Return the URI of the ``SKILL.md`` of a skill."""
    return f"{SCHEME}{PREFIX}/{kind}/{name}/SKILL.md"


def _catalog() -> dict[str, tuple[str, str]]:
    """Map every skill URI to its kind and key (standard slug or checklist domain).

    Two keys that give the same name (``node.js`` and ``node-js``) are both left out: a skill
    name must lead to one content only.
    """
    sources = {
        "standards": [item["slug"] for item in standards.list_standards()],
        "checklists": list(registry.domains()),
    }
    catalog: dict[str, tuple[str, str]] = {}
    for kind, keys in sources.items():
        by_name: dict[str, list[str]] = {}
        for key in keys:
            if (name := skill_name(key)) is not None:
                by_name.setdefault(name, []).append(key)
        for name, same in by_name.items():
            if len(same) == 1:
                catalog[skill_uri(kind, name)] = (kind, same[0])
            else:
                logger.debug("Skill name %s left out: several %s give it", name, kind)
    return dict(sorted(catalog.items()))


def _resolve(uri: str) -> tuple[str, str, str]:
    """Return the kind, name and key of a skill URI.

    Raises:
        NotFoundError: If the URI is not the ``SKILL.md`` of a skill served here.
    """
    match = _URI_RE.fullmatch(uri) if len(uri) <= MAX_URI_CHARS else None
    found = _catalog().get(uri) if match else None
    if match is None or found is None:
        raise NotFoundError(f"Unknown skill {uri[:MAX_URI_CHARS]!r}")
    return found[0], match["name"], found[1]


# ── Rendering ────────────────────────────────────────────────────────────────


def _one_line(text: str, limit: int) -> str:
    """Return a text on one printable line, cut to ``limit`` characters.

    Keeps the frontmatter valid YAML whatever an administrator typed, and identical once
    parsed to the ``frontmatter`` object of the entry.
    """
    printable = "".join(char if char.isprintable() else " " for char in text)
    return _WHITESPACE_RE.sub(" ", printable).strip()[:limit].strip()


def _frontmatter(kind: str, name: str, key: str) -> tuple[dict, str]:
    """Return the frontmatter of a skill and the Markdown body of its ``SKILL.md``."""
    if kind == "standards":
        standard = standards.get_standard(key)
        scope = ", ".join(standard["technologies"]) or standard["slug"]
        about = standard["description"] or standard["title"]
        description = f"Development standard: {about} Applies to: {scope}."
        if standard["file_patterns"]:
            description += f" Files: {', '.join(standard['file_patterns'])}."
        description += " Read it before writing code in these technologies."
        body = standards.render_standard_markdown(standard)
    else:
        items = registry.get_checklist(key)
        label = "every language" if key == ALL_LANGUAGES_DOMAIN else f"the {key} domain"
        description = (
            f"Security review checklist for {label}: {len(items)} verification points. "
            "Walk through them during a security review and give each one an outcome in the "
            "checklist_results of save_security_report."
        )
        body = registry.render_checklist_markdown(key)
    frontmatter = {
        "name": name,
        "description": _one_line(description, MAX_DESCRIPTION_CHARS),
        "metadata": {"secreview-kind": kind, "secreview-key": key},
    }
    return frontmatter, body


def _render_yaml(frontmatter: dict) -> str:
    """Render the frontmatter as YAML, every scalar as a JSON (double-quoted YAML) string."""
    lines = []
    for field, value in frontmatter.items():
        if isinstance(value, dict):
            lines.append(f"{field}:")
            lines += [
                f"  {json.dumps(key)}: {json.dumps(item, ensure_ascii=False)}"
                for key, item in value.items()
            ]
        else:
            lines.append(f"{field}: {json.dumps(value, ensure_ascii=False)}")
    return "\n".join(lines)


def _render(uri: str) -> tuple[dict, bytes]:
    """Return the frontmatter of a skill and the bytes of its ``SKILL.md``.

    Raises:
        NotFoundError: If the URI is not a skill served here, or the skill is larger than the
            SEP-2640 limit (no conforming host would have to load it).
    """
    kind, name, key = _resolve(uri)
    frontmatter, body = _frontmatter(kind, name, key)
    content = f"---\n{_render_yaml(frontmatter)}\n---\n\n{body}\n".encode()
    if len(content) > MAX_SKILL_BYTES:
        logger.warning("Skill %s not served: larger than %d bytes", uri, MAX_SKILL_BYTES)
        raise NotFoundError(f"Skill {uri!r} is too large")
    return frontmatter, content


def _entry(uri: str, frontmatter: dict, content: bytes) -> dict:
    """Return the SEP-2640 entry of a one-file skill."""
    digest = hashlib.sha256(content).hexdigest()
    return {
        "uri": uri,
        "frontmatter": frontmatter,
        "resources": [{"uri": uri, "digest": f"sha256:{digest}", "size": len(content)}],
    }


# ── Public API ───────────────────────────────────────────────────────────────


def read_skill_file(uri: str) -> str:
    """Return the content of a skill file (``resources/read``).

    Raises:
        NotFoundError: If the URI is not a file of a skill served here.
    """
    return _render(uri)[1].decode()


def get_skill(uri: str) -> dict:
    """Return the entry of one skill (``skills/get``), listed or not.

    Raises:
        NotFoundError: If the URI is not the ``SKILL.md`` of a skill served here.
    """
    frontmatter, content = _render(uri)
    return _entry(uri, frontmatter, content)


def list_skills(
    cursor: str | None = None, limit: int | None = None
) -> tuple[list[dict], str | None]:
    """Return a page of skill entries (``skills/list``) and the cursor of the next page.

    The cursor is the position of the next entry. A skill that can no longer be rendered (too
    large, or removed since the catalog was read) is left out of the page.

    Raises:
        ValueError: If the cursor is not one this function returned.
    """
    uris = list(_catalog())
    if cursor is not None and not (
        len(cursor) <= 10 and cursor.isascii() and cursor.isdigit() and int(cursor) <= len(uris)
    ):
        raise ValueError("Invalid cursor")
    start = int(cursor or 0)
    size = min(limit or get_settings().max_list_limit, get_settings().max_list_limit)
    page = []
    for uri in uris[start : start + size]:
        try:
            frontmatter, content = _render(uri)
        except NotFoundError:
            continue
        page.append(_entry(uri, frontmatter, content))
    end = start + size
    return page, (str(end) if end < len(uris) else None)
