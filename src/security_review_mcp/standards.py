"""Development standards: per-technology guidance served to the developer's AI.

Administrators write the standards in the web interface (Markdown content, the technologies
it applies to and the file name patterns that reveal them). The MCP server serves them with
the ``development-standards`` prompt, the ``list_development_standards`` and
``get_development_standards`` tools and the ``standards://`` resources: the host AI receives
the conventions of the technologies it works on before it writes code.

The standards are read from the database on each call (no cache): a change made in the web
interface applies at once to every MCP server instance sharing the database.
"""

import fnmatch
import json
import re
import tomllib
from collections.abc import Iterable

import tomlkit
from sqlalchemy.exc import IntegrityError
from sqlmodel import col, func, select

from .config import get_settings
from .services import NotFoundError
from .storage.database import session_scope
from .storage.models import DevStandard, utcnow

MAX_STANDARDS = 200
MAX_TITLE_CHARS = 200
MAX_DESCRIPTION_CHARS = 500
MAX_CONTENT_CHARS = 50_000
MAX_KEYWORDS = 32
MAX_KEYWORD_CHARS = 50
MAX_PATTERN_CHARS = 100
# Largest standards pack accepted by import_pack (TOML exchange format of the web interface)
MAX_PACK_BYTES = 4 * 1024 * 1024
# Fields of a standard in a pack, in the order they are exported
PACK_FIELDS = ("slug", "title", "description", "technologies", "file_patterns", "enabled")
# Bounds of a lookup by the MCP tools and prompt (with SECREVIEW_MAX_CONTENT_CHARS in total)
MAX_QUERY_TECHNOLOGIES = 50
MAX_QUERY_FILES = 500
MAX_QUERY_FILE_CHARS = 500

# Fields kept from the MCP clients and from the non-administrators of the web interface
AUDIT_FIELDS = frozenset({"updated_by", "created_at", "updated_at"})

# Lowercase id used in URLs and resource URIs (python, angular, node.js, c++...)
SLUG_RE = re.compile(r"[a-z0-9][a-z0-9._+-]{0,49}")
# A technology name or alias (spring boot, c#, node.js...)
TECHNOLOGY_RE = re.compile(r"[a-z0-9][a-z0-9 ._+#/-]{0,49}")
# A file name glob (*.py, pyproject.toml, src/**/*.ts, Dockerfile*, [Mm]akefile)
PATTERN_RE = re.compile(r"[\w*?.\-/\[\]!]{1,100}")


# ── Validation ───────────────────────────────────────────────────────────────


def _text(entry: dict, key: str, limit: int, required: bool = True) -> str:
    """Return a stripped text field, refusing a missing or too long value."""
    value = entry.get(key, "")
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string")
    value = value.strip()
    if required and not value:
        raise ValueError(f"{key} is required")
    if len(value) > limit:
        raise ValueError(f"{key} is too long ({len(value)} chars, limit {limit})")
    return value


def _keywords(values: object, key: str, pattern: re.Pattern[str], lower: bool) -> list[str]:
    """Validate a list of technologies or file patterns; return it without duplicates."""
    if values is None:
        return []
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        raise ValueError(f"{key} must be a list of strings")
    if len(values) > MAX_KEYWORDS:
        raise ValueError(f"{key}: at most {MAX_KEYWORDS} entries")
    result = []
    for raw in values:
        item = " ".join(raw.split())
        item = item.lower() if lower else item
        if not item:
            continue
        if not pattern.fullmatch(item):
            raise ValueError(f"{key}: invalid entry {item[:60]!r}")
        result.append(item)
    return list(dict.fromkeys(result))


def validate_slug(slug: str) -> str:
    """Return a valid standard slug or raise ValueError."""
    if not isinstance(slug, str) or not SLUG_RE.fullmatch(slug):
        raise ValueError(
            "slug must be 1 to 50 lowercase letters, digits or . _ + - (for example 'python')"
        )
    return slug


def normalize(entry: dict) -> dict:
    """Validate a standard sent by an administrator; return its normalized fields.

    Raises:
        ValueError: Describing the first invalid field.
    """
    enabled = entry.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError("enabled must be a boolean")
    return {
        "slug": validate_slug(entry.get("slug", "")),
        "title": _text(entry, "title", MAX_TITLE_CHARS),
        "description": _text(entry, "description", MAX_DESCRIPTION_CHARS, required=False),
        "technologies": _keywords(
            entry.get("technologies"), "technologies", TECHNOLOGY_RE, lower=True
        ),
        "file_patterns": _keywords(
            entry.get("file_patterns"), "file_patterns", PATTERN_RE, lower=False
        ),
        "content": _text(entry, "content", MAX_CONTENT_CHARS),
        "enabled": enabled,
    }


# ── Reading ──────────────────────────────────────────────────────────────────


def _summary(row: DevStandard) -> dict:
    """Return the fields of a standard without its content (for listings)."""
    return {
        "slug": row.slug,
        "title": row.title,
        "description": row.description,
        "technologies": json.loads(row.technologies),
        "file_patterns": json.loads(row.file_patterns),
        "enabled": row.enabled,
        "content_chars": len(row.content),
        "updated_at": row.updated_at.isoformat(),
        "updated_by": row.updated_by,
    }


def _full(row: DevStandard) -> dict:
    """Return every field of a standard, content included."""
    return _summary(row) | {"content": row.content, "created_at": row.created_at.isoformat()}


def list_standards(include_disabled: bool = False) -> list[dict]:
    """Return the standards without their content, ordered by slug."""
    with session_scope() as session:
        query = select(DevStandard).order_by(col(DevStandard.slug))
        if not include_disabled:
            query = query.where(col(DevStandard.enabled).is_(True))
        return [_summary(row) for row in session.exec(query).all()]


def get_standard(slug: str, include_disabled: bool = False) -> dict:
    """Return one standard with its content.

    Raises:
        NotFoundError: If no standard has this slug (or it is disabled and not requested).
    """
    with session_scope() as session:
        row = session.exec(select(DevStandard).where(col(DevStandard.slug) == slug)).first()
        if row is None or not (row.enabled or include_disabled):
            raise NotFoundError(f"Development standard {slug[:60]!r} not found")
        return _full(row)


def _clean_query(values: Iterable[str], limit: int, item_chars: int, key: str) -> list[str]:
    """Bound and normalize the technologies or file names given by the host."""
    items = [value.strip() for value in values if value and value.strip()]
    if len(items) > limit:
        raise ValueError(f"{key}: at most {limit} entries")
    for item in items:
        if len(item) > item_chars:
            raise ValueError(f"{key}: entry too long ({len(item)} chars, limit {item_chars})")
    return list(dict.fromkeys(items))


def _matches_file(patterns: list[str], path: str) -> bool:
    """Tell whether a file matches one of the globs (lowercase).

    A glob with a ``/`` is compared with the whole path, any other one with the base name only.
    """
    path = path.replace("\\", "/").lower()
    name = path.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatchcase(path if "/" in glob else name, glob) for glob in patterns)


def find_standards(technologies: Iterable[str] = (), files: Iterable[str] = ()) -> dict:
    """Select the enabled standards for technologies and file names given by the host.

    A standard matches a technology equal to its slug or to one of its technologies, or a file
    whose path or base name matches one of its file patterns. Returns the matched standards
    (with content), the technologies no standard covers and the available slugs.

    Raises:
        ValueError: If the lookup exceeds its bounds.
    """
    wanted = _clean_query(technologies, MAX_QUERY_TECHNOLOGIES, MAX_KEYWORD_CHARS, "technologies")
    paths = _clean_query(files, MAX_QUERY_FILES, MAX_QUERY_FILE_CHARS, "files")
    limit = get_settings().max_content_chars
    total = sum(map(len, wanted)) + sum(map(len, paths))
    if total > limit:
        raise ValueError(f"Lookup too large ({total} chars); the limit is {limit}")
    lowered = {item.lower(): item for item in wanted}

    matched: list[dict] = []
    covered: set[str] = set()
    with session_scope() as session:
        rows = session.exec(
            select(DevStandard)
            .where(col(DevStandard.enabled).is_(True))
            .order_by(col(DevStandard.slug))
        ).all()
        for row in rows:
            names = {row.slug, *json.loads(row.technologies)}
            hits = names & lowered.keys()
            patterns = [glob.lower() for glob in json.loads(row.file_patterns)]
            files_hit = [path for path in paths if _matches_file(patterns, path)]
            if hits or files_hit:
                covered |= hits
                # Served to MCP clients: no audit fields (who changed the standard, and when)
                entry = {key: value for key, value in _full(row).items() if key not in AUDIT_FIELDS}
                matched.append(entry | {"matched_files": files_hit[:20]})
        available = [row.slug for row in rows]
    return {
        "standards": matched,
        "uncovered_technologies": [lowered[key] for key in lowered if key not in covered],
        "available": available,
    }


# ── Rendering ────────────────────────────────────────────────────────────────


def render_standard_markdown(standard: dict) -> str:
    """Render one standard (with content) as a Markdown section."""
    scope = ", ".join(standard["technologies"]) or standard["slug"]
    lines = [f"## {standard['title']} (`{standard['slug']}`)", f"_Applies to: {scope}_"]
    if standard["file_patterns"]:
        lines[-1] += f" · _files: {', '.join(standard['file_patterns'])}_"
    if standard["description"]:
        lines.append(standard["description"])
    lines.append(standard["content"])
    return "\n\n".join(lines)


def render_catalog_markdown(summaries: list[dict]) -> str:
    """Render the list of the available standards (without their content)."""
    if not summaries:
        return "# Development standards\n\nNo development standard is defined on this server."
    lines = [
        "# Development standards",
        "",
        "Read one with `get_development_standards` or the resource `standard://<slug>`.",
        "",
    ]
    for item in summaries:
        scope = ", ".join(item["technologies"]) or item["slug"]
        line = f"- `{item['slug']}`: **{item['title']}** ({scope})"
        if item["description"]:
            line += f": {item['description']}"
        lines.append(line)
    return "\n".join(lines)


def render_lookup_markdown(found: dict) -> str:
    """Render the result of find_standards as Markdown for the host AI."""
    parts = [render_standard_markdown(item) for item in found["standards"]]
    if not parts:
        available = ", ".join(f"`{slug}`" for slug in found["available"]) or "none"
        parts.append(
            "No development standard matches these technologies or files. "
            f"Available standards: {available}."
        )
    if found["uncovered_technologies"]:
        parts.append(
            "No standard covers: "
            + ", ".join(found["uncovered_technologies"])
            + ". Follow the usual community conventions for them."
        )
    return "# Development standards\n\n" + "\n\n".join(parts)


# ── Changes (web interface) ──────────────────────────────────────────────────


def _apply(row: DevStandard, fields: dict, by: str | None) -> None:
    """Copy the normalized fields onto a row."""
    row.title, row.description, row.content = (
        fields["title"],
        fields["description"],
        fields["content"],
    )
    row.technologies = json.dumps(fields["technologies"])
    row.file_patterns = json.dumps(fields["file_patterns"])
    row.enabled = fields["enabled"]
    row.updated_at, row.updated_by = utcnow(), by


def create_standard(entry: dict, by: str | None = None) -> dict:
    """Create a standard; an existing slug is refused.

    Raises:
        ValueError: If the entry is invalid, the slug exists or the limit is reached.
    """
    fields = normalize(entry)
    try:
        with session_scope() as session:
            if session.exec(select(func.count()).select_from(DevStandard)).one() >= MAX_STANDARDS:
                raise ValueError(f"The limit of {MAX_STANDARDS} standards has been reached")
            exists = session.exec(
                select(DevStandard.id).where(col(DevStandard.slug) == fields["slug"])
            ).first()
            if exists is not None:
                raise ValueError(f"Development standard {fields['slug']} already exists")
            row = DevStandard(slug=fields["slug"], title="")
            _apply(row, fields, by)
            session.add(row)
            session.flush()
            return _full(row)
    except IntegrityError as exc:
        raise ValueError(f"Development standard {fields['slug']} already exists") from exc


def update_standard(slug: str, entry: dict, by: str | None = None) -> dict:
    """Replace the fields of a standard without changing its slug.

    Raises:
        NotFoundError: If no standard has this slug.
        ValueError: If the entry is invalid or tries to change the slug.
    """
    fields = normalize(entry | {"slug": entry.get("slug", slug)})
    if fields["slug"] != slug:
        raise ValueError("The slug of a development standard cannot be changed")
    with session_scope() as session:
        row = session.exec(select(DevStandard).where(col(DevStandard.slug) == slug)).first()
        if row is None:
            raise NotFoundError(f"Development standard {slug[:60]!r} not found")
        _apply(row, fields, by)
        session.add(row)
        session.flush()
        return _full(row)


def delete_standard(slug: str) -> None:
    """Delete a standard.

    Raises:
        NotFoundError: If no standard has this slug.
    """
    with session_scope() as session:
        row = session.exec(select(DevStandard).where(col(DevStandard.slug) == slug)).first()
        if row is None:
            raise NotFoundError(f"Development standard {slug[:60]!r} not found")
        session.delete(row)


# ── Import / export (web interface) ──────────────────────────────────────────


def export_pack() -> str:
    """Return every standard (disabled ones included) as a TOML pack accepted by import_pack.

    The audit fields (who changed a standard, and when) are left out.
    """
    document = tomlkit.document()
    document.add(tomlkit.comment("Development standards exported by security-review-controller."))
    document.add(tomlkit.comment("Import them in the web interface (Standards > Import)."))
    tables = tomlkit.aot()
    with session_scope() as session:
        rows = session.exec(select(DevStandard).order_by(col(DevStandard.slug))).all()
        for row in rows:
            entry = _full(row)
            table = tomlkit.table()
            for key in PACK_FIELDS:
                table[key] = entry[key]
            table["content"] = tomlkit.string(entry["content"], multiline=True)
            tables.append(table)
    document["standards"] = tables
    return tomlkit.dumps(document)


def _parse_pack(text: str, name: str) -> list[dict]:
    """Parse and validate a standards pack; return the normalized standards.

    Raises:
        ValueError: Listing every invalid entry.
    """
    if len(text.encode("utf-8")) > MAX_PACK_BYTES:
        raise ValueError(f"{name}: file larger than {MAX_PACK_BYTES} bytes")
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"{name}: {exc}") from exc
    except RecursionError as exc:
        raise ValueError(f"{name}: values nested too deeply") from exc
    entries = data.get("standards", [])
    if not isinstance(entries, list) or not all(isinstance(item, dict) for item in entries):
        raise ValueError(f"{name}: standards must be an array of tables")
    if not entries:
        raise ValueError(f"{name}: no [[standards]] entry to import")
    if len(entries) > MAX_STANDARDS:
        raise ValueError(f"{name}: at most {MAX_STANDARDS} standards")
    parsed: dict[str, dict] = {}
    errors: list[str] = []
    for index, entry in enumerate(entries, start=1):
        try:
            fields = normalize(entry)
        except ValueError as exc:
            errors.append(f"standards[{index}]: {exc}")
            continue
        if fields["slug"] in parsed:
            errors.append(f"standards[{index}]: duplicate slug {fields['slug']}")
            continue
        parsed[fields["slug"]] = fields
    if errors:
        raise ValueError(
            f"Invalid standards pack {name}, nothing imported: " + "; ".join(errors[:20])
        )
    return list(parsed.values())


def import_pack(text: str, name: str, by: str | None = None) -> dict:
    """Import a TOML standards pack, all or nothing.

    A standard is created, or replaced when its slug exists; the other standards are kept.

    Raises:
        ValueError: If the pack is invalid or the limit of standards would be exceeded.
    """
    entries = _parse_pack(text, name)
    created: list[str] = []
    updated: list[str] = []
    try:
        with session_scope() as session:
            existing = {
                row.slug: row
                for row in session.exec(
                    select(DevStandard).where(
                        col(DevStandard.slug).in_([entry["slug"] for entry in entries])
                    )
                ).all()
            }
            total = session.exec(select(func.count()).select_from(DevStandard)).one()
            new = [entry for entry in entries if entry["slug"] not in existing]
            if total + len(new) > MAX_STANDARDS:
                raise ValueError(f"The limit of {MAX_STANDARDS} standards would be exceeded")
            for fields in entries:
                row = existing.get(fields["slug"])
                if row is None:
                    row = DevStandard(slug=fields["slug"], title="")
                    created.append(fields["slug"])
                else:
                    updated.append(fields["slug"])
                _apply(row, fields, by)
                session.add(row)
    except IntegrityError as exc:
        raise ValueError("The standards were changed concurrently; retry the import") from exc
    return {"file": name, "created": created, "updated": updated}
