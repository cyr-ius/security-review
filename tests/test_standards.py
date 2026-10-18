"""Development standards: validation, storage, lookup and rendering."""

import tomllib

import pytest

from security_review_mcp import standards
from security_review_mcp.services import NotFoundError


def make(slug: str = "python", **kwargs) -> dict:
    """Return a valid standard entry."""
    entry = {
        "slug": slug,
        "title": f"{slug.title()} standard",
        "description": "House conventions",
        "technologies": [slug, "FastAPI"],
        "file_patterns": ["*.py", "pyproject.toml"],
        "content": "- Type every function.\n- Use ruff.",
    }
    entry.update(kwargs)
    return entry


def test_create_normalizes_and_lists_without_content():
    created = standards.create_standard(
        make(technologies=["Python", " Spring   Boot ", "python"]), by="admin"
    )

    assert created["technologies"] == ["python", "spring boot"]
    assert created["updated_by"] == "admin"
    listed = standards.list_standards()
    assert [item["slug"] for item in listed] == ["python"]
    assert "content" not in listed[0]
    assert listed[0]["content_chars"] == len(created["content"])


@pytest.mark.parametrize(
    "changes, message",
    [
        ({"slug": "Python"}, "slug"),
        ({"slug": "a b"}, "slug"),
        ({"title": "   "}, "title is required"),
        ({"content": ""}, "content is required"),
        ({"content": "x" * (standards.MAX_CONTENT_CHARS + 1)}, "content is too long"),
        ({"technologies": ["ok", "<script>"]}, "technologies: invalid entry"),
        ({"technologies": [f"t{i}" for i in range(standards.MAX_KEYWORDS + 1)]}, "at most"),
        ({"file_patterns": ["*.py;rm"]}, "file_patterns: invalid entry"),
        ({"technologies": "python"}, "must be a list"),
        ({"enabled": "yes"}, "enabled must be a boolean"),
    ],
)
def test_invalid_entries_are_refused(changes, message):
    with pytest.raises(ValueError, match=message):
        standards.create_standard(make(**changes))
    assert standards.list_standards(include_disabled=True) == []


def test_duplicate_slug_and_limit_are_refused(monkeypatch):
    standards.create_standard(make())
    with pytest.raises(ValueError, match="already exists"):
        standards.create_standard(make())

    monkeypatch.setattr(standards, "MAX_STANDARDS", 1)
    with pytest.raises(ValueError, match="limit of 1"):
        standards.create_standard(make("angular"))


def test_update_keeps_slug_and_delete_removes():
    standards.create_standard(make())

    updated = standards.update_standard("python", make(content="New rules"), by="bob")
    assert updated["content"] == "New rules"
    assert updated["updated_by"] == "bob"
    with pytest.raises(ValueError, match="cannot be changed"):
        standards.update_standard("python", make("java"))
    with pytest.raises(NotFoundError):
        standards.update_standard("java", make("java"))

    standards.delete_standard("python")
    with pytest.raises(NotFoundError):
        standards.get_standard("python")
    with pytest.raises(NotFoundError):
        standards.delete_standard("python")


def test_disabled_standard_is_hidden_from_the_lookup():
    standards.create_standard(make(enabled=False))

    assert standards.list_standards() == []
    assert standards.list_standards(include_disabled=True)[0]["enabled"] is False
    with pytest.raises(NotFoundError):
        standards.get_standard("python")
    assert standards.get_standard("python", include_disabled=True)["slug"] == "python"
    assert standards.find_standards(["python"])["standards"] == []


def test_find_by_technology_alias_or_file():
    standards.create_standard(make())
    standards.create_standard(
        make("angular", technologies=["typescript"], file_patterns=["angular.json", "*.ts"])
    )

    by_alias = standards.find_standards(["FastAPI", "Rust"])
    assert [item["slug"] for item in by_alias["standards"]] == ["python"]
    assert by_alias["uncovered_technologies"] == ["Rust"]
    assert by_alias["available"] == ["angular", "python"]

    by_file = standards.find_standards(files=["web\\src\\app\\App.TS", "README.md"])
    assert [item["slug"] for item in by_file["standards"]] == ["angular"]
    assert by_file["standards"][0]["matched_files"] == ["web\\src\\app\\App.TS"]

    assert standards.find_standards(["go"])["standards"] == []


def test_glob_with_a_slash_matches_the_whole_path():
    standards.create_standard(make("ci", technologies=[], file_patterns=[".github/workflows/*"]))

    assert standards.find_standards(files=[".github/workflows/ci.yml"])["standards"]
    assert standards.find_standards(files=["ci.yml", "workflows/ci.yml"])["standards"] == []


def test_find_is_bounded(monkeypatch):
    with pytest.raises(ValueError, match="technologies: at most"):
        standards.find_standards([f"t{i}" for i in range(standards.MAX_QUERY_TECHNOLOGIES + 1)])
    with pytest.raises(ValueError, match="entry too long"):
        standards.find_standards(files=["a" * (standards.MAX_QUERY_FILE_CHARS + 1)])
    monkeypatch.setenv("SECREVIEW_MAX_CONTENT_CHARS", "10")
    standards.get_settings.cache_clear()
    try:
        with pytest.raises(ValueError, match="Lookup too large"):
            standards.find_standards(files=["src/app/main.ts"])
    finally:
        monkeypatch.delenv("SECREVIEW_MAX_CONTENT_CHARS")
        standards.get_settings.cache_clear()


def test_rendering():
    assert "No development standard" in standards.render_catalog_markdown([])
    standards.create_standard(make())

    catalog = standards.render_catalog_markdown(standards.list_standards())
    assert "`python`: **Python standard** (python, fastapi): House conventions" in catalog

    found = standards.render_lookup_markdown(standards.find_standards(["python", "cobol"]))
    assert "## Python standard (`python`)" in found
    assert "Type every function" in found
    assert "No standard covers: cobol" in found

    missing = standards.render_lookup_markdown(standards.find_standards(["cobol"]))
    assert "Available standards: `python`" in missing


# ── Import / export ──────────────────────────────────────────────────────────


def test_export_round_trips_through_import():
    tricky = 'Quotes """ and \\ backslashes\n```python\nprint("x")\n```'
    standards.create_standard(make(content=tricky), by="alice")
    standards.create_standard(make("angular", enabled=False))
    exported = standards.export_pack()
    data = tomllib.loads(exported)
    assert [item["slug"] for item in data["standards"]] == ["angular", "python"]
    assert data["standards"][0]["enabled"] is False
    assert data["standards"][1]["content"] == tricky
    assert "updated_by" not in data["standards"][1]  # no audit field
    assert "alice" not in exported

    for slug in ("angular", "python"):
        standards.delete_standard(slug)
    result = standards.import_pack(exported, "export.toml", by="bob")
    assert result == {"file": "export.toml", "created": ["angular", "python"], "updated": []}
    assert standards.get_standard("python")["content"] == tricky
    assert standards.get_standard("python")["updated_by"] == "bob"
    assert standards.export_pack() == exported


def test_import_creates_or_replaces_by_slug_and_keeps_the_others():
    standards.create_standard(make("python"))
    standards.create_standard(make("go"))
    pack = '[[standards]]\nslug = "python"\ntitle = "New"\ncontent = "- New rule"\n'
    pack += '[[standards]]\nslug = "rust"\ntitle = "Rust"\ncontent = "- Clippy"\n'
    result = standards.import_pack(pack, "pack.toml")
    assert result["created"] == ["rust"] and result["updated"] == ["python"]
    python = standards.get_standard("python")
    assert python["title"] == "New" and python["technologies"] == [] and python["enabled"]
    assert [item["slug"] for item in standards.list_standards()] == ["go", "python", "rust"]


@pytest.mark.parametrize(
    "pack, message",
    [
        ("not = [toml", "pack.toml"),
        ("", "no \\[\\[standards\\]\\] entry"),
        ('standards = "x"', "array of tables"),
        (
            '[[standards]]\nslug = "rust"\ntitle = "Rust"\ncontent = "- Clippy"\n'
            '[[standards]]\nslug = "Bad"\ntitle = "t"\ncontent = "c"',
            r"nothing imported: standards\[2\]: slug",
        ),
        (
            '[[standards]]\nslug = "a"\ntitle = "t"\ncontent = "c"\n'
            '[[standards]]\nslug = "a"\ntitle = "t"\ncontent = "c"',
            "duplicate slug a",
        ),
    ],
)
def test_invalid_packs_import_nothing(pack, message):
    standards.create_standard(make())
    with pytest.raises(ValueError, match=message):
        standards.import_pack(pack, "pack.toml")
    assert [item["slug"] for item in standards.list_standards()] == ["python"]


def test_import_is_bounded(monkeypatch):
    monkeypatch.setattr(standards, "MAX_PACK_BYTES", 10)
    with pytest.raises(ValueError, match="larger than 10 bytes"):
        standards.import_pack("# " + "x" * 20, "big.toml")
    monkeypatch.setattr(standards, "MAX_PACK_BYTES", 4096)
    monkeypatch.setattr(standards, "MAX_STANDARDS", 1)
    standards.create_standard(make())
    pack = '[[standards]]\nslug = "rust"\ntitle = "Rust"\ncontent = "- Clippy"\n'
    with pytest.raises(ValueError, match="limit of 1 standards"):
        standards.import_pack(pack, "pack.toml")
    # Replacing an existing standard does not count against the limit
    standards.import_pack(pack.replace("rust", "python"), "pack.toml")


def test_deeply_nested_pack_is_refused():
    with pytest.raises(ValueError, match="nested.toml"):
        standards.import_pack("a = " + "[" * 50_000 + "]" * 50_000, "nested.toml")
