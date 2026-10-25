import importlib.util
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_release_placeholder_becomes_the_tag_of_the_version():
    # The copied commands of the docs fetch the manifests of the documented release
    spec = importlib.util.spec_from_file_location("mkdocs_hooks", ROOT / "scripts/mkdocs_hooks.py")
    hooks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hooks)
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]
    page = "blob/{{ release_tag }}/examples and `\\{{ release_tag }}`"
    assert hooks.on_page_markdown(page) == f"blob/v{version}/examples and `{{{{ release_tag }}}}`"
