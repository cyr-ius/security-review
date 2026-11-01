import json
import re
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from security_review_mcp import cli
from security_review_mcp.rules import opengrep_rule_store

CASES_DIR = Path(__file__).parent / "opengrep_rules"

RULE = """rules:
  - id: python.test.safe-eval
    message: Avoid dynamic evaluation
    languages: [python]
    severity: WARNING
    pattern: eval($VALUE)
"""


@pytest.fixture
def configured_store(tmp_path, monkeypatch):
    settings = SimpleNamespace(
        opengrep_rules_dir=str(tmp_path),
        opengrep_binary="opengrep",
        opengrep_timeout_seconds=10,
    )
    monkeypatch.setattr(opengrep_rule_store, "get_settings", lambda: settings)
    monkeypatch.setattr(opengrep_rule_store.shutil, "which", lambda _: "/usr/bin/opengrep")
    monkeypatch.setattr(
        opengrep_rule_store.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout="Configuration is valid", stderr=""
        ),
    )
    return tmp_path


def test_create_list_read_delete(configured_store):
    saved = opengrep_rule_store.save_rule("python.test.safe-eval", RULE, create=True)
    assert saved["content"] == RULE
    assert opengrep_rule_store.list_rules()[0]["id"] == "python.test.safe-eval"
    assert opengrep_rule_store.get_rule("python.test.safe-eval")["content"] == RULE
    opengrep_rule_store.delete_rule("python.test.safe-eval")
    assert opengrep_rule_store.list_rules() == []


def test_reject_mismatched_rule_id():
    with pytest.raises(ValueError, match="must match"):
        opengrep_rule_store.validate_rule("python.test.other", RULE)


def test_reject_path_traversal(configured_store):
    with pytest.raises(ValueError, match="identifier"):
        opengrep_rule_store.get_rule("../outside")


def test_reject_duplicate_rule(configured_store):
    opengrep_rule_store.save_rule("python.test.safe-eval", RULE, create=True)
    with pytest.raises(FileExistsError):
        opengrep_rule_store.save_rule("python.test.safe-eval", RULE, create=True)


def test_reject_invalid_rule(configured_store, monkeypatch):
    monkeypatch.setattr(
        opengrep_rule_store.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=2, stdout="", stderr="invalid pattern"),
    )
    with pytest.raises(ValueError, match="invalid pattern"):
        opengrep_rule_store.validate_rule("python.test.safe-eval", RULE)


def test_rule_id_check_is_linear_on_blank_lines(configured_store):
    # Regression: the former pattern (\s* spanning lines) took minutes on this input (ReDoS)
    with pytest.raises(ValueError, match="one rule"):
        opengrep_rule_store.validate_rule("python.test.safe-eval", "\n" * 262_000 + "x")


def test_install_bundled_rules_keeps_local_edits(configured_store, capsys):
    python_rules = opengrep_rule_store.bundled_rules(["python"])["python"]
    assert cli.run(["opengrep", "install", "--language", "python"]) == cli.EXIT_PASSED
    installed = json.loads(capsys.readouterr().out)["installed"]
    assert sorted(installed) == sorted(path.stem for path in python_rules)
    # Installed flat, one rule per file: the web page and the scan read them as-is
    assert {rule["id"] for rule in opengrep_rule_store.list_rules()} == set(installed)

    edited = configured_store / f"{installed[0]}.yaml"
    edited.write_text(edited.read_text(encoding="utf-8") + "# local edit\n", encoding="utf-8")
    assert opengrep_rule_store.install_bundled(["python"])["skipped"] == sorted(installed)
    assert edited.read_text(encoding="utf-8").endswith("# local edit\n")
    assert len(opengrep_rule_store.install_bundled(["python"], overwrite=True)["replaced"]) == len(
        installed
    )
    assert not edited.read_text(encoding="utf-8").endswith("# local edit\n")

    assert cli.run(["opengrep", "install", "--language", "cobol"]) == cli.EXIT_ERROR
    assert "cobol" in json.loads(capsys.readouterr().err)["error"]


_ANNOTATION = re.compile(r"(?:#|//)\s*(ruleid|ok):\s*([\w.,\s-]+?)\s*$")


@pytest.mark.skipif(shutil.which("opengrep") is None, reason="OpenGrep is not installed")
def test_bundled_rules_match_their_test_cases(tmp_path):
    """Every bundled rule flags its "ruleid:" lines and none of its "ok:" lines.

    Cases are in tests/opengrep_rules: an annotation applies to the next code line.
    """
    cases = tmp_path / "cases"  # OpenGrep skips the paths under tests/ by default
    shutil.copytree(CASES_DIR, cases)
    expected: set[tuple[str, int, str]] = set()
    allowed: set[tuple[str, int, str]] = set()
    for path in cases.rglob("*"):
        if not path.is_file():
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines, 1):
            if not (match := _ANNOTATION.search(line.strip())):
                continue
            target = number + 1
            while _ANNOTATION.search(lines[target - 1].strip()):
                target += 1
            for rule_id in match.group(2).split(","):
                key = (path.relative_to(tmp_path).as_posix(), target, rule_id.strip())
                (expected if match.group(1) == "ruleid" else allowed).add(key)
    process = subprocess.run(
        ["opengrep", "scan", "--json", "--config", str(opengrep_rule_store.BUNDLED_DIR), "cases"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    payload = json.loads(process.stdout)
    assert payload["errors"] == []
    bundled = {
        path.stem for files in opengrep_rule_store.bundled_rules().values() for path in files
    }
    # The rule id is prefixed with the dotted path of the --config directory
    found = {
        (item["path"], item["start"]["line"], rule_id)
        for item in payload["results"]
        for rule_id in bundled
        if item["check_id"].endswith("." + rule_id)
    }
    assert expected - found == set(), "rules missing their expected matches"
    assert allowed & found == set(), "rules matching safe code"
    assert bundled - {key[2] for key in expected} == set(), "bundled rules without a test case"


def _bundle(directory, **rules):
    """Write a bundled rule pack: one python/<id>.yaml file per rule, message as content."""
    language = directory / "python"
    language.mkdir(parents=True, exist_ok=True)
    for rule_id, message in rules.items():
        rule_id = rule_id.replace("_", "-")
        (language / f"python.test.{rule_id}.yaml").write_text(
            RULE.replace("python.test.safe-eval", f"python.test.{rule_id}").replace(
                "Avoid dynamic evaluation", message
            ),
            encoding="utf-8",
        )


def test_sync_bundled_rules_keeps_administrator_edits_and_deletions(
    configured_store, tmp_path, monkeypatch
):
    bundle = tmp_path / "bundle"
    monkeypatch.setattr(opengrep_rule_store, "BUNDLED_DIR", bundle)
    _bundle(bundle, edited="v1", deleted="v1", untouched="v1")
    assert sorted(opengrep_rule_store.sync_bundled()["installed"]) == [
        "python.test.deleted",
        "python.test.edited",
        "python.test.untouched",
    ]

    edited = configured_store / "python.test.edited.yaml"
    edited.write_text(edited.read_text(encoding="utf-8") + "# local edit\n", encoding="utf-8")
    opengrep_rule_store.delete_rule("python.test.deleted")
    # A new version of the package changes every rule and adds one
    _bundle(bundle, edited="v2", deleted="v2", untouched="v2", added="v2")
    changes = opengrep_rule_store.sync_bundled()

    assert changes == {
        "installed": ["python.test.added"],
        "updated": ["python.test.untouched"],
        "kept": ["python.test.edited"],
    }
    assert edited.read_text(encoding="utf-8").endswith("# local edit\n")
    assert not (configured_store / "python.test.deleted.yaml").exists()
    assert "v2" in opengrep_rule_store.get_rule("python.test.untouched")["content"]
    # Up to date: nothing changes at the next start
    assert opengrep_rule_store.sync_bundled() == {
        "installed": [],
        "updated": [],
        "kept": ["python.test.edited"],
    }
