from types import SimpleNamespace

import pytest

from security_review_mcp.rules import opengrep_rule_store

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
