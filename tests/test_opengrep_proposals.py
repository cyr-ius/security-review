from types import SimpleNamespace

import pytest

from security_review_mcp.config import get_settings
from security_review_mcp.observability import audit
from security_review_mcp.rules import opengrep_proposals, opengrep_rule_store

RULE_ID = "acme.python.unsafe-template"
RULE = f"""rules:
  - id: {RULE_ID}
    message: Template rendered from user input
    languages: [python]
    severity: ERROR
    metadata:
      cwe: "CWE-1336"
    pattern: render_template_string(request.$X.get(...))
"""
REASON = "Server-side template injection missed by the scan rules"
TEST_CODE = (
    f"# ruleid: {RULE_ID}\nrender_template_string(request.args.get('t'))\n"
    f"# ok: {RULE_ID}\nrender_template('page.html')\n"
)


@pytest.fixture
def rules_dir(tmp_path, monkeypatch):
    """A rules directory, with an OpenGrep executable that accepts every rule."""
    settings = SimpleNamespace(
        opengrep_rules_dir=str(tmp_path), opengrep_binary="opengrep", opengrep_timeout_seconds=10
    )
    monkeypatch.setattr(opengrep_rule_store, "get_settings", lambda: settings)
    monkeypatch.setattr(opengrep_rule_store.shutil, "which", lambda _: "/usr/bin/opengrep")
    monkeypatch.setattr(
        opengrep_rule_store.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="ok", stderr=""),
    )
    return tmp_path


def propose(rule_id: str = RULE_ID, content: str = RULE) -> dict:
    return opengrep_proposals.propose_rule(
        "Acme/Shop", rule_id, content, REASON, TEST_CODE, "agent-token"
    )


def actions() -> list[str]:
    return [event["action"] for event in audit.list_events()["events"]]


def test_a_proposed_rule_is_installed_only_by_an_approval_and_never_over_a_rule(rules_dir):
    first = propose()
    # A new proposal of the same rule replaces the pending one
    replaced = propose(content=RULE.replace("ERROR", "WARNING"))
    assert replaced["id"] == first["id"] and replaced["project"] == "shop"
    assert [item["id"] for item in opengrep_proposals.list_proposals()] == [first["id"]]
    assert not (rules_dir / f"{RULE_ID}.yaml").exists()

    approved = opengrep_proposals.approve_proposal(first["id"], "alice", "user:alice", RULE)
    assert (approved["status"], approved["decided_by"]) == ("approved", "alice")
    assert (rules_dir / f"{RULE_ID}.yaml").read_text(encoding="utf-8") == RULE
    assert opengrep_proposals.list_proposals() == []
    with pytest.raises(ValueError, match="already decided"):
        opengrep_proposals.reject_proposal(first["id"], "alice", "user:alice")

    # The same rule proposed again cannot replace the installed one: nothing is recorded
    again = propose()
    with pytest.raises(FileExistsError):
        opengrep_proposals.approve_proposal(again["id"], "alice", "user:alice")
    assert opengrep_proposals.list_proposals()[0]["status"] == "pending"
    assert actions() == [
        "opengrep_rule.proposed",
        "opengrep_rule.approved",
        "opengrep_rule.proposed",
        "opengrep_rule.proposed",
    ]


@pytest.mark.parametrize(
    ("rule_id", "content", "error"),
    [
        ("secreview.python.x", RULE.replace(RULE_ID, "secreview.python.x"), "reserved"),
        (RULE_ID, RULE + "    # password: hunter2hunter2\n", "secret"),
        (RULE_ID, RULE.replace("Template", "Temp\u200blate"), "invisible"),
        (RULE_ID, RULE + RULE.split("\n", 1)[1].replace(RULE_ID, "acme.other"), "one rule"),
    ],
)
def test_an_agent_cannot_propose_an_unsafe_rule(rule_id, content, error):
    with pytest.raises(ValueError, match=error):
        propose(rule_id, content)
    assert opengrep_proposals.list_proposals() == [] and actions() == []


def test_pending_proposals_are_bounded(monkeypatch):
    monkeypatch.setenv("SECREVIEW_OPENGREP_MAX_PENDING_PROPOSALS", "1")
    get_settings.cache_clear()
    try:
        propose()
        with pytest.raises(ValueError, match="Too many"):
            propose("acme.python.other", RULE.replace(RULE_ID, "acme.python.other"))
        # Replacing the pending proposal stays possible
        assert propose()["rule_id"] == RULE_ID
    finally:
        monkeypatch.delenv("SECREVIEW_OPENGREP_MAX_PENDING_PROPOSALS")
        get_settings.cache_clear()
