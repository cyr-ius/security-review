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
OTHER_ID = "acme.python.other"
OTHER = RULE.replace(RULE_ID, OTHER_ID).replace("render_template_string", "Template")
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

    # An approval never replaces a rule installed meanwhile: nothing is recorded
    other = propose(OTHER_ID, OTHER)
    (rules_dir / f"{OTHER_ID}.yaml").write_text(OTHER, encoding="utf-8")
    with pytest.raises(FileExistsError):
        opengrep_proposals.approve_proposal(other["id"], "alice", "user:alice")
    assert opengrep_proposals.list_proposals()[0]["status"] == "pending"
    assert actions() == [
        "opengrep_rule.proposed",
        "opengrep_rule.approved",
        "opengrep_rule.proposed",
        "opengrep_rule.proposed",
    ]


def test_a_rule_already_installed_or_proposed_is_refused(rules_dir):
    # Same detection as a pending proposal, under another id and another layout
    propose()
    copy = (
        RULE.replace(RULE_ID, "acme.python.copy")
        .replace("Template rendered from user input", "SSTI")
        .replace("  - id", "  # a comment\n  - id")
        .replace(
            "pattern: render_template_string(request.$X.get(...))",
            'pattern:   "render_template_string(request.$X.get(...))"',
        )
    )
    with pytest.raises(ValueError, match=f"pending proposal .*'{RULE_ID}'"):
        propose("acme.python.copy", copy)
    # Not named to another project
    with pytest.raises(ValueError, match="another pending proposal$"):
        opengrep_proposals.propose_rule(
            "other", "acme.python.copy", copy, REASON, TEST_CODE, "agent-token"
        )
    opengrep_proposals.approve_proposal(propose()["id"], "alice", "user:alice")
    # The installed rule, under its id or another one, and a default rule
    with pytest.raises(ValueError, match="already installed"):
        propose()
    with pytest.raises(ValueError, match=f"same code as the OpenGrep rule '{RULE_ID}'"):
        propose("acme.python.copy", copy)
    bundled = next(iter(opengrep_rule_store.bundled_rules().values()))[0]
    content = bundled.read_text(encoding="utf-8").replace(bundled.stem, "acme.default.copy")
    with pytest.raises(ValueError, match=f"'{bundled.stem}'"):
        propose("acme.default.copy", content)
    # Another pattern is a new rule
    assert propose(OTHER_ID, OTHER)["status"] == "pending"


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
            propose(OTHER_ID, OTHER)
        # Replacing the pending proposal stays possible
        assert propose()["rule_id"] == RULE_ID
    finally:
        monkeypatch.delenv("SECREVIEW_OPENGREP_MAX_PENDING_PROPOSALS")
        get_settings.cache_clear()
