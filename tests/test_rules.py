"""Tests for internal rule packs, platform rules, suppression and the registry."""

import pytest

from security_review_mcp import prompts, registry, rule_store
from security_review_mcp.rules_loader import parse_pack

VALID_PACK = """
disabled_rules = ["PY-008"]

[[rules]]
id = "ACME-001"
title = "Legacy crypto helper"
severity = "high"
cwe = "CWE-327"
languages = ["python"]
pattern = '''LegacyCrypto\\.encrypt\\('''
advice = "Use CryptoService."

[[checklist]]
domain = "company"
id = "ACME-CL-01"
title = "Tenant isolation"
what_to_look_for = "Queries are scoped by tenant."
cwe = "CWE-639"

[[checklist]]
domain = "payments"
id = "ACME-PAY-01"
title = "Idempotency"
what_to_look_for = "Replays are rejected."
"""


def ids(matches: list[dict]) -> set[str]:
    """Return the rule ids of a match list."""
    return {m["rule_id"] for m in matches}


# ── Internal rules (database) ────────────────────────────────────────────────


def test_valid_pack_adds_rules_and_checklists(import_pack):
    import_pack(VALID_PACK)
    matches, _ = registry.scan("x = LegacyCrypto.encrypt(data)", "python")
    assert ids(matches) == {"ACME-001"}
    assert "company" in registry.domains()
    assert "payments" in registry.domains()
    assert "Idempotency" in registry.render_checklist_markdown("payments")
    assert registry.snapshot().errors == ()


def test_pack_can_disable_a_builtin_rule(import_pack):
    import_pack(VALID_PACK)
    matches, _ = registry.scan("v = random.randint(1, 9)", "python")
    assert "PY-008" not in ids(matches)
    assert "PY-008" in registry.snapshot().disabled_rule_ids


def test_custom_rule_replaces_builtin_with_same_id(import_pack):
    import_pack(
        """
[[rules]]
id = "PY-006"
title = "Custom TLS rule"
severity = "critical"
languages = ["python"]
pattern = 'verify\\s*=\\s*False'
"""
    )
    matches, _ = registry.scan("requests.get(u, verify=False)", "python")
    hit = next(m for m in matches if m["rule_id"] == "PY-006")
    assert hit["title"] == "Custom TLS rule"
    assert hit["severity"] == "critical"


def test_company_checklist_is_added_to_review_prompts(import_pack):
    import_pack(VALID_PACK)
    text = prompts.build_security_review_prompt("python", "x = 1", "", "")
    assert "ACME-CL-01" in text
    assert "ACME-CL-01" in prompts.build_api_review_prompt("FastAPI", "", "", "")


def test_without_pack_there_is_no_company_section():
    assert registry.company_checklist_markdown() == ""
    assert "ACME" not in prompts.build_security_review_prompt("java", "", "", "")


@pytest.mark.parametrize(
    "entry, fragment",
    [
        ('id = "bad id"\ntitle = "t"\nseverity = "high"\npattern = "x"', "invalid id"),
        ('id = "A-1"\ntitle = "t"\nseverity = "huge"\npattern = "x"', "invalid severity"),
        ('id = "A-1"\ntitle = "t"\nseverity = "low"\npattern = "("', "invalid regex"),
        ('id = "A-1"\ntitle = "t"\nseverity = "low"\npattern = "(a+)+$"', "backtracking"),
        ('id = "A-1"\ntitle = "t"\nseverity = "low"\npattern = "a*"', "empty string"),
        ('id = "A-1"\ntitle = "t"\nseverity = "low"\npattern = "x"\ncwe = "89"', "invalid cwe"),
        (
            'id = "A-1"\ntitle = "t"\nseverity = "low"\npattern = "x"\nlanguages = ["cobol"]',
            "unknown",
        ),
        ('id = "A-1"\ntitle = "t"\nseverity = "low"', "missing pattern"),
        (f'id = "A-1"\ntitle = "{"t" * 301}"\nseverity = "low"\npattern = "x"', "longer than"),
        (f'id = "A-{"1" * 60}"\ntitle = "t"\nseverity = "low"\npattern = "x"', "invalid id"),
    ],
)
def test_invalid_rules_are_reported(entry, fragment):
    result = parse_pack(f"[[rules]]\n{entry}\n", "bad.toml")
    assert result.rules == []
    assert any(fragment in error and "bad.toml" in error for error in result.errors), result.errors


def test_broken_pack_is_reported():
    result = parse_pack("this is [not valid toml", "broken.toml")
    assert result.errors and "broken.toml" in result.errors[0]
    assert parse_pack('disabled_rules = ["not an id"]', "p.toml").errors


def test_unreadable_database_keeps_builtin_rules(database):
    database.dispose()
    from sqlmodel import SQLModel

    SQLModel.metadata.drop_all(database)
    snapshot = registry.reload()
    assert snapshot.errors and "database error (OperationalError)" in snapshot.errors[0]
    assert len(snapshot.rules) > 0  # built-in rules still work


def test_reload_picks_up_changes():
    assert "ACME-001" not in registry.snapshot().custom_rule_ids
    rule_store.import_packs([("company.toml", VALID_PACK)])
    assert "ACME-001" in registry.reload().custom_rule_ids


def test_snapshot_follows_changes_made_by_another_process(monkeypatch):
    assert "ACME-001" not in registry.snapshot().custom_rule_ids
    rule_store.import_packs([("company.toml", VALID_PACK)])  # e.g. the CLI, no reload here
    assert "ACME-001" not in registry.snapshot().custom_rule_ids  # cached
    monkeypatch.setattr(registry, "REFRESH_SECONDS", 0.0)
    assert "ACME-001" in registry.snapshot().custom_rule_ids
    revision = registry.snapshot().revision
    assert registry.snapshot().revision == revision  # unchanged revision: no reload


def test_describe_rules_marks_origin_and_state(import_pack):
    import_pack(VALID_PACK)
    rows = {row["id"]: row for row in registry.describe_rules("python")}
    assert rows["ACME-001"]["origin"] == "custom"
    assert rows["PY-001"]["origin"] == "builtin"
    assert "JV-001" not in rows
    assert "PY-008" not in rows
    every = {row["id"]: row for row in registry.describe_rules("python", include_disabled=True)}
    assert every["PY-008"]["enabled"] is False
    assert every["PY-001"]["enabled"] is True


# ── Platform rules ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "language, code, expected",
    [
        ("gitlab-ci", "include:\n  - remote: 'https://example.com/ci.yml'", "GL-001"),
        ("gitlab-ci", '  - echo "token $CI_JOB_TOKEN"', "GL-002"),
        ("gitlab-ci", 'variables:\n  DOCKER_TLS_CERTDIR: ""', "GL-003"),
        ("gitlab-ci", "  allow_failure: true", "GL-004"),
        ("jenkins", 'sh "deploy ${params.TARGET}"', "JK-001"),
        ("jenkins", "@Library('shared-lib') _", "JK-002"),
        ("jenkins", "pipeline { agent any }", "JK-003"),
        ("jenkins", "sh 'curl -k https://nexus/x.sh'", "CI-001"),
        ("config", "management.endpoint.health.show-details=always", "SP-001"),
        ("config", "spring.h2.console.enabled=true", "SP-002"),
        ("java", "http.authorizeRequests().anyRequest().permitAll();", "SP-005"),
        ("java", "public User save(@RequestBody UserEntity user)", "SP-006"),
        ("python", "app.add_middleware(CORSMiddleware, allow_origins=['*'])", "FA-001"),
        ("python", 'jwt.decode(t, options={"verify_signature": False})', "FA-002"),
        ("python", "tar.extractall(path)", "PY-011"),
        ("angular", "win.postMessage(data, '*')", "NG-006"),
    ],
)
def test_platform_rules(language, code, expected):
    matches, _ = registry.scan(code, language)
    assert expected in ids(matches), matches


def test_gitlab_ci_inherits_yaml_rules():
    matches, _ = registry.scan("  privileged: true", "gitlab-ci")
    assert "CFG-001" in ids(matches)


def test_language_aliases():
    matches, _ = registry.scan("pipeline { agent any }", "Jenkinsfile")
    assert "JK-003" in ids(matches)


# ── Inline suppression ───────────────────────────────────────────────────────


def test_inline_suppression_is_reported_not_hidden():
    code = "subprocess.run(c, shell=True)  # secreview:ignore PY-004 test fixture"
    matches, suppressed = registry.scan(code, "python")
    assert "PY-004" not in ids(matches)
    assert ids(suppressed) == {"PY-004"}
    assert suppressed[0]["line"] == 1


def test_suppression_without_ids_hides_every_rule_on_the_line():
    code = "subprocess.run(c, shell=True); eval(x)  # secreview:ignore"
    matches, suppressed = registry.scan(code, "python")
    assert matches == []
    assert {"PY-001", "PY-004"} <= ids(suppressed)


def test_suppressing_another_rule_does_not_hide_the_match():
    code = "subprocess.run(c, shell=True)  # secreview:ignore PY-001"
    matches, suppressed = registry.scan(code, "python")
    assert "PY-004" in ids(matches)
    assert suppressed == []


def test_very_long_lines_are_truncated_before_matching():
    line = "a" * 5000 + " eval(x)"
    matches, _ = registry.scan(line, "python")
    assert matches == []
