"""Tests for internal rule packs, platform rules, suppression and the registry."""

import pytest

from security_review_mcp import prompts, registry
from security_review_mcp.rules_loader import load_rules_dir

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


# ── Rule packs ───────────────────────────────────────────────────────────────


def test_valid_pack_adds_rules_and_checklists(rules_dir):
    (rules_dir / "company.toml").write_text(VALID_PACK)
    matches, _ = registry.scan("x = LegacyCrypto.encrypt(data)", "python")
    assert ids(matches) == {"ACME-001"}
    assert "company" in registry.domains()
    assert "payments" in registry.domains()
    assert "Idempotency" in registry.render_checklist_markdown("payments")
    assert registry.snapshot().errors == ()


def test_pack_can_disable_a_builtin_rule(rules_dir):
    (rules_dir / "company.toml").write_text(VALID_PACK)
    matches, _ = registry.scan("v = random.randint(1, 9)", "python")
    assert "PY-008" not in ids(matches)
    assert "PY-008" in registry.snapshot().disabled_rule_ids


def test_custom_rule_replaces_builtin_with_same_id(rules_dir):
    (rules_dir / "override.toml").write_text(
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


def test_company_checklist_is_added_to_review_prompts(rules_dir):
    (rules_dir / "company.toml").write_text(VALID_PACK)
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
    ],
)
def test_invalid_rules_are_skipped_and_reported(rules_dir, entry, fragment):
    (rules_dir / "bad.toml").write_text(f"[[rules]]\n{entry}\n")
    result = load_rules_dir(rules_dir)
    assert result.rules == []
    assert any(fragment in error for error in result.errors), result.errors


def test_broken_file_does_not_block_valid_ones(rules_dir):
    (rules_dir / "a_broken.toml").write_text("this is [not valid toml")
    (rules_dir / "b_good.toml").write_text(VALID_PACK)
    snapshot = registry.reload()
    assert "ACME-001" in snapshot.custom_rule_ids
    assert any("a_broken.toml" in error for error in snapshot.errors)


def test_missing_directory_is_reported_not_fatal(tmp_path, monkeypatch):
    from security_review_mcp.config import get_settings

    monkeypatch.setattr(get_settings(), "rules_dir", str(tmp_path / "nope"))
    registry.reset()
    snapshot = registry.snapshot()
    assert snapshot.errors and "not found" in snapshot.errors[0]
    assert len(snapshot.rules) > 0  # built-in rules still work


def test_reload_picks_up_changes(rules_dir):
    assert "ACME-001" not in registry.snapshot().custom_rule_ids
    (rules_dir / "company.toml").write_text(VALID_PACK)
    assert "ACME-001" in registry.reload().custom_rule_ids


def test_describe_rules_marks_origin(rules_dir):
    (rules_dir / "company.toml").write_text(VALID_PACK)
    rows = {row["id"]: row for row in registry.describe_rules("python")}
    assert rows["ACME-001"]["origin"] == "custom"
    assert rows["PY-001"]["origin"] == "builtin"
    assert "JV-001" not in rows


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
