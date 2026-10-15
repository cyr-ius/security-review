"""Tests for the pattern scanner and secret redaction."""

import pytest

from security_review_mcp.scanner import normalize_language, redact_secrets, scan_content


def rule_ids(content: str, language: str) -> set[str]:
    """Return the ids of the rules matching the content."""
    return {m["rule_id"] for m in scan_content(content, language)}


def test_python_rules_detect_common_issues():
    code = "\n".join(
        [
            "import pickle, subprocess, hashlib, requests",
            "data = pickle.loads(blob)",
            "subprocess.run(cmd, shell=True)",
            "requests.get(url, verify=False)",
            "h = hashlib.md5(pw).hexdigest()",
            'cur.execute(f"SELECT * FROM t WHERE id = {uid}")',
            "yaml.load(stream)",
        ]
    )
    found = rule_ids(code, "python")
    assert {"PY-002", "PY-004", "PY-005", "PY-006", "PY-007", "PY-003"} <= found


def test_safe_python_has_no_match():
    code = 'cur.execute("SELECT * FROM t WHERE id = %s", (uid,))\nyaml.safe_load(stream)\n'
    assert scan_content(code, "python") == []


def test_java_rules():
    code = "\n".join(
        [
            "ObjectInputStream in = new ObjectInputStream(socket.getInputStream());",
            'stmt.executeQuery("SELECT * FROM u WHERE n=\'" + name + "\'");',
            "http.csrf().disable();",
            'MessageDigest.getInstance("MD5");',
        ]
    )
    found = rule_ids(code, "java")
    assert {"JV-001", "JV-003", "JV-005", "JV-007"} <= found


def test_angular_rules_accept_aliases():
    code = "this.s.bypassSecurityTrustHtml(x);\nel.innerHTML = y;"
    assert {"NG-001", "NG-002"} <= rule_ids(code, "ts")


def test_config_rules():
    content = (
        "privileged: true\nimage: nginx:latest\nsource: 0.0.0.0/0\nRUN curl http://x.io/i.sh | sh"
    )
    found = rule_ids(content, "yaml")
    assert {"CFG-001", "CFG-004", "CFG-006"} <= found


def test_generic_rules_apply_to_every_language():
    line = 'password = "SuperSecret123"'
    assert "GEN-001" in rule_ids(line, "java")
    assert "GEN-001" in rule_ids(line, "yaml")


def test_excerpt_never_contains_the_secret():
    matches = scan_content('api_key = "SuperSecret123"', "python")
    assert matches
    assert all("SuperSecret123" not in m["excerpt"] for m in matches)


def test_unknown_language_is_rejected():
    with pytest.raises(ValueError):
        normalize_language("cobol")


@pytest.mark.parametrize(
    "text, secret",
    [
        ("password = 'hunter2hunter2'", "hunter2hunter2"),
        ("Authorization: Bearer abcdefghijklmnop12345", "abcdefghijklmnop12345"),
        ("key AKIAABCDEFGHIJKLMNOP here", "AKIAABCDEFGHIJKLMNOP"),
        ("postgres://admin:s3cr3tpw@db:5432/x", "s3cr3tpw"),
        ("t=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdef", "eyJhbGciOiJIUzI1NiJ9"),
        ('SECRET_KEY = "django-insecure-abc"', "django-insecure-abc"),
        ('app.config["SECRET_KEY"] = "flask-dev-key"', "flask-dev-key"),
        ('{"password": "hunter2hunter2"}', "hunter2hunter2"),
        # Fake tokens built at run time so that the file itself holds no token-like literal
        ("GH = " + "ghp_" + "a1" * 18, "a1" * 18),
        ("x " + "glpat-" + "Z9" * 10, "Z9" * 10),
        ("hook " + "xoxb-" + "1234567890-abc", "1234567890-abc"),
        ("k=" + "sk_live_" + "Q" * 24, "Q" * 24),
    ],
)
def test_redact_secrets(text: str, secret: str):
    redacted = redact_secrets(text)
    assert secret not in redacted
    assert "[REDACTED]" in redacted


def test_redact_private_key_block():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc123\n-----END RSA PRIVATE KEY-----"
    redacted = redact_secrets(text)
    assert "MIIEabc123" not in redacted


@pytest.mark.parametrize(
    "content, language, secret",
    [
        ('SECRET_KEY = "django-insecure-abc"', "python", "django-insecure-abc"),
        ("token: " + "ghp_" + "b2" * 18, "yaml", "b2" * 18),
        ("POSTGRES_PASSWORD: postgres", "yaml", "postgres"),
        ("ENV API_TOKEN=abcd1234efgh", "docker", "abcd1234efgh"),
        ("spring.datasource.password=Sup3rS3cret", "config", "Sup3rS3cret"),
    ],
)
def test_new_secret_rules_never_echo_the_secret(content: str, language: str, secret: str):
    matches = scan_content(content, language)
    assert matches
    assert all(secret not in m["excerpt"] for m in matches)
