"""Lightweight pattern scanner and secret redaction.

This is a first-pass helper that points the reviewer at suspicious lines. It is NOT a
replacement for SAST tools or for a real review: matches are leads to verify, and the
absence of a match proves nothing.
"""

import re
from dataclasses import dataclass

from .models import Severity


@dataclass(frozen=True)
class Rule:
    """A single detection rule."""

    id: str
    title: str
    severity: Severity
    cwe: str
    languages: frozenset[str]  # "*" matches every language
    pattern: re.Pattern[str]
    advice: str


def _rule(
    rule_id: str,
    title: str,
    severity: Severity,
    cwe: str,
    languages: str,
    pattern: str,
    advice: str,
) -> Rule:
    """Build a Rule from a space-separated language list and a regex."""
    return Rule(
        rule_id,
        title,
        severity,
        cwe,
        frozenset(languages.split()),
        re.compile(pattern, re.IGNORECASE),
        advice,
    )


RULES: tuple[Rule, ...] = (
    # ── Cross-language ───────────────────────────────────────────────────────
    _rule(
        "GEN-001",
        "Hard-coded credential",
        Severity.HIGH,
        "CWE-798",
        "*",
        r"(password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*[\"'][^\"'\s]{6,}[\"']",
        "Move the secret to a vault or environment variable and rotate it.",
    ),
    _rule(
        "GEN-002",
        "Private key material",
        Severity.CRITICAL,
        "CWE-321",
        "*",
        r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "Remove the key from the repository, rotate it and purge it from history.",
    ),
    _rule(
        "GEN-003",
        "Cloud access key identifier",
        Severity.HIGH,
        "CWE-798",
        "*",
        r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
        "Revoke the key and use short-lived credentials.",
    ),
    _rule(
        "GEN-004",
        "Plain HTTP URL for a non-local host",
        Severity.LOW,
        "CWE-319",
        "*",
        r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])[\w.-]+",
        "Use HTTPS unless the endpoint is strictly local.",
    ),
    # ── Python ───────────────────────────────────────────────────────────────
    _rule(
        "PY-001",
        "eval/exec on dynamic data",
        Severity.HIGH,
        "CWE-95",
        "python",
        r"\b(eval|exec)\s*\(",
        "Avoid dynamic execution; use ast.literal_eval or an explicit dispatch table.",
    ),
    _rule(
        "PY-002",
        "Unsafe deserialization (pickle/marshal)",
        Severity.HIGH,
        "CWE-502",
        "python",
        r"\b(pickle|cPickle|marshal|shelve)\.(loads?|Unpickler)\b",
        "Never load untrusted data; use JSON or a schema-validated format.",
    ),
    _rule(
        "PY-003",
        "yaml.load without SafeLoader",
        Severity.HIGH,
        "CWE-502",
        "python",
        r"yaml\.load\s*\((?![^)]*SafeLoader)",
        "Use yaml.safe_load.",
    ),
    _rule(
        "PY-004",
        "Shell command execution",
        Severity.HIGH,
        "CWE-78",
        "python",
        r"(shell\s*=\s*True|os\.system\s*\(|os\.popen\s*\()",
        "Pass an argument list to subprocess without shell=True and validate inputs.",
    ),
    _rule(
        "PY-005",
        "SQL built with string formatting",
        Severity.HIGH,
        "CWE-89",
        "python",
        r"(execute|executemany|text)\s*\(\s*(f[\"']|[\"'][^\"']*[\"']\s*(%|\.format|\+))",
        "Use bound parameters (cursor.execute(sql, params)).",
    ),
    _rule(
        "PY-006",
        "TLS verification disabled",
        Severity.HIGH,
        "CWE-295",
        "python",
        r"verify\s*=\s*False",
        "Keep verification on; supply a CA bundle for internal CAs.",
    ),
    _rule(
        "PY-007",
        "Weak hash function",
        Severity.MEDIUM,
        "CWE-327",
        "python",
        r"hashlib\.(md5|sha1)\s*\(",
        "Use SHA-256+ for integrity and argon2/bcrypt/scrypt for passwords.",
    ),
    _rule(
        "PY-008",
        "Non-cryptographic random for security use",
        Severity.MEDIUM,
        "CWE-338",
        "python",
        r"\brandom\.(random|randint|choice|randrange)\s*\(",
        "Use the secrets module for tokens, passwords and keys.",
    ),
    _rule(
        "PY-009",
        "Debug mode enabled",
        Severity.MEDIUM,
        "CWE-489",
        "python",
        r"(debug\s*=\s*True|app\.run\([^)]*debug\s*=\s*True)",
        "Disable debug outside local development.",
    ),
    _rule(
        "PY-010",
        "Insecure temporary file",
        Severity.LOW,
        "CWE-377",
        "python",
        r"\btempfile\.mktemp\s*\(",
        "Use tempfile.mkstemp or NamedTemporaryFile.",
    ),
    # ── Java ─────────────────────────────────────────────────────────────────
    _rule(
        "JV-001",
        "Java deserialization",
        Severity.HIGH,
        "CWE-502",
        "java",
        r"\b(new\s+ObjectInputStream|XMLDecoder|enableDefaultTyping|activateDefaultTyping)\b",
        "Use an allow-list ObjectInputFilter or a data-only format such as JSON.",
    ),
    _rule(
        "JV-002",
        "OS command execution",
        Severity.HIGH,
        "CWE-78",
        "java",
        r"(Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(",
        "Avoid shell invocation; pass fixed commands and validated arguments.",
    ),
    _rule(
        "JV-003",
        "SQL built by concatenation",
        Severity.HIGH,
        "CWE-89",
        "java",
        r"(createStatement\(\)|executeQuery|executeUpdate|createQuery|createNativeQuery)"
        r"\s*\([^;]*\+",
        "Use PreparedStatement or named parameters.",
    ),
    _rule(
        "JV-004",
        "XML parser possibly vulnerable to XXE",
        Severity.MEDIUM,
        "CWE-611",
        "java",
        r"\b(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory)"
        r"\.newInstance\s*\(",
        "Enable secure processing and disallow DOCTYPE declarations.",
    ),
    _rule(
        "JV-005",
        "CSRF protection disabled",
        Severity.MEDIUM,
        "CWE-352",
        "java",
        r"csrf\s*\(\s*\)\s*\.\s*disable\s*\(|csrf\s*\(\s*\w+\s*->\s*\w+\.disable\s*\(",
        "Keep CSRF on for browser/session clients; disable only for stateless token APIs.",
    ),
    _rule(
        "JV-006",
        "Wildcard CORS",
        Severity.MEDIUM,
        "CWE-942",
        "java",
        r"(@CrossOrigin\s*(\(\s*\))?\s*$|allowedOrigins?\s*\(\s*\"\*\"|origins\s*=\s*\"\*\")",
        "Restrict allowed origins; never combine * with credentials.",
    ),
    _rule(
        "JV-007",
        "Weak hash/cipher",
        Severity.MEDIUM,
        "CWE-327",
        "java",
        r"(MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\"|Cipher\.getInstance\(\s*\"(DES|AES/ECB|AES\")"
        r"|NoOpPasswordEncoder)",
        "Use SHA-256+, AES-GCM and a strong PasswordEncoder (BCrypt/Argon2).",
    ),
    _rule(
        "JV-008",
        "Trust-all TLS",
        Severity.HIGH,
        "CWE-295",
        "java",
        r"(ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|checkServerTrusted\s*\([^)]*\)\s*\{\s*\})",
        "Validate certificates and hostnames.",
    ),
    # ── Angular / TypeScript ─────────────────────────────────────────────────
    _rule(
        "NG-001",
        "Sanitizer bypass",
        Severity.HIGH,
        "CWE-79",
        "typescript javascript angular",
        r"bypassSecurityTrust(Html|Script|Style|Url|ResourceUrl)\s*\(",
        "Remove the bypass or sanitize with a strict allow-list (e.g. DOMPurify).",
    ),
    _rule(
        "NG-002",
        "innerHTML / DOM write",
        Severity.MEDIUM,
        "CWE-79",
        "typescript javascript angular",
        r"(\.innerHTML\s*=|\[innerHTML\]|outerHTML\s*=|document\.write\s*\()",
        "Prefer text binding; if HTML is required, sanitize it.",
    ),
    _rule(
        "NG-003",
        "Dynamic code execution",
        Severity.HIGH,
        "CWE-95",
        "typescript javascript angular",
        r"(\beval\s*\(|new\s+Function\s*\()",
        "Remove dynamic code execution.",
    ),
    _rule(
        "NG-004",
        "Token stored in web storage",
        Severity.MEDIUM,
        "CWE-922",
        "typescript javascript angular",
        r"(localStorage|sessionStorage)\.setItem\s*\(\s*[\"'][^\"']*(token|jwt|secret|password)",
        "Prefer HttpOnly, Secure, SameSite cookies handled by the backend.",
    ),
    _rule(
        "NG-005",
        "Direct DOM access",
        Severity.LOW,
        "CWE-79",
        "typescript angular",
        r"nativeElement\s*\.(innerHTML|outerHTML)",
        "Use Angular bindings or Renderer2 with sanitized values.",
    ),
    # ── Configuration (YAML, Docker, properties, CI) ─────────────────────────
    _rule(
        "CFG-001",
        "Privileged container",
        Severity.HIGH,
        "CWE-250",
        "config yaml docker",
        r"privileged\s*:\s*true",
        "Drop privileged mode; add only the capabilities needed.",
    ),
    _rule(
        "CFG-002",
        "Docker socket mounted",
        Severity.HIGH,
        "CWE-250",
        "config yaml docker",
        r"/var/run/docker\.sock",
        "Avoid mounting the Docker socket; use a rootless builder.",
    ),
    _rule(
        "CFG-003",
        "Container image uses :latest",
        Severity.LOW,
        "CWE-1357",
        "config yaml docker",
        r"(^|\s)(image\s*:|FROM)\s+[\w./-]+(:latest)?\s*$",
        "Pin images by version or, better, by digest.",
    ),
    _rule(
        "CFG-004",
        "Unrestricted network range",
        Severity.HIGH,
        "CWE-668",
        "config yaml docker",
        r"0\.0\.0\.0/0",
        "Restrict the source range to what is strictly required.",
    ),
    _rule(
        "CFG-005",
        "World-writable permissions",
        Severity.MEDIUM,
        "CWE-732",
        "config yaml docker",
        r"chmod\s+(-R\s+)?(777|666)",
        "Apply least-privilege file modes.",
    ),
    _rule(
        "CFG-006",
        "Remote script piped to shell",
        Severity.HIGH,
        "CWE-829",
        "config yaml docker",
        r"(curl|wget)[^|\n]*\|\s*(sudo\s+)?(ba)?sh",
        "Download, verify checksum/signature, then execute.",
    ),
    _rule(
        "CFG-007",
        "Debug enabled in configuration",
        Severity.MEDIUM,
        "CWE-489",
        "config yaml",
        r"\b(debug|DEBUG)\s*[:=]\s*(true|1|yes)\b",
        "Disable debug in non-development environments.",
    ),
    _rule(
        "CFG-008",
        "TLS verification disabled in configuration",
        Severity.HIGH,
        "CWE-295",
        "config yaml docker",
        r"(ssl[_-]?verify|verify[_-]?ssl|insecure[_-]?skip[_-]?verify|NODE_TLS_REJECT_UNAUTHORIZED)"
        r"\s*[:=]\s*[\"']?(false|0|true)",
        "Keep certificate verification enabled.",
    ),
    _rule(
        "CFG-009",
        "Actuator/management endpoints fully exposed",
        Severity.MEDIUM,
        "CWE-200",
        "config yaml",
        r"management\.endpoints\.web\.exposure\.include\s*[:=]\s*\*",
        "Expose only health/info and protect the rest.",
    ),
)

SUPPORTED_LANGUAGES: tuple[str, ...] = (
    "python",
    "java",
    "typescript",
    "javascript",
    "angular",
    "config",
    "yaml",
    "docker",
    "gitlab-ci",
    "jenkins",
)

_LANGUAGE_ALIASES = {
    "py": "python",
    "ts": "typescript",
    "js": "javascript",
    "yml": "yaml",
    "dockerfile": "docker",
    "properties": "config",
    "ini": "config",
    "env": "config",
    "gitlab": "gitlab-ci",
    "gitlab_ci": "gitlab-ci",
    ".gitlab-ci.yml": "gitlab-ci",
    "groovy": "jenkins",
    "jenkinsfile": "jenkins",
}

# Rules written for a parent language also apply to its children
LANGUAGE_PARENTS: dict[str, tuple[str, ...]] = {
    "gitlab-ci": ("yaml", "config"),
    "jenkins": ("config",),
}

MAX_LINE_CHARS = 2000  # longer lines are truncated before matching (bounds regex cost)

_SUPPRESS_RE = re.compile(r"secreview:ignore(?P<rest>[^\n]*)", re.IGNORECASE)
_RULE_ID_RE = re.compile(r"\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+\b")


def normalize_language(language: str) -> str:
    """Return the canonical language name or raise ValueError."""
    key = language.strip().lower()
    key = _LANGUAGE_ALIASES.get(key, key)
    if key not in SUPPORTED_LANGUAGES:
        raise ValueError(
            f"Unsupported language '{language}'. Supported: {', '.join(SUPPORTED_LANGUAGES)}"
        )
    return key


def _suppressed_ids(line: str) -> set[str] | None:
    """Parse an inline ``secreview:ignore [RULE-ID ...]`` marker.

    Returns None when there is no marker, an empty set to ignore every rule on the line,
    or the set of rule ids to ignore.
    """
    found = _SUPPRESS_RE.search(line)
    if not found:
        return None
    return set(_RULE_ID_RE.findall(found.group("rest")))


def scan_content_detailed(
    content: str,
    language: str,
    rules: tuple[Rule, ...] | list[Rule] | None = None,
    max_matches: int = 200,
) -> tuple[list[dict], list[dict]]:
    """Scan source text and return ``(matches, suppressed)``.

    Args:
        content: Source or configuration text.
        language: One of SUPPORTED_LANGUAGES (aliases accepted).
        rules: Rules to apply (defaults to the built-in rules).
        max_matches: Maximum number of matches returned.

    Returns:
        The matches (secrets masked in the excerpts) and the matches hidden by an inline
        ``secreview:ignore`` marker. Suppressions are reported so that they can be audited.
    """
    lang = normalize_language(language)
    accepted = {lang, *LANGUAGE_PARENTS.get(lang, ())}
    active = RULES if rules is None else rules
    selected = [r for r in active if "*" in r.languages or r.languages & accepted]

    matches: list[dict] = []
    suppressed: list[dict] = []
    for number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line[:MAX_LINE_CHARS]
        ignored = _suppressed_ids(line)
        for rule in selected:
            if not rule.pattern.search(line):
                continue
            item = {
                "rule_id": rule.id,
                "title": rule.title,
                "severity": rule.severity.value,
                "cwe": rule.cwe,
                "line": number,
                "excerpt": redact_secrets(line.strip())[:300],
                "advice": rule.advice,
            }
            if ignored is not None and (not ignored or rule.id in ignored):
                suppressed.append(item)
            else:
                matches.append(item)
                if len(matches) >= max_matches:
                    return matches, suppressed
    return matches, suppressed


def scan_content(content: str, language: str, max_matches: int = 200) -> list[dict]:
    """Scan with the built-in rules and return only the visible matches."""
    return scan_content_detailed(content, language, None, max_matches)[0]


# ── Secret redaction ─────────────────────────────────────────────────────────

_REDACTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    # key = "value" assignments for sensitive-looking names
    re.compile(
        r"(?i)((?:password|passwd|pwd|secret|api[_-]?key|token|authorization)\s*[:=]\s*[\"']?"
        r"(?:(?:bearer|basic)\s+)?)"
        r"([^\"'\s,;]{4,})"
    ),
    # Bearer tokens
    re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._~+/=-]{12,})"),
    # Cloud access keys
    re.compile(r"()\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
    # JWT-looking values
    re.compile(r"()\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)"),
    # Credentials embedded in URLs: scheme://user:pass@host
    re.compile(r"(://[^:/\s@]+:)([^@\s]+)(?=@)"),
)

_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN ([A-Z ]*PRIVATE KEY)-----.*?(-----END \1-----|$)", re.DOTALL
)

REDACTED = "[REDACTED]"


def redact_secrets(text: str) -> str:
    """Mask credentials and private keys so that they are never stored or echoed."""
    text = _PRIVATE_KEY_BLOCK.sub(f"-----BEGIN \\1-----{REDACTED}-----END \\1-----", text)
    for pattern in _REDACTION_PATTERNS:
        text = pattern.sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    return text
