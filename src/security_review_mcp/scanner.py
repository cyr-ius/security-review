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
        rules: Rules to apply (defaults to the rules of ``default_rules.toml``).
        max_matches: Maximum number of matches returned.

    Returns:
        The matches (secrets masked in the excerpts) and the matches hidden by an inline
        ``secreview:ignore`` marker. Suppressions are reported so that they can be audited.
    """
    lang = normalize_language(language)
    accepted = {lang, *LANGUAGE_PARENTS.get(lang, ())}
    if rules is None:
        from .rules_loader import default_content  # imported here: rules_loader imports us

        rules = default_content().rules
    selected = [r for r in rules if "*" in r.languages or r.languages & accepted]

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
    """Scan with the default rules and return only the visible matches."""
    return scan_content_detailed(content, language, None, max_matches)[0]


# ── Secret redaction ─────────────────────────────────────────────────────────

_REDACTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    # key = "value" assignments for sensitive-looking names (also "key": "v" and ["KEY"] = "v");
    # permission levels such as GitHub Actions "id-token: write" are not secrets, and an already
    # masked value (the marker, then closing punctuation only) is skipped so that the characters
    # after the marker are kept
    re.compile(
        r"(?i)((?:password|passwd|pwd|secret(?:[_-]?key)?|api[_-]?key|token|authorization)"
        r"[\"']?\]?\s*[:=]\s*[\"']?(?:(?:bearer|basic)\s+)?)"
        r"(?!(?:read|write|none|\[REDACTED\][)\]}>.:!?]*)(?:[\"'\s,;]|$))([^\"'\s,;]{4,})"
    ),
    # Tokens with a known service prefix (GitHub, GitLab, Slack, Google, Stripe, npm)
    re.compile(
        r"()\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|glpat-[A-Za-z0-9_-]{20,}"
        r"|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|(?:sk|rk)_live_[0-9A-Za-z]{20,}"
        r"|npm_[A-Za-z0-9]{36})"
    ),
    # Bearer tokens
    re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._~+/=-]{12,})"),
    # Cloud access keys
    re.compile(r"()\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
    # JWT-looking values
    re.compile(r"()\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)"),
    # Credentials embedded in URLs: scheme://user:pass@host  # secreview:ignore GEN-007 (example)
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
