"""Lightweight pattern scanner and secret redaction.

This is a first-pass helper that points the reviewer at suspicious lines. It is NOT a
replacement for SAST tools or for a real review: matches are leads to verify, and the
absence of a match proves nothing.
"""

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial

from .models import Severity
from .syntax_analysis import (
    angular_xss_taint_lines,
    java_sql_taint_lines,
    message_origin_check_lines,
    python_sql_taint_lines,
    sql_taint_lines,
)

logger = logging.getLogger(__name__)

# Rule of the request-to-SQL flow analysis of each language
_SQL_FLOW_RULES = {"go": "GO-019", "csharp": "CS-021", "rust": "RS-015"}


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
    "go",
    "csharp",
    "rust",
    "config",
    "yaml",
    "docker",
    "gitlab-ci",
    "jenkins",
    "agent-instructions",
)

_LANGUAGE_ALIASES = {
    "py": "python",
    "ts": "typescript",
    "js": "javascript",
    "golang": "go",
    "cs": "csharp",
    "c#": "csharp",
    "dotnet": "csharp",
    ".net": "csharp",
    "rs": "rust",
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


def _excerpt(line: str) -> str:
    """Return the excerpt of a matched line: secrets masked, hidden characters revealed."""
    return sanitize_untrusted(line.strip())[:300]


def _structural_analyses(lang: str) -> list[tuple[str, Callable[[str], list[int]]]]:
    """Return the Tree-sitter analyses of a language: (rule id, function returning lines)."""
    if lang == "python":
        return [("PY-026", python_sql_taint_lines)]
    if lang == "java":
        return [("JV-019", java_sql_taint_lines)]
    if lang in ("go", "csharp", "rust"):
        return [(_SQL_FLOW_RULES[lang], partial(sql_taint_lines, language=lang))]
    if lang in ("typescript", "javascript", "angular"):
        grammar = "javascript" if lang == "javascript" else "typescript"
        analyses: list[tuple[str, Callable[[str], list[int]]]] = [
            ("NG-021", partial(angular_xss_taint_lines, language=grammar)),
            ("NG-022", partial(message_origin_check_lines, language=grammar)),
        ]
        if lang != "angular":  # templates hold no SQL
            analyses.append(("TS-016", partial(sql_taint_lines, language=grammar)))
        return analyses
    return []


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
                "excerpt": _excerpt(line),
                "advice": rule.advice,
            }
            if ignored is not None and (not ignored or rule.id in ignored):
                suppressed.append(item)
            else:
                matches.append(item)
                if len(matches) >= max_matches:
                    return matches, suppressed
    for rule_id, analysis in _structural_analyses(lang):
        if len(matches) >= max_matches:
            break
        rule = next((rule for rule in selected if rule.id == rule_id), None)
        if rule is None:
            continue
        try:
            numbers = analysis(content)
        except RecursionError:
            # Deeply nested code: the structural check is skipped, the patterns still apply
            logger.warning("%s skipped: the code is nested too deeply", rule_id)
            continue
        source_lines = content.splitlines()
        for number in numbers:
            line = source_lines[number - 1][:MAX_LINE_CHARS]
            item = {
                "rule_id": rule.id,
                "title": rule.title,
                "severity": rule.severity.value,
                "cwe": rule.cwe,
                "line": number,
                "excerpt": _excerpt(line),
                "advice": rule.advice,
            }
            ignored = _suppressed_ids(line)
            if ignored is not None and (not ignored or rule.id in ignored):
                suppressed.append(item)
            else:
                matches.append(item)
                if len(matches) >= max_matches:
                    break
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


# ── Hidden characters ────────────────────────────────────────────────────────

# Characters that display as nothing but are read by a model: zero-width characters, the byte
# order mark, bidirectional controls (Trojan Source), Unicode tags and supplementary variation
# selectors (text smuggled to an AI assistant)
_HIDDEN_CHARS_RE = re.compile(
    "[\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff"
    "\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
)


def reveal_hidden_characters(text: str) -> str:
    """Replace each invisible character with a visible ``<U+XXXX>`` marker (nothing is removed)."""
    return _HIDDEN_CHARS_RE.sub(lambda m: f"<U+{ord(m.group()):04X}>", text)


def sanitize_untrusted(text: str) -> str:
    """Mask the secrets and reveal the hidden characters of text that a model will read."""
    return reveal_hidden_characters(redact_secrets(text))
