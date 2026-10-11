"""Prompt builders for the MCP prompts (kept separate from the server wiring for testability)."""

from .registry import company_checklist_markdown, render_checklist_markdown

_METHOD = """\
## Method
1. Understand the code: entry points, trust boundaries, data flows from untrusted input \
(requests, files, messages, environment) to sensitive sinks (queries, commands, file system, \
HTML, deserialization, outbound requests).
2. Call the `scan_code` tool on the code to get quick leads, then verify each lead by reading \
the surrounding code. A match is a lead, not a finding. Lines hidden by an inline \
`secreview:ignore` marker are returned under `suppressed`: judge them yourself and report \
any suppression that looks unjustified.
3. Walk through the checklist below, item by item. Report only issues you can point to \
in the code you were given.
4. For each confirmed issue, give: title, severity, CWE (and OWASP category when relevant), \
file and line range, a short explanation of the impact and of how it can be reached, an \
evidence excerpt, and a concrete fix (a code snippet when useful).
5. Rate severity by exploitability and impact in context (critical, high, medium, low, info). \
Do not inflate severity: an issue that needs privileged access or is unreachable is lower.

## Rules
- Never invent findings, file names or line numbers. If you are unsure, say so and lower the \
confidence instead of guessing.
- Never copy real secrets into your answer or into the report: mask them (for example \
`AKIA****`). The server also masks common secret formats, but do not rely on it.
- Prefer few, well-supported findings over a long list of speculative ones.
- If the provided code is too small to judge a point, list it under "Not verifiable" rather \
than reporting it.

## Deliverable
1. Reply with a short summary and the list of findings, most severe first.
2. Then call the `save_security_report` tool exactly once with the project name, a summary \
and the structured findings, so that the review is stored. Pass an empty findings list if \
the review found nothing, and say what was covered.
"""


_PIPELINE_HINTS = ("gitlab", "jenkins", "pipeline", "ci/cd", "cicd", "stages:")


def _cicd_checklist(kind: str, content: str) -> str:
    """Return the CI/CD checklist when the files look like pipeline definitions."""
    haystack = f"{kind}\n{content[:2000]}".lower()
    if any(hint in haystack for hint in _PIPELINE_HINTS):
        return render_checklist_markdown("cicd")
    return ""


def _context_block(context: str, focus: str) -> str:
    """Render the optional context and focus sections."""
    parts = []
    if context.strip():
        parts.append(f"## Context\n{context.strip()}")
    if focus.strip():
        parts.append(f"## Focus\nGive extra attention to: {focus.strip()}")
    return "\n\n".join(parts)


def _code_block(code: str, language: str) -> str:
    """Render the code to review, or tell the agent to read it from the workspace."""
    if code.strip():
        return f"## Code to review\n```{language}\n{code.strip()}\n```"
    return (
        "## Code to review\nNo code was provided inline. Review the files, diff or merge "
        "request currently available in your workspace, and state exactly which files you read."
    )


def build_security_review_prompt(language: str, code: str, context: str, focus: str) -> str:
    """Build the general security-review prompt for Python, Java or Angular code."""
    lang = language.strip().lower() or "python"
    domains = [lang if lang in ("python", "java", "angular") else None, "api"]
    checklists = "\n\n".join(render_checklist_markdown(d) for d in domains if d)
    checklists = "\n\n".join(x for x in (checklists, company_checklist_markdown()) if x)
    sections = [
        f"You are a senior application security engineer performing a code review of "
        f"**{lang}** code. Look for security vulnerabilities and insecure configuration "
        "(OWASP Top 10, CWE).",
        _context_block(context, focus),
        _METHOD,
        checklists,
        _code_block(code, lang),
    ]
    return "\n\n".join(s for s in sections if s)


def build_api_review_prompt(framework: str, code: str, context: str, focus: str) -> str:
    """Build the REST API security-review prompt (OWASP API Security Top 10)."""
    fw = framework.strip() or "unspecified framework"
    sections = [
        f"You are a senior application security engineer reviewing a **REST API** "
        f"({fw}). Use the OWASP API Security Top 10 as the reference. Pay particular "
        "attention to authorization on every route and to how request data is bound and "
        "returned.",
        _context_block(context, focus),
        "For each endpoint you can see, determine: who may call it, how identity is "
        "established, how object ownership is verified, which fields are accepted and "
        "returned, and which limits apply (size, rate, pagination).",
        _METHOD,
        render_checklist_markdown("api"),
        company_checklist_markdown(),
        _code_block(code, "text"),
    ]
    return "\n\n".join(s for s in sections if s)


def build_config_review_prompt(config_type: str, content: str, context: str, focus: str) -> str:
    """Build the configuration review prompt (Docker, CI/CD, Spring, YAML, properties...)."""
    kind = config_type.strip() or "configuration"
    sections = [
        f"You are a senior application security engineer reviewing **{kind}** files for "
        "security misconfiguration: exposed secrets, excessive privileges, insecure defaults, "
        "network exposure, weak TLS, unpinned dependencies and risky CI/CD steps.",
        _context_block(context, focus),
        _METHOD.replace("`scan_code`", "`scan_code` (use language `config`, `yaml` or `docker`)"),
        render_checklist_markdown("config"),
        _cicd_checklist(kind, content),
        company_checklist_markdown(),
        _code_block(content, "yaml"),
    ]
    return "\n\n".join(s for s in sections if s)


def build_triage_prompt(report_text: str, context: str) -> str:
    """Build the triage prompt used to re-assess an existing report."""
    sections = [
        "You are a senior application security engineer triaging a security report. "
        "For each finding decide: confirmed, false positive, or needs more information. "
        "Re-assess severity with the deployment context, then propose a fix order.",
        _context_block(context, ""),
        "When a finding is a false positive or has been fixed, call `update_finding_status` "
        "with the finding id and the new status (`fixed`, `accepted` or `false_positive`).",
        f"## Report\n{report_text.strip()}",
    ]
    return "\n\n".join(s for s in sections if s)


def build_dependency_review_prompt(ecosystem: str, files: str, context: str) -> str:
    """Build the dependency / supply-chain review prompt."""
    scope = ecosystem.strip() or "PyPI, npm and Maven"
    sections = [
        f"You are a senior application security engineer reviewing the **dependencies** ({scope}) "
        "of a project: known vulnerabilities and supply-chain hygiene.",
        _context_block(context, ""),
        """\
## Method
1. List the dependency files of the project (manifests and lockfiles). Prefer lockfiles: they \
contain the exact resolved versions, including transitive dependencies.
2. For each file call the `scan_dependencies` tool with its content and its file name. Large \
lockfiles do not fit in a tool call: tell the user to run \
`security-review-mcp deps scan <file> --project <name> --save` in the pipeline instead.
3. Read `vulnerability_check` first. If it is not `performed`, say clearly that vulnerable \
versions could NOT be checked: never report "no vulnerability" in that case.
4. Read `advisory_database`: report its age; a stale database means recent issues may be missing.
5. For each vulnerability, confirm that the package is really used (direct, transitive, dev only) \
and give the recommended upgrade. For each hygiene issue, explain the risk in this project.
6. Check what the tool cannot see: manifest without a committed lockfile, private package names \
that exist on public registries (dependency confusion), abandoned or typosquatted packages.

## Rules
- Do not invent vulnerabilities or versions: use only what the tool returns.
- A vulnerability in a dev-only dependency is lower risk than one in a runtime dependency.
- Prefer one finding per vulnerable package, not one per advisory alias.

## Deliverable
Reply with a short summary and the findings, then call `save_security_report` once. Use \
category `dependency`, the advisory id as `rule_id`, `CWE-1395` for vulnerable components and \
the manifest path as `file_path`.
""",
        render_checklist_markdown("dependencies"),
        company_checklist_markdown(),
        (
            f"## Dependency files\n{files.strip()}"
            if files.strip()
            else "## Dependency files\nNo content was provided inline: read the dependency "
            "files of your workspace and state exactly which files you read."
        ),
    ]
    return "\n\n".join(s for s in sections if s)
