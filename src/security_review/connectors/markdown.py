"""Markdown description of a record, for the systems that render Markdown (GitHub, GitLab).

The texts of a finding are written by an agent: rendered as Markdown, they could mention people
(``@team`` notifies them), load an image from another site, add links or, in GitLab, run quick
actions (``/close``). Each value is therefore put in a code span or a code block whose fence is
longer than any run of its fence character in the text, so that nothing in it is read as
Markdown.
"""

import re

from .api import MAX_DESCRIPTION_CHARS, FindingContent


def _longest_run(text: str, char: str) -> int:
    """Length of the longest run of ``char`` in ``text``."""
    return max((len(run) for run in re.findall(f"{re.escape(char)}+", text)), default=0)


def code_span(text: str) -> str:
    """Inline code holding ``text`` as is (one line)."""
    text = " ".join(text.split())
    fence = "`" * (_longest_run(text, "`") + 1)
    return f"{fence} {text} {fence}"


def code_block(text: str) -> str:
    """Fenced code block holding ``text`` as is."""
    fence = "~" * max(3, _longest_run(text, "~") + 1)
    return f"{fence}text\n{text}\n{fence}"


def markdown_description(content: FindingContent, limit: int = MAX_DESCRIPTION_CHARS) -> str:
    """Description of a record: the facts as code spans, then each section in a code block.

    The link to the report is the only active link: the controller builds it from its own URL.
    """
    lines = []
    for name, value in content.facts:
        if name == "Report" and value == content.report_url:
            lines.append(f"- **{name}**: <{value}>")
        else:
            lines.append(f"- **{name}**: {code_span(value)}")
    footer = f"\n\n_Sent by Security Review (finding {content.finding_id})._"
    body = "\n".join(lines)
    for title, text in content.sections:
        block = f"\n\n### {title}\n\n{code_block(text)}"
        if len(body) + len(block) + len(footer) > limit:
            room = limit - len(body) - len(footer) - len(f"\n\n### {title}\n\n") - 40
            if room > 0:
                block = f"\n\n### {title}\n\n{code_block(text[:room] + '\n[truncated]')}"
                body += block
            body += "\n\n_[truncated]_"
            break
        body += block
    return body + footer
