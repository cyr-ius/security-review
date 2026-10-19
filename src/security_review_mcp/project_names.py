"""Normalization of project names.

Reports, tokens, roles and gates are grouped by project name, compared exactly. The name is
chosen by each client (the host model, the ``--project`` option of a pipeline), so the members
of a team could otherwise store the same repository under several names. Every project name
entering the server goes through ``normalize_project``: the canonical form is the repository
name, in lowercase, made of letters, digits and single ``-`` (no quote, colon or control
character can reach a label, a file name or a log line).
"""

import re
import unicodedata
from typing import Annotated

from pydantic import AfterValidator

MAX_PROJECT_CHARS = 200
# Bound of the name given by the client, before normalization (a remote URL is longer)
MAX_RAW_PROJECT_CHARS = 1000

# git@github.com:owner/repo.git (SCP-like syntax of git remotes)
_SCP_REMOTE = re.compile(r"^[\w.+-]+@[\w.-]+:")
_PATH_SEPARATORS = re.compile(r"[/\\]+")
# Runs of anything but letters and digits become one dash (spaces, dots, underscores...)
_SEPARATORS = re.compile(r"[\W_]+")


def normalize_project(name: str) -> str:
    """Return the canonical form of a project name.

    The name is NFKC-normalized and lowercased; a git remote URL or a path keeps its last
    segment without ``.git`` (``https://github.com/Owner/My_Repo.git`` and ``owner/my-repo``
    both give ``my-repo``); every run of characters other than letters and digits (spaces, dots,
    underscores, dashes, punctuation, control characters) becomes one dash. The result is
    idempotent: normalizing a normalized name returns it unchanged.

    Raises:
        ValueError: If the name is longer than MAX_RAW_PROJECT_CHARS, or the normalized name
            empty or longer than MAX_PROJECT_CHARS.
    """
    if len(name) > MAX_RAW_PROJECT_CHARS:
        raise ValueError(f"Project must contain at most {MAX_RAW_PROJECT_CHARS} characters")
    value = unicodedata.normalize("NFKC", name).strip().lower()
    if "://" in value:
        value = value.split("://", 1)[1]
    else:
        value = _SCP_REMOTE.sub("", value)
    segments = [segment for segment in _PATH_SEPARATORS.split(value) if segment.strip()]
    value = segments[-1].strip() if segments else ""
    value = _SEPARATORS.sub("-", value.removesuffix(".git")).strip("-")
    if not 1 <= len(value) <= MAX_PROJECT_CHARS:
        raise ValueError(f"Project must contain between 1 and {MAX_PROJECT_CHARS} characters")
    return value


# Project name accepted by the MCP tools and the REST API, normalized at validation
ProjectName = Annotated[str, AfterValidator(normalize_project)]
