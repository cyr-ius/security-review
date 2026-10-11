"""Checklist items: the verification points of a review domain.

The default checklists are shipped in ``default_rules.toml`` and stored in the database; the
active ones are served by ``registry``.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class CheckItem:
    """One verification point of a checklist."""

    id: str
    title: str
    what_to_look_for: str
    cwe: str
