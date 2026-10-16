"""Version comparison that works well enough for PyPI, npm and Maven.

Each ecosystem has its own rules (PEP 440, semver, Maven ordering). This comparator covers the
common cases: dotted numbers, and pre-release tags (alpha, beta, rc, SNAPSHOT...) that sort
before the release. Exotic versions can be mis-ordered, so matches are leads to verify.
"""

import re
from functools import cmp_to_key

_TOKEN_RE = re.compile(r"\d+|[a-z]+")

# Pre-release tags, from the oldest to the closest to the release
_PRE_RANK = {
    "dev": 0,
    # npm channels (Angular, React...): published before the betas of a release
    "canary": 0,
    "nightly": 0,
    "experimental": 0,
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "milestone": 3,
    "m": 3,
    # Angular: 22.0.0-next.N, then 22.0.0-rc.N, then 22.0.0
    "next": 3,
    "rc": 4,
    "cr": 4,
    "c": 4,
    "pre": 4,
    "preview": 4,
    "snapshot": 5,
}
# Suffixes that mean "the plain release" (Maven: 1.0.RELEASE == 1.0)
_NEUTRAL = {"final", "release", "ga"}
_OTHER_RANK = 10  # unknown words (post, sp...) sort after the release


def tokenize(version: str) -> list[int | str]:
    """Split a version into numbers and lowercase words (epoch and build metadata dropped)."""
    text = version.strip().lower()
    text = text.split("+", 1)[0]
    text = re.sub(r"^\d+!", "", text)  # PEP 440 epoch
    text = text.removeprefix("v")
    return [int(t) if t.isdigit() else t for t in _TOKEN_RE.findall(text)]


def _against_missing(token: int | str) -> int:
    """Compare a token with an absent one (``1.0.1`` vs ``1.0``): sign of token - missing."""
    if isinstance(token, int):
        return 1 if token > 0 else 0
    if token in _NEUTRAL:
        return 0
    return -1 if token in _PRE_RANK else 1


def _rank(word: str) -> int:
    """Return the ordering rank of a word token."""
    if word in _NEUTRAL:
        return 6
    return _PRE_RANK.get(word, _OTHER_RANK)


def compare_versions(left: str, right: str) -> int:
    """Return -1, 0 or 1 depending on whether ``left`` is older, equal or newer than ``right``."""
    a, b = tokenize(left), tokenize(right)
    for index in range(max(len(a), len(b))):
        x = a[index] if index < len(a) else None
        y = b[index] if index < len(b) else None
        if x == y:
            continue
        if x is None:
            result = -_against_missing(y)  # type: ignore[arg-type]
        elif y is None:
            result = _against_missing(x)
        elif isinstance(x, int) and isinstance(y, int):
            result = -1 if x < y else 1
        elif isinstance(x, int):  # a number beats a word at the same position
            result = 1
        elif isinstance(y, int):
            result = -1
        else:
            rx, ry = _rank(x), _rank(y)
            result = (-1 if rx < ry else 1) if rx != ry else (-1 if x < y else 1)
        if result != 0:
            return result
    return 0


version_key = cmp_to_key(compare_versions)


def sort_versions(values: list[str]) -> list[str]:
    """Return the versions sorted from the oldest to the newest."""
    return sorted(values, key=version_key)
