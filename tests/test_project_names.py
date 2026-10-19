"""Tests of the normalization of project names."""

import pytest

from security_review_mcp.project_names import (
    MAX_PROJECT_CHARS,
    MAX_RAW_PROJECT_CHARS,
    normalize_project,
)


@pytest.mark.parametrize(
    "name",
    [
        "security-review-mcp",
        "Security-Review-MCP",
        "  security-review-mcp\n",
        "security_review_mcp",
        "Security Review MCP",
        "security.review.mcp",
        "security--review__mcp",
        "-security-review-mcp-",
        "cyr-ius/security-review-mcp",
        "cyr-ius/security-review-mcp/",
        "group/subgroup/security-review-mcp",
        "https://github.com/cyr-ius/security-review-mcp",
        "https://github.com/cyr-ius/security-review-mcp.git",
        "https://user:secret@gitlab.example.com/cyr-ius/Security_Review_MCP.git/",
        "git@github.com:cyr-ius/security-review-mcp.git",
        "ssh://git@github.com/cyr-ius/security-review-mcp.git",
        r"C:\src\security-review-mcp",
        "ＳＥＣＵＲＩＴＹ-review-mcp",  # fullwidth letters (NFKC)
    ],
)
def test_variants_of_a_repository_name_give_one_project(name):
    assert normalize_project(name) == "security-review-mcp"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("shop", "shop"),
        ("API v2", "api-v2"),
        ("Équipe Paiement", "équipe-paiement"),
        ('evil"} 1\nsecreview_fake 9', "evil-1-secreview-fake-9"),
        ("project:shop", "project-shop"),
        ("repo.git.git", "repo-git"),
        ("legit", "legit"),
    ],
)
def test_normalized_names(name, expected):
    assert normalize_project(name) == expected


@pytest.mark.parametrize(
    "name",
    ["security-review-mcp", "Owner/My_Repo.git", "Équipe Paiement", "İstanbul", "a\tb\x00c"],
)
def test_normalization_is_idempotent_and_keeps_letters_digits_and_dashes(name):
    once = normalize_project(name)
    assert normalize_project(once) == once
    assert all(char.isalnum() or char == "-" for char in once)
    assert not once.startswith("-") and not once.endswith("-") and "--" not in once


@pytest.mark.parametrize("name", ["", "   ", "---", "///", "https://", ".git", "_"])
def test_names_without_letters_or_digits_are_refused(name):
    with pytest.raises(ValueError, match=f"between 1 and {MAX_PROJECT_CHARS}"):
        normalize_project(name)


def test_long_names_are_refused():
    assert len(normalize_project("a" * MAX_PROJECT_CHARS)) == MAX_PROJECT_CHARS
    with pytest.raises(ValueError, match=f"between 1 and {MAX_PROJECT_CHARS}"):
        normalize_project("a" * (MAX_PROJECT_CHARS + 1))
    # A long URL is accepted when its repository name fits
    url = "https://gitlab.example.com/" + "group/" * 100 + "shop"
    assert len(url) > MAX_PROJECT_CHARS and normalize_project(url) == "shop"
    with pytest.raises(ValueError, match=f"at most {MAX_RAW_PROJECT_CHARS}"):
        normalize_project("a/" * MAX_RAW_PROJECT_CHARS + "shop")
