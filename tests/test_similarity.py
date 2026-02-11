"""Tests for similarity module — fuzzy package name suggestions."""


from src.utils.similarity import (
    suggest_crates_package,
    suggest_go_module,
    suggest_npm_package,
    suggest_pypi_package,
    suggest_similar_package,
)


def test_exact_match_returns_suggestion() -> None:
    """Exact match should return a suggestion."""
    result = suggest_similar_package("requests", ["requests", "flask"])
    assert "requests" in result


def test_close_match_returns_suggestion() -> None:
    """Typo in package name should suggest correct one."""
    result = suggest_similar_package("reqeusts", ["requests", "flask"])
    assert "requests" in result


def test_no_match_returns_empty() -> None:
    """Completely unrelated name returns empty string."""
    result = suggest_similar_package("zzzzzzzzz", ["requests", "flask"])
    assert result == ""


def test_suggest_pypi_known_typo() -> None:
    """Common PyPI typo should be caught."""
    result = suggest_pypi_package("requsets")
    assert "requests" in result


def test_suggest_pypi_no_match() -> None:
    """Gibberish returns empty."""
    result = suggest_pypi_package("xyzzy_nonexistent_pkg_9999")
    assert result == ""


def test_suggest_npm_known_package() -> None:
    """Close npm name should be suggested."""
    result = suggest_npm_package("exress")
    assert "express" in result


def test_suggest_npm_no_match() -> None:
    """Gibberish returns empty for npm."""
    result = suggest_npm_package("xyzzy_nonexistent_pkg_9999")
    assert result == ""


def test_suggest_crates_known_package() -> None:
    """Close crate name should be suggested."""
    result = suggest_crates_package("sered")
    assert "serde" in result


def test_suggest_crates_no_match() -> None:
    """Gibberish returns empty for crates."""
    result = suggest_crates_package("xyzzy_nonexistent_pkg_9999")
    assert result == ""


def test_suggest_go_known_module() -> None:
    """Close Go module should be suggested."""
    result = suggest_go_module("github.com/gin-gonic/gin")
    assert "gin" in result.lower()


def test_suggest_go_no_match() -> None:
    """Gibberish returns empty for Go modules."""
    result = suggest_go_module("xyzzy/nonexistent/module/9999")
    assert result == ""


def test_custom_cutoff() -> None:
    """Higher cutoff is stricter."""
    result = suggest_similar_package("req", ["requests"], cutoff=0.9)
    assert result == ""  # Too short to match at 0.9


def test_max_results_respected() -> None:
    """max_results limits suggestions."""
    result = suggest_similar_package(
        "test", ["test1", "test2", "test3", "test4"], max_results=2,
    )
    # Should have at most 2 suggestions
    if result:
        assert result.count(",") <= 1


def test_case_insensitive_matching() -> None:
    """Matching should be case-insensitive."""
    result = suggest_similar_package("REQUESTS", ["requests"])
    assert "requests" in result
