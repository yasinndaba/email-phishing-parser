from analyzer.reputation import (
    resolve_domain,
    analyze_domain,
    analyze_url_reputation,
)


def test_resolve_localhost():
    result = resolve_domain("localhost")

    assert result["domain"] == "localhost"
    assert result["resolved"] is True
    assert len(result["ips"]) >= 1


def test_empty_domain():
    result = resolve_domain("")

    assert result["resolved"] is False
    assert result["ips"] == []
    assert result["error"] is not None


def test_analyze_domain():
    result = analyze_domain("localhost")

    assert result["domain"] == "localhost"
    assert "dns" in result
    assert "reputation" in result
    assert "findings" in result
    assert "score" in result


def test_analyze_url_reputation():
    result = analyze_url_reputation(
        "https://example.com/login"
    )

    assert result["hostname"] == "example.com"
    assert "domain_analysis" in result