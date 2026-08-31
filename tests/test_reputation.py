from analyzer.reputation import (
    resolve_domain,
    analyze_domain,
    analyze_url_reputation,
    calculate_reputation_score,
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
    result = analyze_domain(
        "localhost",
        check_reputation=False,
    )

    assert result["domain"] == "localhost"
    assert "dns" in result
    assert "reputation" in result
    assert "findings" in result
    assert "score" in result


def test_analyze_url_reputation():
    result = analyze_url_reputation(
        "https://example.com/login",
        check_reputation=False,
    )

    assert result["hostname"] == "example.com"
    assert "domain_analysis" in result


def test_reputation_score_no_detections():
    result = {
        "available": True,
        "malicious": 0,
        "suspicious": 0,
    }

    assert calculate_reputation_score(result) == 0


def test_reputation_score_malicious():
    result = {
        "available": True,
        "malicious": 5,
        "suspicious": 0,
    }

    assert calculate_reputation_score(result) == 15


def test_reputation_score_suspicious():
    result = {
        "available": True,
        "malicious": 0,
        "suspicious": 5,
    }

    assert calculate_reputation_score(result) == 5


def test_reputation_score_is_capped():
    result = {
        "available": True,
        "malicious": 100,
        "suspicious": 100,
    }

    assert calculate_reputation_score(result) == 30


def test_unavailable_reputation_has_zero_score():
    result = {
        "available": False,
        "malicious": 100,
        "suspicious": 100,
    }

    assert calculate_reputation_score(result) == 0