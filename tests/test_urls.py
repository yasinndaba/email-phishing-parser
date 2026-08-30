from analyzer.urls import analyze_url


def test_suspicious_url():
    url = "https://micros0ft-support.com/verify"

    result = analyze_url(url)

    assert result["hostname"] == "micros0ft-support.com"
    assert result["uses_https"] is True
    assert result["is_ip_address"] is False

    assert "verify" in result["matched_keywords"]
    assert result["score"] > 0
    assert len(result["findings"]) > 0


def test_ip_based_url():
    url = "http://192.168.1.100/login"

    result = analyze_url(url)

    assert result["uses_https"] is False
    assert result["is_ip_address"] is True
    assert result["score"] > 0


def test_legitimate_style_url():
    url = "https://example.com/about"

    result = analyze_url(url)

    assert result["uses_https"] is True
    assert result["is_ip_address"] is False
    assert result["score"] == 0