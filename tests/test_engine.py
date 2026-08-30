from analyzer.engine import analyze_email


def test_complete_email_analysis():
    result = analyze_email("samples/test_email.eml")

    assert result["email"]["subject"] == (
        "URGENT: Your Microsoft 365 account will be suspended"
    )

    assert result["headers"]["spf"] == "fail"
    assert result["headers"]["dkim"] == "fail"
    assert result["headers"]["dmarc"] == "fail"

    assert len(result["iocs"]["urls"]) == 1
    assert "micros0ft-support.com" in result["iocs"]["domains"]

    assert len(result["urls"]) == 1
    assert result["urls"][0]["brand_impersonation"]["detected"] is True

    assert result["content"]["score"] > 0

    assert result["risk"]["score"] > 0
    assert result["risk"]["severity"] in {
        "LOW",
        "SUSPICIOUS",
        "HIGH",
        "CRITICAL",
    }