from analyzer.scoring import calculate_risk_score, classify_severity


def test_critical_score():
    headers = {
        "spf": "fail",
        "dkim": "fail",
        "dmarc": "fail",
        "reply_to_mismatch": True,
        "return_path_mismatch": True,
    }

    urls = [
        {
            "score": 30,
            "findings": [
                "Possible Microsoft brand impersonation detected."
            ],
        }
    ]

    result = calculate_risk_score(headers, urls)

    assert result["score"] == 100
    assert result["severity"] == "CRITICAL"


def test_low_score():
    headers = {
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
        "reply_to_mismatch": False,
        "return_path_mismatch": False,
    }

    urls = [
        {
            "score": 0,
            "findings": [],
        }
    ]

    result = calculate_risk_score(headers, urls)

    assert result["score"] == 0
    assert result["severity"] == "LOW"


def test_severity_boundaries():
    assert classify_severity(0) == "LOW"
    assert classify_severity(29) == "LOW"

    assert classify_severity(30) == "SUSPICIOUS"
    assert classify_severity(59) == "SUSPICIOUS"

    assert classify_severity(60) == "HIGH"
    assert classify_severity(79) == "HIGH"

    assert classify_severity(80) == "CRITICAL"
    assert classify_severity(100) == "CRITICAL"