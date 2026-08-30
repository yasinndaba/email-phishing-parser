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

    result = calculate_risk_score(
        headers,
        urls,
        content_score=30,
    )

    assert result["score"] == 100
    assert result["severity"] == "CRITICAL"

    assert result["breakdown"]["header"] == 40
    assert result["breakdown"]["url"] == 30
    assert result["breakdown"]["content"] == 30


def test_low_score():
    headers = {
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
        "reply_to_mismatch": False,
        "return_path_mismatch": False,
    }

    urls = []

    result = calculate_risk_score(
        headers,
        urls,
        content_score=0,
    )

    assert result["score"] == 0
    assert result["severity"] == "LOW"


def test_severity_boundaries():
    headers = {
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
        "reply_to_mismatch": False,
        "return_path_mismatch": False,
    }

    urls = []

    # 0-29 = LOW
    result = calculate_risk_score(
        headers,
        urls,
        content_score=29,
    )

    assert result["score"] == 29
    assert result["severity"] == "LOW"

    # 30 = SUSPICIOUS
    result = calculate_risk_score(
        headers,
        urls,
        content_score=30,
    )

    assert result["score"] == 30
    assert result["severity"] == "SUSPICIOUS"

    # Add 20 header points.
    headers["spf"] = "fail"
    headers["dkim"] = "fail"

    # 50 = SUSPICIOUS
    result = calculate_risk_score(
        headers,
        urls,
        content_score=30,
    )

    assert result["score"] == 50
    assert result["severity"] == "SUSPICIOUS"

    # Add 10 URL points.
    urls = [
        {
            "score": 10,
            "findings": [],
        }
    ]

    # 60 = HIGH
    result = calculate_risk_score(
        headers,
        urls,
        content_score=30,
    )

    assert result["score"] == 60
    assert result["severity"] == "HIGH"

    # Add remaining header risk and URL risk.
    headers["dmarc"] = "fail"
    headers["reply_to_mismatch"] = True

    urls = [
        {
            "score": 30,
            "findings": [],
        }
    ]

    # Header = 35
    # URL = 30
    # Content = 30
    # Total = 95
    result = calculate_risk_score(
        headers,
        urls,
        content_score=30,
    )

    assert result["score"] == 95
    assert result["severity"] == "CRITICAL"


def test_score_breakdown():
    headers = {
        "spf": "fail",
        "dkim": "pass",
        "dmarc": "pass",
        "reply_to_mismatch": False,
        "return_path_mismatch": False,
    }

    urls = [
        {
            "score": 15,
            "findings": [
                "Suspicious URL detected."
            ],
        }
    ]

    result = calculate_risk_score(
        headers,
        urls,
        content_score=20,
    )

    assert result["breakdown"]["header"] == 10
    assert result["breakdown"]["url"] == 15
    assert result["breakdown"]["content"] == 20

    assert result["score"] == 45
    assert result["severity"] == "SUSPICIOUS"


def test_header_score_is_capped():
    headers = {
        "spf": "fail",
        "dkim": "fail",
        "dmarc": "fail",
        "reply_to_mismatch": True,
        "return_path_mismatch": True,
    }

    urls = []

    result = calculate_risk_score(
        headers,
        urls,
        content_score=0,
    )

    assert result["breakdown"]["header"] == 40
    assert result["score"] == 40


def test_url_score_is_capped():
    headers = {
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
        "reply_to_mismatch": False,
        "return_path_mismatch": False,
    }

    urls = [
        {
            "score": 100,
            "findings": [],
        }
    ]

    result = calculate_risk_score(
        headers,
        urls,
        content_score=0,
    )

    assert result["breakdown"]["url"] == 30
    assert result["score"] == 30


def test_content_score_is_capped():
    headers = {
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
        "reply_to_mismatch": False,
        "return_path_mismatch": False,
    }

    urls = []

    result = calculate_risk_score(
        headers,
        urls,
        content_score=100,
    )

    assert result["breakdown"]["content"] == 30
    assert result["score"] == 30


def test_classify_severity():
    assert classify_severity(0) == "LOW"
    assert classify_severity(29) == "LOW"
    assert classify_severity(30) == "SUSPICIOUS"
    assert classify_severity(59) == "SUSPICIOUS"
    assert classify_severity(60) == "HIGH"
    assert classify_severity(79) == "HIGH"
    assert classify_severity(80) == "CRITICAL"
    assert classify_severity(100) == "CRITICAL"