from analyzer.content import analyze_content


def test_phishing_content():
    body = """
    URGENT!

    Your account has been suspended due to suspicious activity.

    Please verify your identity immediately within 24 hours.

    Click here to complete verification.
    """

    result = analyze_content(body)

    assert result["score"] > 0

    assert "urgency" in result["categories"]
    assert "account_threat" in result["categories"]
    assert "credential_request" in result["categories"]
    assert "call_to_action" in result["categories"]
    assert "security_alert" in result["categories"]

    assert len(result["findings"]) >= 5


def test_legitimate_content():
    body = """
    Hello,

    Your monthly newsletter is now available.

    Thank you for subscribing.
    """

    result = analyze_content(body)

    assert result["score"] == 0
    assert result["categories"] == {}
    assert result["findings"] == []


def test_empty_content():
    result = analyze_content("")

    assert result["score"] == 0
    assert result["categories"] == {}
    assert result["findings"] == []