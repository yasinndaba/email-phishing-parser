from email import policy
from email.parser import BytesParser

from analyzer.attachments import analyze_attachments


def load_email(path):
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def test_executable_attachment():
    email = load_email("samples/attachment_phishing.eml")

    result = analyze_attachments(email)

    assert result["count"] == 1
    assert result["attachments"][0]["filename"] == "invoice.exe"
    assert result["attachments"][0]["extension"] == ".exe"
    assert result["attachments"][0]["suspicious"] is True
    assert result["score"] > 0


def test_executable_attachment_detection():
    email = load_email("samples/attachment_phishing.eml")

    result = analyze_attachments(email)

    assert any(
        "Executable attachment detected" in finding
        for finding in result["findings"]
    )


def test_no_attachment():
    email = load_email("samples/legitimate_email.eml")

    result = analyze_attachments(email)

    assert result["count"] == 0
    assert result["attachments"] == []
    assert result["score"] == 0
    assert result["findings"] == []
