from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

from analyzer.attachments import analyze_attachments


def load_email(path):
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def build_attachment_email(
    filename: str,
    mime_type: str = "application/octet-stream",
):
    email = EmailMessage()

    email["From"] = "attacker@example.com"
    email["To"] = "analyst@example.com"
    email["Subject"] = "Test Attachment"

    email.set_content(
        "Please review the attached document."
    )

    email.add_attachment(
        b"test attachment content",
        maintype=mime_type.split("/")[0],
        subtype=mime_type.split("/")[1],
        filename=filename,
    )

    return email


def test_executable_attachment():
    email = load_email(
        "samples/attachment_phishing.eml"
    )

    result = analyze_attachments(email)

    assert result["count"] == 1

    attachment = result["attachments"][0]

    assert attachment["filename"] == "invoice.exe"
    assert attachment["extension"] == ".exe"
    assert attachment["suspicious"] is True
    assert attachment["mime_type"] == "application/octet-stream"
    assert attachment["size"] > 0
    assert result["score"] > 0


def test_executable_attachment_detection():
    email = load_email(
        "samples/attachment_phishing.eml"
    )

    result = analyze_attachments(email)

    assert any(
        "Executable attachment detected"
        in finding
        for finding in result["findings"]
    )


def test_suspicious_extension_detection():
    email = load_email(
        "samples/attachment_phishing.eml"
    )

    result = analyze_attachments(email)

    assert any(
        "Suspicious attachment extension detected"
        in finding
        for finding in result["findings"]
    )


def test_double_extension_detection():
    email = build_attachment_email(
        "invoice.pdf.exe"
    )

    result = analyze_attachments(email)

    attachment = result["attachments"][0]

    assert attachment["suspicious"] is True

    assert any(
        "double-extension"
        in finding.lower()
        for finding in result["findings"]
    )


def test_macro_enabled_document_detection():
    email = build_attachment_email(
        "invoice.docm"
    )

    result = analyze_attachments(email)

    attachment = result["attachments"][0]

    assert attachment["suspicious"] is True

    assert any(
        "Macro-enabled Office attachment"
        in finding
        for finding in result["findings"]
    )


def test_mime_extension_mismatch_detection():
    email = build_attachment_email(
        "invoice.exe",
        "application/pdf",
    )

    result = analyze_attachments(email)

    attachment = result["attachments"][0]

    assert attachment["suspicious"] is True

    assert any(
        "MIME type/extension mismatch"
        in finding
        for finding in result["findings"]
    )


def test_attachment_score_is_capped():
    email = load_email(
        "samples/attachment_phishing.eml"
    )

    result = analyze_attachments(email)

    assert result["score"] <= 50


def test_no_attachment():
    email = load_email(
        "samples/legitimate_email.eml"
    )

    result = analyze_attachments(email)

    assert result["count"] == 0
    assert result["attachments"] == []
    assert result["score"] == 0
    assert result["findings"] == []
