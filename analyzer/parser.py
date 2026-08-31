from email import policy
from email.parser import BytesParser
from pathlib import Path


def parse_email(file_path: str) -> dict:
    """
    Parse an .eml file and extract important email information.

    Args:
        file_path: Path to the .eml file.

    Returns:
        Dictionary containing parsed email data and attachment metadata.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Email file not found: {file_path}"
        )

    if path.suffix.lower() != ".eml":
        raise ValueError(
            "Only .eml files are supported."
        )

    with path.open("rb") as email_file:
        message = BytesParser(
            policy=policy.default
        ).parse(email_file)

    return {
        "from": message.get("From"),
        "to": message.get("To"),
        "cc": message.get("Cc"),
        "subject": message.get("Subject"),
        "date": message.get("Date"),
        "reply_to": message.get("Reply-To"),
        "return_path": message.get("Return-Path"),
        "message_id": message.get("Message-ID"),
        "authentication_results": message.get(
            "Authentication-Results"
        ),
        "received": message.get_all(
            "Received",
            [],
        ),
        "body": extract_body(message),
        "attachments": extract_attachments(message),
    }


def extract_body(message) -> str:
    """
    Extract the readable body from an email message.
    """

    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()

            if content_type != "text/plain":
                continue

            try:
                return part.get_content()
            except Exception:
                continue

        return ""

    try:
        return message.get_content()
    except Exception:
        return ""


def extract_attachments(message) -> list:
    """
    Extract metadata about email attachments.

    The actual attachment contents are not written to disk.
    Only metadata required for analysis is returned.
    """

    attachments = []

    for part in message.walk():
        filename = part.get_filename()

        if not filename:
            continue

        filename = str(filename)

        payload = part.get_payload(
            decode=True
        )

        size = len(payload) if payload else 0

        attachments.append(
            {
                "filename": filename,
                "mime_type": part.get_content_type(),
                "size": size,
            }
        )

    return attachments