from email import policy
from email.parser import BytesParser
from pathlib import Path


def parse_email(file_path: str) -> dict:
    """
    Parse an .eml file and extract important email information.

    Args:
        file_path: Path to the .eml file.

    Returns:
        Dictionary containing parsed email data.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Email file not found: {file_path}")

    if path.suffix.lower() != ".eml":
        raise ValueError("Only .eml files are supported.")

    with path.open("rb") as email_file:
        message = BytesParser(policy=policy.default).parse(email_file)

    return {
        "from": message.get("From"),
        "to": message.get("To"),
        "cc": message.get("Cc"),
        "subject": message.get("Subject"),
        "date": message.get("Date"),
        "reply_to": message.get("Reply-To"),
        "return_path": message.get("Return-Path"),
        "message_id": message.get("Message-ID"),
        "authentication_results": message.get("Authentication-Results"),
        "received": message.get_all("Received", []),
        "body": extract_body(message),
    }


def extract_body(message) -> str:
    """
    Extract the readable body from an email message.
    """

    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()

            if content_type == "text/plain":
                try:
                    return part.get_content()
                except Exception:
                    continue

        return ""

    try:
        return message.get_content()
    except Exception:
        return ""
