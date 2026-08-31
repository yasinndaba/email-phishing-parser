from __future__ import annotations

from email.message import Message
from pathlib import Path


SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".com",
    ".msi",
    ".dll",
    ".ps1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
    ".jar",
}

SCRIPT_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
}


def analyze_attachments(email: Message) -> dict:
    """
    Analyze email attachments for potentially dangerous files.

    Returns:
        Dictionary containing attachment details, score, and findings.
    """

    attachments = []
    findings = []
    score = 0

    for part in email.walk():
        filename = part.get_filename()

        if not filename:
            continue

        filename = str(filename)
        extension = Path(filename).suffix.lower()
        content_type = part.get_content_type()
        payload = part.get_payload(decode=True)

        size = len(payload) if payload else 0

        attachment = {
            "filename": filename,
            "extension": extension,
            "mime_type": content_type,
            "size": size,
            "suspicious": False,
            "findings": [],
        }

        if extension in SUSPICIOUS_EXTENSIONS:
            attachment["suspicious"] = True
            attachment["findings"].append(
                f"Suspicious attachment extension detected: {extension}"
            )

            findings.append(
                f"Suspicious attachment extension detected: {filename}"
            )

            score += 30

        if extension in SCRIPT_EXTENSIONS:
            attachment["suspicious"] = True
            attachment["findings"].append(
                f"Script file attachment detected: {extension}"
            )

            findings.append(
                f"Script file attachment detected: {filename}"
            )

            score += 20

        if extension == ".exe":
            attachment["findings"].append(
                "Executable attachment detected."
            )

            findings.append(
                f"Executable attachment detected: {filename}"
            )

            score += 20

        attachments.append(attachment)

    score = min(score, 50)

    return {
        "count": len(attachments),
        "attachments": attachments,
        "score": score,
        "findings": findings,
    }
