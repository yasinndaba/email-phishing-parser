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

MACRO_EXTENSIONS = {
    ".docm",
    ".dotm",
    ".xlsm",
    ".xltm",
    ".xlam",
    ".pptm",
    ".potm",
    ".ppsm",
    ".ppam",
}

OFFICE_EXTENSIONS = {
    ".doc",
    ".docx",
    ".docm",
    ".dot",
    ".dotx",
    ".dotm",
    ".xls",
    ".xlsx",
    ".xlsm",
    ".xlt",
    ".xltx",
    ".xltm",
    ".ppt",
    ".pptx",
    ".pptm",
    ".pot",
    ".potx",
    ".potm",
    ".pps",
    ".ppsm",
    ".ppa",
    ".ppam",
}

DOCUMENT_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".docm",
    ".xls",
    ".xlsx",
    ".xlsm",
    ".ppt",
    ".pptx",
    ".pptm",
    ".txt",
}

MIME_EXTENSION_MAP = {
    "application/pdf": {".pdf"},
    "text/plain": {".txt"},
    "application/msword": {".doc"},
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {
        ".docx"
    },
    "application/vnd.ms-excel": {".xls"},
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {
        ".xlsx"
    },
    "application/vnd.ms-powerpoint": {".ppt"},
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": {
        ".pptx"
    },
    "application/x-msdownload": {".exe"},
    "application/x-msdos-program": {".exe", ".com"},
}


def _extract_attachment_data(email: Message | dict) -> list[dict]:
    """
    Extract normalized attachment metadata from either an
    email.message.Message object or a parsed email dictionary.
    """

    if isinstance(email, Message):
        attachment_data = []

        for part in email.walk():
            filename = part.get_filename()

            if not filename:
                continue

            payload = part.get_payload(decode=True)
            size = len(payload) if payload else 0

            attachment_data.append(
                {
                    "filename": str(filename),
                    "mime_type": part.get_content_type(),
                    "size": size,
                }
            )

        return attachment_data

    if isinstance(email, dict):
        return email.get("attachments", [])

    raise TypeError(
        "analyze_attachments() expects an "
        "email.message.Message or parsed email dictionary."
    )


def _detect_double_extension(filename: str) -> bool:
    """
    Detect filenames such as:

        invoice.pdf.exe
        document.docx.js
        photo.jpg.scr

    where a normal-looking document/image extension appears
    before a potentially dangerous final extension.
    """

    suffixes = Path(filename).suffixes

    if len(suffixes) < 2:
        return False

    final_extension = suffixes[-1].lower()

    previous_extensions = {
        extension.lower()
        for extension in suffixes[:-1]
    }

    return (
        final_extension in SUSPICIOUS_EXTENSIONS
        and bool(
            previous_extensions
            & DOCUMENT_EXTENSIONS
        )
    )


def _mime_extension_mismatch(
    extension: str,
    mime_type: str,
) -> bool:
    """
    Detect cases where the MIME type claims one file type
    but the filename uses another extension.
    """

    expected_extensions = MIME_EXTENSION_MAP.get(
        mime_type.lower()
    )

    if not expected_extensions:
        return False

    return extension not in expected_extensions


def analyze_attachments(email: Message | dict) -> dict:
    """
    Analyze email attachments for potentially dangerous files.

    Detection includes:

    - Suspicious executable/script extensions
    - Macro-enabled Office documents
    - Double-extension evasion
    - MIME type / extension mismatch
    - Executable attachments

    Returns:
        Dictionary containing attachment details,
        score, and findings.
    """

    attachment_data = _extract_attachment_data(email)

    attachments = []
    findings = []
    score = 0

    for item in attachment_data:
        filename = str(
            item.get("filename", "")
        )

        extension = Path(
            filename
        ).suffix.lower()

        mime_type = str(
            item.get(
                "mime_type",
                "application/octet-stream",
            )
        )

        size = item.get(
            "size",
            0,
        )

        attachment = {
            "filename": filename,
            "extension": extension,
            "mime_type": mime_type,
            "size": size,
            "suspicious": False,
            "findings": [],
        }

        # -----------------------------------------------------
        # Suspicious extension
        # -----------------------------------------------------

        if extension in SUSPICIOUS_EXTENSIONS:
            attachment["suspicious"] = True

            attachment["findings"].append(
                f"Suspicious attachment extension detected: {extension}"
            )

            findings.append(
                f"Suspicious attachment extension detected: {filename}"
            )

            score += 30

        # -----------------------------------------------------
        # Script file
        # -----------------------------------------------------

        if extension in SCRIPT_EXTENSIONS:
            attachment["suspicious"] = True

            attachment["findings"].append(
                f"Script file attachment detected: {extension}"
            )

            findings.append(
                f"Script file attachment detected: {filename}"
            )

            score += 20

        # -----------------------------------------------------
        # Executable file
        # -----------------------------------------------------

        if extension == ".exe":
            attachment["suspicious"] = True

            attachment["findings"].append(
                "Executable attachment detected."
            )

            findings.append(
                f"Executable attachment detected: {filename}"
            )

            score += 20

        # -----------------------------------------------------
        # Macro-enabled Office document
        # -----------------------------------------------------

        if extension in MACRO_EXTENSIONS:
            attachment["suspicious"] = True

            attachment["findings"].append(
                f"Macro-enabled Office attachment detected: {extension}"
            )

            findings.append(
                f"Macro-enabled Office attachment detected: {filename}"
            )

            score += 20

        # -----------------------------------------------------
        # Double-extension evasion
        # -----------------------------------------------------

        if _detect_double_extension(filename):
            attachment["suspicious"] = True

            attachment["findings"].append(
                "Potential double-extension filename evasion detected."
            )

            findings.append(
                f"Potential double-extension filename evasion detected: "
                f"{filename}"
            )

            score += 20

        # -----------------------------------------------------
        # MIME type / extension mismatch
        # -----------------------------------------------------

        if _mime_extension_mismatch(
            extension,
            mime_type,
        ):
            attachment["suspicious"] = True

            attachment["findings"].append(
                "Attachment MIME type does not match filename extension."
            )

            findings.append(
                f"MIME type/extension mismatch detected: "
                f"{filename} ({mime_type})"
            )

            score += 15

        attachments.append(
            attachment
        )

    # ---------------------------------------------------------
    # Cap attachment analyzer score
    # ---------------------------------------------------------

    score = min(
        score,
        50,
    )

    return {
        "count": len(attachments),
        "attachments": attachments,
        "score": score,
        "findings": findings,
    }
