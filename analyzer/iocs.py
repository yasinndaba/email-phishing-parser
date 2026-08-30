import re
from urllib.parse import urlparse


# Basic patterns for common IOC types
URL_PATTERN = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE,
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

IP_PATTERN = re.compile(
    r"\b(?:"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\."
    r"){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)


def extract_iocs(email_data: dict) -> dict:
    """
    Extract URLs, domains, email addresses and IPv4 addresses
    from parsed email data.

    Args:
        email_data: Dictionary returned by parse_email().

    Returns:
        Dictionary containing extracted IOCs.
    """

    # Combine relevant email content
    headers = [
        email_data.get("from") or "",
        email_data.get("to") or "",
        email_data.get("cc") or "",
        email_data.get("reply_to") or "",
        email_data.get("return_path") or "",
        email_data.get("subject") or "",
    ]

    received_headers = email_data.get("received") or []

    content = "\n".join(headers + received_headers)
    content += "\n" + (email_data.get("body") or "")

    # Extract URLs
    urls = extract_urls(content)

    # Extract email addresses
    email_addresses = sorted(
        set(EMAIL_PATTERN.findall(content)),
        key=str.lower,
    )

    # Extract IPv4 addresses
    ip_addresses = sorted(
        set(IP_PATTERN.findall(content)),
    )

    # Extract domains from URLs
    domains = extract_domains(urls)

    return {
        "urls": urls,
        "domains": domains,
        "email_addresses": email_addresses,
        "ip_addresses": ip_addresses,
    }


def extract_urls(content: str) -> list[str]:
    """
    Extract and clean URLs from text.
    """

    urls = []

    for match in URL_PATTERN.findall(content):
        # Remove common punctuation that may follow a URL
        url = match.rstrip(".,!?;:)")

        if url not in urls:
            urls.append(url)

    return urls


def extract_domains(urls: list[str]) -> list[str]:
    """
    Extract unique hostnames/domains from URLs.
    """

    domains = set()

    for url in urls:
        try:
            parsed = urlparse(url)

            if parsed.hostname:
                domains.add(parsed.hostname.lower())

        except ValueError:
            continue

    return sorted(domains)