import ipaddress
import re
from urllib.parse import urlparse


SUSPICIOUS_TLDS = {
    ".zip",
    ".mov",
    ".click",
    ".download",
    ".work",
    ".country",
    ".gq",
    ".tk",
    ".top",
    ".xyz",
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "password",
    "credential",
    "secure",
    "security",
    "update",
    "confirm",
    "authenticate",
    "microsoft",
    "paypal",
    "apple",
    "bank",
}


def analyze_url(url: str) -> dict:
    """
    Analyze a URL for characteristics commonly associated
    with phishing URLs.

    This function does not determine whether a URL is
    definitively malicious.
    """

    findings = []
    score = 0

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    hostname = hostname.lower()

    # Check HTTPS
    uses_https = parsed.scheme.lower() == "https"

    if not uses_https:
        findings.append("URL does not use HTTPS.")
        score += 10

    # Check whether hostname is an IP address
    is_ip_address = False

    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
        findings.append("URL uses an IP address instead of a domain name.")
        score += 25
    except ValueError:
        pass

    # Check suspicious TLD
    suspicious_tld = any(
        hostname.endswith(tld)
        for tld in SUSPICIOUS_TLDS
    )

    if suspicious_tld:
        findings.append("Domain uses a potentially suspicious TLD.")
        score += 15

    # Check excessive subdomains
    subdomain_count = 0

    if hostname and not is_ip_address:
        parts = hostname.split(".")

        if len(parts) > 3:
            subdomain_count = len(parts) - 2
            findings.append(
                f"Domain contains {subdomain_count} subdomains."
            )
            score += 10

    # Check URL length
    url_length = len(url)

    if url_length > 100:
        findings.append("URL is unusually long.")
        score += 10

    # Check suspicious keywords
    lowercase_url = url.lower()

    matched_keywords = sorted(
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in lowercase_url
    )

    if matched_keywords:
        findings.append(
            "URL contains potentially suspicious keywords: "
            + ", ".join(matched_keywords)
        )
        score += min(len(matched_keywords) * 5, 15)

    # Check @ symbol
    contains_at_symbol = "@" in parsed.netloc

    if contains_at_symbol:
        findings.append(
            "URL contains '@', which can be used to obscure the destination."
        )
        score += 20

    # Check excessive hyphens
    hyphen_count = hostname.count("-")

    if hyphen_count >= 3:
        findings.append(
            "Domain contains an unusually high number of hyphens."
        )
        score += 10

    # Check encoded characters
    contains_encoding = bool(re.search(r"%[0-9a-fA-F]{2}", url))

    if contains_encoding:
        findings.append("URL contains percent-encoded characters.")
        score += 5

    return {
        "url": url,
        "hostname": hostname,
        "uses_https": uses_https,
        "is_ip_address": is_ip_address,
        "suspicious_tld": suspicious_tld,
        "subdomain_count": subdomain_count,
        "url_length": url_length,
        "matched_keywords": matched_keywords,
        "contains_at_symbol": contains_at_symbol,
        "hyphen_count": hyphen_count,
        "contains_encoding": contains_encoding,
        "score": min(score, 100),
        "findings": findings,
    }