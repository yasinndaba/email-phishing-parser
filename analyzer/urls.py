import ipaddress
import re
from urllib.parse import urlparse

from rapidfuzz.fuzz import ratio


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


KNOWN_BRANDS = {
    "microsoft": "microsoft.com",
    "paypal": "paypal.com",
    "apple": "apple.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "linkedin": "linkedin.com",
    "facebook": "facebook.com",
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


def normalize_domain_name(domain: str) -> str:
    """
    Normalize a domain name for brand comparison.

    Removes separators and converts common character substitutions
    often used in typosquatting attacks.
    """

    normalized = re.sub(r"[^a-z0-9]", "", domain.lower())

    # Common look-alike substitutions.
    normalized = (
        normalized
        .replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("4", "a")
        .replace("5", "s")
        .replace("7", "t")
    )

    return normalized


def detect_brand_impersonation(hostname: str) -> dict:
    """
    Detect domains that may be impersonating well-known brands.

    Uses normalization, string similarity, and brand-prefix
    detection.

    This is an indicator of possible impersonation and does
    not prove that a domain is malicious.
    """

    hostname = hostname.lower().strip(".")

    if not hostname:
        return {
            "detected": False,
            "brand": None,
            "expected_domain": None,
            "observed_domain": None,
            "similarity": 0,
        }

    domain_parts = hostname.split(".")

    # Extract the registered domain.
    #
    # Example:
    # login.micros0ft-support.com
    # -> micros0ft-support.com
    if len(domain_parts) >= 2:
        registered_domain = ".".join(domain_parts[-2:])
    else:
        registered_domain = hostname

    observed_name = registered_domain.split(".")[0]

    normalized_observed = normalize_domain_name(observed_name)

    for brand, legitimate_domain in KNOWN_BRANDS.items():

        # Never flag the legitimate domain itself.
        if registered_domain == legitimate_domain:
            continue

        legitimate_name = legitimate_domain.split(".")[0]

        normalized_brand = normalize_domain_name(
            legitimate_name
        )

        similarity = ratio(
            normalized_observed,
            normalized_brand,
        )

        # Detect cases such as:
        #
        # micros0ft
        # micr0soft
        # paypa1
        #
        # after normalization.
        exact_normalized_match = (
            normalized_observed == normalized_brand
        )

        # Detect brand + suspicious modifier:
        #
        # microsoftsupport
        # microsoftlogin
        # microsoftsecurity
        #
        # after separators are removed.
        brand_prefix = (
            normalized_observed.startswith(normalized_brand)
            and normalized_observed != normalized_brand
        )

        # Detect domains that are very similar to the brand.
        fuzzy_match = similarity >= 80

        if (
            exact_normalized_match
            or brand_prefix
            or fuzzy_match
        ):
            return {
                "detected": True,
                "brand": brand,
                "expected_domain": legitimate_domain,
                "observed_domain": registered_domain,
                "similarity": similarity,
            }

    return {
        "detected": False,
        "brand": None,
        "expected_domain": None,
        "observed_domain": None,
        "similarity": 0,
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

    # --------------------------------
    # Brand impersonation
    # --------------------------------

    brand_result = detect_brand_impersonation(hostname)

    if brand_result["detected"]:
        findings.append(
            f"Possible {brand_result['brand'].title()} "
            f"brand impersonation detected. "
            f"Observed domain: "
            f"{brand_result['observed_domain']}; "
            f"expected domain: "
            f"{brand_result['expected_domain']}."
        )

        score += 25

    # --------------------------------
    # HTTPS check
    # --------------------------------

    uses_https = parsed.scheme.lower() == "https"

    if not uses_https:
        findings.append(
            "URL does not use HTTPS."
        )

        score += 10

    # --------------------------------
    # IP address check
    # --------------------------------

    is_ip_address = False

    try:
        ipaddress.ip_address(hostname)

        is_ip_address = True

        findings.append(
            "URL uses an IP address instead of "
            "a domain name."
        )

        score += 25

    except ValueError:
        pass

    # --------------------------------
    # Suspicious TLD
    # --------------------------------

    suspicious_tld = any(
        hostname.endswith(tld)
        for tld in SUSPICIOUS_TLDS
    )

    if suspicious_tld:
        findings.append(
            "Domain uses a potentially suspicious TLD."
        )

        score += 15

    # --------------------------------
    # Excessive subdomains
    # --------------------------------

    subdomain_count = 0

    if hostname and not is_ip_address:

        parts = hostname.split(".")

        if len(parts) > 3:

            subdomain_count = len(parts) - 2

            findings.append(
                f"Domain contains "
                f"{subdomain_count} subdomains."
            )

            score += 10

    # --------------------------------
    # URL length
    # --------------------------------

    url_length = len(url)

    if url_length > 100:

        findings.append(
            "URL is unusually long."
        )

        score += 10

    # --------------------------------
    # Suspicious keywords
    # --------------------------------

    lowercase_url = url.lower()

    matched_keywords = sorted(
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in lowercase_url
    )

    if matched_keywords:

        findings.append(
            "URL contains potentially suspicious "
            "keywords: "
            + ", ".join(matched_keywords)
        )

        score += min(
            len(matched_keywords) * 5,
            15,
        )

    # --------------------------------
    # @ symbol
    # --------------------------------

    contains_at_symbol = "@" in parsed.netloc

    if contains_at_symbol:

        findings.append(
            "URL contains '@', which can be used "
            "to obscure the destination."
        )

        score += 20

    # --------------------------------
    # Excessive hyphens
    # --------------------------------

    hyphen_count = hostname.count("-")

    if hyphen_count >= 3:

        findings.append(
            "Domain contains an unusually high "
            "number of hyphens."
        )

        score += 10

    # --------------------------------
    # Percent encoding
    # --------------------------------

    contains_encoding = bool(
        re.search(
            r"%[0-9a-fA-F]{2}",
            url,
        )
    )

    if contains_encoding:

        findings.append(
            "URL contains percent-encoded characters."
        )

        score += 5

    # --------------------------------
    # Final result
    # --------------------------------

    return {
        "url": url,
        "hostname": hostname,
        "uses_https": uses_https,
        "is_ip_address": is_ip_address,
        "brand_impersonation": brand_result,
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