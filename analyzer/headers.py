import re
from email.utils import parseaddr


def analyze_headers(email_data: dict) -> dict:
    """
    Analyze email headers for common phishing indicators.

    Args:
        email_data: Parsed email data returned by parser.parse_email()

    Returns:
        Dictionary containing header analysis results and findings.
    """

    findings = []

    sender = email_data.get("from") or ""
    reply_to = email_data.get("reply_to") or ""
    return_path = email_data.get("return_path") or ""
    authentication_results = email_data.get("authentication_results") or ""

    # Extract actual email addresses
    sender_address = parseaddr(sender)[1].lower()
    reply_to_address = parseaddr(reply_to)[1].lower()
    return_path_address = parseaddr(return_path)[1].lower()

    # Check Reply-To mismatch
    reply_to_mismatch = False

    if sender_address and reply_to_address:
        sender_domain = sender_address.split("@")[-1]
        reply_to_domain = reply_to_address.split("@")[-1]

        if sender_domain != reply_to_domain:
            reply_to_mismatch = True
            findings.append(
                f"Reply-To domain differs from sender domain: "
                f"{sender_domain} -> {reply_to_domain}"
            )

    # Check Return-Path mismatch
    return_path_mismatch = False

    if sender_address and return_path_address:
        sender_domain = sender_address.split("@")[-1]
        return_path_domain = return_path_address.split("@")[-1]

        if sender_domain != return_path_domain:
            return_path_mismatch = True
            findings.append(
                f"Return-Path domain differs from sender domain: "
                f"{sender_domain} -> {return_path_domain}"
            )

    # Analyze SPF, DKIM and DMARC
    spf_result = extract_auth_result(authentication_results, "spf")
    dkim_result = extract_auth_result(authentication_results, "dkim")
    dmarc_result = extract_auth_result(authentication_results, "dmarc")

    if spf_result == "fail":
        findings.append("SPF authentication failed.")

    if dkim_result == "fail":
        findings.append("DKIM authentication failed.")

    if dmarc_result == "fail":
        findings.append("DMARC authentication failed.")

    return {
        "sender": sender_address,
        "reply_to": reply_to_address,
        "return_path": return_path_address,
        "spf": spf_result,
        "dkim": dkim_result,
        "dmarc": dmarc_result,
        "reply_to_mismatch": reply_to_mismatch,
        "return_path_mismatch": return_path_mismatch,
        "findings": findings,
    }


def extract_auth_result(authentication_results: str, mechanism: str) -> str:
    """
    Extract SPF, DKIM or DMARC authentication result.

    Example:
        spf=fail
        dkim=pass
        dmarc=none
    """

    pattern = rf"\b{mechanism}\s*=\s*([a-zA-Z]+)"
    match = re.search(pattern, authentication_results, re.IGNORECASE)

    if match:
        return match.group(1).lower()

    return "unknown"