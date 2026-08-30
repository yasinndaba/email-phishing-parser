def calculate_risk_score(header_results: dict, url_results: list[dict]) -> dict:
    """
    Calculate an overall phishing risk score from analysis results.

    Args:
        header_results: Results from analyze_headers().
        url_results: Results from analyze_url() for each extracted URL.

    Returns:
        Dictionary containing score, severity, and contributing indicators.
    """

    score = 0
    findings = []

    # -------------------------
    # Email authentication
    # -------------------------

    if header_results.get("spf") == "fail":
        score += 20
        findings.append("SPF authentication failed.")

    if header_results.get("dkim") == "fail":
        score += 20
        findings.append("DKIM authentication failed.")

    if header_results.get("dmarc") == "fail":
        score += 15
        findings.append("DMARC authentication failed.")

    # -------------------------
    # Header mismatches
    # -------------------------

    if header_results.get("reply_to_mismatch"):
        score += 15
        findings.append("Reply-To address differs from sender domain.")

    if header_results.get("return_path_mismatch"):
        score += 10
        findings.append("Return-Path differs from sender domain.")

    # -------------------------
    # URL analysis
    # -------------------------

    for url_result in url_results:

        url_score = url_result.get("score", 0)

        # Limit the contribution of each individual URL.
        score += min(url_score, 30)

        for finding in url_result.get("findings", []):
            findings.append(f"URL: {finding}")

    # Prevent scores above 100
    score = min(score, 100)

    return {
        "score": score,
        "severity": classify_severity(score),
        "findings": findings,
    }


def classify_severity(score: int) -> str:
    """
    Convert a numerical risk score into a severity level.
    """

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 30:
        return "SUSPICIOUS"

    return "LOW"