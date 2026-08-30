def calculate_header_score(header_results: dict) -> tuple[int, list[str]]:
    """
    Calculate the header component of the phishing risk score.

    Maximum: 40 points.
    """

    score = 0
    findings = []

    # Email authentication
    if header_results.get("spf") == "fail":
        score += 10
        findings.append("SPF authentication failed.")

    if header_results.get("dkim") == "fail":
        score += 10
        findings.append("DKIM authentication failed.")

    if header_results.get("dmarc") == "fail":
        score += 10
        findings.append("DMARC authentication failed.")

    # Header mismatches
    if header_results.get("reply_to_mismatch"):
        score += 5
        findings.append(
            "Reply-To address differs from sender domain."
        )

    if header_results.get("return_path_mismatch"):
        score += 5
        findings.append(
            "Return-Path differs from sender domain."
        )

    return min(score, 40), findings


def calculate_url_score(
    url_results: list[dict],
) -> tuple[int, list[str]]:
    """
    Calculate the URL component of the phishing risk score.

    Maximum: 30 points.
    """

    score = 0
    findings = []

    for url_result in url_results:
        url_score = url_result.get("score", 0)

        score += min(url_score, 30)

        for finding in url_result.get("findings", []):
            findings.append(f"URL: {finding}")

    return min(score, 30), findings


def calculate_risk_score(
    header_results: dict,
    url_results: list[dict],
    content_score: int = 0,
    content_findings: list[str] | None = None,
) -> dict:
    """
    Calculate the overall phishing risk score.

    Scoring model:

        Headers: 0-40
        URLs:    0-30
        Content: 0-30
        Total:   0-100
    """

    if content_findings is None:
        content_findings = []

    header_score, header_findings = calculate_header_score(
        header_results
    )

    url_score, url_findings = calculate_url_score(
        url_results
    )

    content_score = min(max(content_score, 0), 30)

    total_score = (
        header_score
        + url_score
        + content_score
    )

    total_score = min(total_score, 100)

    findings = (
        header_findings
        + url_findings
        + content_findings
    )

    return {
        "score": total_score,
        "severity": classify_severity(total_score),
        "findings": findings,
        "breakdown": {
            "header": header_score,
            "url": url_score,
            "content": content_score,
        },
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