from analyzer.parser import parse_email
from analyzer.headers import analyze_headers
from analyzer.iocs import extract_iocs
from analyzer.urls import analyze_url
from analyzer.content import analyze_content
from analyzer.scoring import calculate_risk_score


def analyze_email(file_path: str) -> dict:
    """
    Run the complete phishing email analysis pipeline.

    The analysis consists of:
    - Email parsing
    - Header authentication analysis
    - IOC extraction
    - URL analysis
    - Email content analysis
    - Risk scoring
    """

    # Parse email
    email = parse_email(file_path)

    # Analyze headers
    header_results = analyze_headers(email)

    # Extract IOCs
    iocs = extract_iocs(email)

    # Analyze URLs
    url_results = []

    for url in iocs["urls"]:
        url_results.append(analyze_url(url))

    # Analyze email content
    content_results = analyze_content(email["body"])

    # Calculate individual component scores
    #
    # Header score is calculated separately from URL score.
    # This prevents the URL score from being counted twice.
    header_score = 0

    if header_results.get("spf") == "fail":
        header_score += 20

    if header_results.get("dkim") == "fail":
        header_score += 20

    if header_results.get("dmarc") == "fail":
        header_score += 15

    if header_results.get("reply_to_mismatch"):
        header_score += 15

    if header_results.get("return_path_mismatch"):
        header_score += 10

    # Header contribution is capped at 40 points.
    header_score = min(header_score, 40)

    # Calculate URL score.
    #
    # Each individual URL can contribute up to 30 points.
    # The total URL contribution is capped at 30.
    url_score = sum(
        min(result.get("score", 0), 30)
        for result in url_results
    )

    url_score = min(url_score, 30)

    # Content score is capped at 30.
    content_score = min(
        content_results.get("score", 0),
        30,
    )

    # Calculate final score.
    raw_score = (
        header_score
        + url_score
        + content_score
    )

    final_score = min(raw_score, 100)

    # Determine severity
    if final_score >= 80:
        severity = "CRITICAL"
    elif final_score >= 60:
        severity = "HIGH"
    elif final_score >= 30:
        severity = "SUSPICIOUS"
    else:
        severity = "LOW"

    # Generate risk findings.
    #
    # calculate_risk_score() is still used here to generate
    # authentication/header and URL findings.
    risk_results = calculate_risk_score(
        header_results,
        url_results,
        content_score=content_score,
    )

    # Combine findings
    findings = (
        risk_results["findings"]
        + content_results["findings"]
    )

    return {
        "email": email,
        "headers": header_results,
        "iocs": iocs,
        "urls": url_results,
        "content": content_results,
        "risk": {
            "score": final_score,
            "raw_score": raw_score,
            "severity": severity,
            "breakdown": {
                "header": header_score,
                "url": url_score,
                "content": content_score,
            },
            "findings": findings,
        },
    }