from analyzer.parser import parse_email
from analyzer.headers import analyze_headers
from analyzer.iocs import extract_iocs
from analyzer.urls import analyze_url
from analyzer.content import analyze_content
from analyzer.scoring import calculate_risk_score


def analyze_email(file_path: str) -> dict:
    """
    Run the complete phishing email analysis pipeline.
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

    # Analyze content
    content_results = analyze_content(email["body"])

    # Calculate header + URL risk
    risk_results = calculate_risk_score(
        header_results,
        url_results,
    )

    # Calculate component scores
    header_score = risk_results["score"]

    url_score = sum(
        result["score"]
        for result in url_results
    )

    content_score = content_results["score"]

    raw_score = (
        header_score
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