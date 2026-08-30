from analyzer.parser import parse_email
from analyzer.headers import analyze_headers
from analyzer.iocs import extract_iocs
from analyzer.urls import analyze_url
from analyzer.content import analyze_content
from analyzer.scoring import calculate_risk_score


def analyze_email(file_path: str) -> dict:
    """
    Run the complete phishing email analysis pipeline.

    Args:
        file_path: Path to an .eml file.

    Returns:
        Complete analysis results.
    """

    # Step 1: Parse email
    email = parse_email(file_path)

    # Step 2: Analyze headers
    header_results = analyze_headers(email)

    # Step 3: Extract IOCs
    iocs = extract_iocs(email)

    # Step 4: Analyze every extracted URL
    url_results = []

    for url in iocs["urls"]:
        result = analyze_url(url)
        url_results.append(result)

    # Step 5: Analyze email content
    content_results = analyze_content(email["body"])

    # Step 6: Calculate overall risk
    risk_results = calculate_risk_score(
        header_results,
        url_results,
    )

    # Step 7: Add content risk to overall score
    total_score = min(
        risk_results["score"] + content_results["score"],
        100,
    )

    # Recalculate severity using final score
    if total_score >= 80:
        severity = "CRITICAL"
    elif total_score >= 60:
        severity = "HIGH"
    elif total_score >= 30:
        severity = "SUSPICIOUS"
    else:
        severity = "LOW"

    return {
        "email": email,
        "headers": header_results,
        "iocs": iocs,
        "urls": url_results,
        "content": content_results,
        "risk": {
            "score": total_score,
            "severity": severity,
            "findings": (
                risk_results["findings"]
                + content_results["findings"]
            ),
        },
    }