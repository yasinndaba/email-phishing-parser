from analyzer.parser import parse_email
from analyzer.headers import analyze_headers
from analyzer.iocs import extract_iocs
from analyzer.urls import analyze_url
from analyzer.content import analyze_content
from analyzer.attachments import analyze_attachments
from analyzer.html_analysis import analyze_html
from analyzer.scoring import calculate_risk_score


def analyze_email(file_path: str) -> dict:
    """
    Run the complete phishing email analysis pipeline.

    Analysis includes:
    - Email parsing
    - Header authentication analysis
    - IOC extraction
    - URL analysis
    - HTML analysis
    - Email content analysis
    - Attachment analysis
    - Risk scoring
    """

    # ---------------------------------------------------------
    # Parse email
    # ---------------------------------------------------------

    email = parse_email(file_path)

    # ---------------------------------------------------------
    # Header analysis
    # ---------------------------------------------------------

    header_results = analyze_headers(email)

    # ---------------------------------------------------------
    # IOC extraction
    # ---------------------------------------------------------

    iocs = extract_iocs(email)

    # ---------------------------------------------------------
    # URL analysis
    # ---------------------------------------------------------

    url_results = []

    for url in iocs["urls"]:
        url_results.append(
            analyze_url(url)
        )

    # ---------------------------------------------------------
    # Content analysis
    # ---------------------------------------------------------

    content_results = analyze_content(
        email["body"]
    )

    # ---------------------------------------------------------
    # Attachment analysis
    # ---------------------------------------------------------

    attachment_results = analyze_attachments(
        email
    )

    # ---------------------------------------------------------
    # HTML analysis
    # ---------------------------------------------------------

    html_results = analyze_html(
        email["body"]
    )

    # ---------------------------------------------------------
    # Header score
    # ---------------------------------------------------------

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

    header_score = min(
        header_score,
        40,
    )

    # ---------------------------------------------------------
    # URL score
    # ---------------------------------------------------------

    url_score = sum(
        min(
            result.get("score", 0),
            30,
        )
        for result in url_results
    )

    url_score = min(
        url_score,
        30,
    )

    # ---------------------------------------------------------
    # Content score
    # ---------------------------------------------------------

    content_score = min(
        content_results.get("score", 0),
        30,
    )

    # ---------------------------------------------------------
    # Attachment score
    #
    # Attachment analyzer can score up to 50.
    # For the overall risk model, attachment contribution
    # is limited to 30.
    # ---------------------------------------------------------

    attachment_score = min(
        attachment_results.get("score", 0),
        30,
    )

    # ---------------------------------------------------------
    # HTML score
    #
    # HTML analyzer can score up to 50.
    # For the overall risk model, HTML contribution is
    # limited to 20.
    # ---------------------------------------------------------

    html_score = min(
        html_results.get("score", 0),
        20,
    )

    # ---------------------------------------------------------
    # Calculate final score
    # ---------------------------------------------------------

    raw_score = (
        header_score
        + url_score
        + content_score
        + attachment_score
        + html_score
    )

    final_score = min(
        raw_score,
        100,
    )

    # ---------------------------------------------------------
    # Determine severity
    # ---------------------------------------------------------

    if final_score >= 80:
        severity = "CRITICAL"

    elif final_score >= 60:
        severity = "HIGH"

    elif final_score >= 30:
        severity = "SUSPICIOUS"

    else:
        severity = "LOW"

    # ---------------------------------------------------------
    # Generate risk findings
    # ---------------------------------------------------------

    risk_results = calculate_risk_score(
        header_results,
        url_results,
        content_score=content_score,
    )

    # ---------------------------------------------------------
    # Combine findings
    # ---------------------------------------------------------

    findings = (
        risk_results["findings"]
        + content_results["findings"]
        + attachment_results["findings"]
        + html_results["findings"]
    )

    # ---------------------------------------------------------
    # Return complete analysis
    # ---------------------------------------------------------

    return {
        "email": email,

        "headers": header_results,

        "iocs": iocs,

        "urls": url_results,

        "content": content_results,

        "attachments": attachment_results,

        "html": html_results,

        "risk": {
            "score": final_score,
            "raw_score": raw_score,
            "severity": severity,

            "breakdown": {
                "header": header_score,
                "url": url_score,
                "content": content_score,
                "attachments": attachment_score,
                "html": html_score,
            },

            "findings": findings,
        },
    }