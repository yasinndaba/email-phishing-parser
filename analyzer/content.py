import re


# Common social-engineering indicators found in phishing emails.
INDICATORS = {
    "urgency": {
        "keywords": [
            "urgent",
            "immediately",
            "as soon as possible",
            "within 24 hours",
            "act now",
            "action required",
            "important",
        ],
        "points": 5,
    },
    "account_threat": {
        "keywords": [
            "suspended",
            "suspension",
            "locked",
            "terminated",
            "disabled",
            "deactivated",
            "will be closed",
        ],
        "points": 5,
    },
    "credential_request": {
        "keywords": [
            "password",
            "username",
            "credentials",
            "verify your identity",
            "login",
            "sign in",
            "authenticate",
            "security verification",
        ],
        "points": 7,
    },
    "financial_pressure": {
        "keywords": [
            "payment",
            "invoice",
            "bank account",
            "credit card",
            "wire transfer",
            "transfer funds",
            "payment required",
        ],
        "points": 7,
    },
    "call_to_action": {
        "keywords": [
            "click here",
            "click the link",
            "verify now",
            "confirm now",
            "update your account",
            "complete verification",
        ],
        "points": 5,
    },
    "security_alert": {
        "keywords": [
            "suspicious activity",
            "security alert",
            "unusual activity",
            "unauthorized access",
            "security warning",
        ],
        "points": 5,
    },
}


def analyze_content(body: str) -> dict:
    """
    Analyze email body for common phishing/social-engineering indicators.

    Args:
        body: Plain-text email body.

    Returns:
        Dictionary containing matched indicators, findings and risk score.
    """

    if not body:
        return {
            "score": 0,
            "categories": {},
            "findings": [],
        }

    text = body.lower()

    categories = {}
    findings = []
    score = 0

    for category, data in INDICATORS.items():
        matches = []

        for keyword in data["keywords"]:
            # Match phrases/words while avoiding partial-word matches.
            pattern = rf"\b{re.escape(keyword)}\b"

            if re.search(pattern, text, re.IGNORECASE):
                matches.append(keyword)

        if matches:
            categories[category] = matches

            # Each category gets its defined weight once.
            score += data["points"]

            findings.append(
                f"{category.replace('_', ' ').title()} indicators detected: "
                + ", ".join(matches)
            )

    return {
        "score": min(score, 100),
        "categories": categories,
        "findings": findings,
    }