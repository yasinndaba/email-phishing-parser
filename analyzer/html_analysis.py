from __future__ import annotations

from urllib.parse import urlparse

from bs4 import BeautifulSoup


SUSPICIOUS_HTML_KEYWORDS = {
    "login",
    "verify",
    "verification",
    "password",
    "credential",
    "account",
    "security",
    "update",
    "confirm",
}


def analyze_html(body: str) -> dict:
    """
    Analyze an HTML email body for suspicious links and HTML patterns.

    Detects:
    - HTML content
    - Links
    - Links with suspicious keywords
    - Visible-text / URL mismatches
    - Forms
    - Embedded scripts
    - Suspicious HTML attributes

    Returns:
        Dictionary containing HTML analysis results.
    """

    if not body or "<" not in body or ">" not in body:
        return {
            "is_html": False,
            "link_count": 0,
            "links": [],
            "forms": 0,
            "scripts": 0,
            "score": 0,
            "findings": [],
        }

    soup = BeautifulSoup(body, "html.parser")

    links = []
    findings = []
    score = 0

    # ---------------------------------------------------------
    # Analyze links
    # ---------------------------------------------------------

    for tag in soup.find_all("a"):
        href = tag.get("href")

        if not href:
            continue

        href = str(href).strip()

        visible_text = tag.get_text(
            " ",
            strip=True,
        )

        parsed = urlparse(href)

        hostname = parsed.hostname or ""

        link_findings = []

        # -----------------------------------------------------
        # Suspicious URL keywords
        # -----------------------------------------------------

        lower_href = href.lower()

        matched_keywords = [
            keyword
            for keyword in SUSPICIOUS_HTML_KEYWORDS
            if keyword in lower_href
        ]

        if matched_keywords:
            link_findings.append(
                "Suspicious URL keywords detected: "
                + ", ".join(sorted(matched_keywords))
            )

            findings.append(
                f"HTML link contains suspicious keywords: {href}"
            )

            score += 5

        # -----------------------------------------------------
        # Visible text / URL mismatch
        # -----------------------------------------------------

        visible_hostname = ""

        if visible_text:
            visible_parsed = urlparse(
                visible_text
            )

            visible_hostname = (
                visible_parsed.hostname or ""
            )

        if (
            visible_hostname
            and hostname
            and visible_hostname.lower()
            != hostname.lower()
        ):
            link_findings.append(
                "Visible link text does not match "
                "the destination hostname."
            )

            findings.append(
                "HTML link text/URL mismatch detected: "
                f"{visible_text} -> {href}"
            )

            score += 20

        # -----------------------------------------------------
        # IP address destination
        # -----------------------------------------------------

        hostname_parts = hostname.split(".")

        is_ip = (
            hostname
            and all(
                part.isdigit()
                for part in hostname_parts
            )
            and len(hostname_parts) == 4
        )

        if is_ip:
            link_findings.append(
                "HTML link uses an IP address."
            )

            findings.append(
                f"HTML link uses an IP address: {href}"
            )

            score += 15

        links.append(
            {
                "href": href,
                "visible_text": visible_text,
                "hostname": hostname,
                "suspicious": bool(link_findings),
                "findings": link_findings,
            }
        )

    # ---------------------------------------------------------
    # Forms
    # ---------------------------------------------------------

    forms = soup.find_all("form")

    if forms:
        findings.append(
            f"HTML form detected: {len(forms)}"
        )

        score += 20

    # ---------------------------------------------------------
    # Scripts
    # ---------------------------------------------------------

    scripts = soup.find_all("script")

    if scripts:
        findings.append(
            f"Embedded JavaScript detected: {len(scripts)}"
        )

        score += 20

    # ---------------------------------------------------------
    # Suspicious event handlers
    # ---------------------------------------------------------

    event_handler_count = 0

    for tag in soup.find_all(True):
        for attribute in tag.attrs:
            if str(attribute).lower().startswith("on"):
                event_handler_count += 1

    if event_handler_count:
        findings.append(
            "HTML event handler attributes detected: "
            f"{event_handler_count}"
        )

        score += 10

    # ---------------------------------------------------------
    # Final score
    # ---------------------------------------------------------

    score = min(score, 50)

    return {
        "is_html": True,
        "link_count": len(links),
        "links": links,
        "forms": len(forms),
        "scripts": len(scripts),
        "score": score,
        "findings": findings,
    }