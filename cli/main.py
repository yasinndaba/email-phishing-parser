
import argparse
import sys

from analyzer.engine import analyze_email


def print_section(title: str) -> None:
    """Print a formatted section heading."""
    print()
    print("=" * 60)
    print(title)
    print("=" * 60)


def print_list(items: list[str], empty_message: str = "None detected.") -> None:
    """Print a list of items."""
    if not items:
        print(f"  {empty_message}")
        return

    for item in items:
        print(f"  - {item}")


def main() -> None:
    """Run the phishing email analyzer CLI."""

    parser = argparse.ArgumentParser(
        description="Analyze an email for potential phishing indicators."
    )

    parser.add_argument(
        "email",
        help="Path to the .eml file to analyze.",
    )

    args = parser.parse_args()

    try:
        result = analyze_email(args.email)

    except FileNotFoundError:
        print(f"Error: File not found: {args.email}")
        sys.exit(1)

    except Exception as exc:
        print(f"Error analyzing email: {exc}")
        sys.exit(1)

    email = result["email"]
    headers = result["headers"]
    iocs = result["iocs"]
    content = result["content"]
    urls = result["urls"]
    risk = result["risk"]

    # --------------------------------
    # Header
    # --------------------------------

    print()
    print("=" * 60)
    print("              PHISHING EMAIL ANALYZER")
    print("=" * 60)

    print(f"\nVERDICT:    {risk['severity']}")
    print(f"RISK SCORE: {risk['score']}/100")

    # --------------------------------
    # Email information
    # --------------------------------

    print_section("EMAIL")

    print(f"From:       {email.get('from', 'Unknown')}")
    print(f"Reply-To:   {email.get('reply_to', 'None')}")
    print(f"Subject:    {email.get('subject', 'No subject')}")

    # --------------------------------
    # Authentication
    # --------------------------------

    print_section("AUTHENTICATION")

    print(f"SPF:         {headers.get('spf', 'unknown').upper()}")
    print(f"DKIM:        {headers.get('dkim', 'unknown').upper()}")
    print(f"DMARC:       {headers.get('dmarc', 'unknown').upper()}")

    # --------------------------------
    # IOCs
    # --------------------------------

    print_section("INDICATORS OF COMPROMISE")

    print(f"URLs:            {len(iocs.get('urls', []))}")
    print(f"Domains:         {len(iocs.get('domains', []))}")
    print(f"IP Addresses:    {len(iocs.get('ip_addresses', []))}")
    print(f"Email Addresses: {len(iocs.get('email_addresses', []))}")

    # --------------------------------
    # URLs
    # --------------------------------

    if urls:
        print_section("URL ANALYSIS")

        for url_result in urls:

            print(f"\nURL: {url_result['url']}")
            print(f"Hostname: {url_result['hostname']}")
            print(f"Score: {url_result['score']}/100")

            brand = url_result.get("brand_impersonation", {})

            if brand.get("detected"):
                print(
                    f"Brand impersonation: "
                    f"{brand['brand'].title()}"
                )

            if url_result["findings"]:
                print("Findings:")

                for finding in url_result["findings"]:
                    print(f"  [!] {finding}")

    # --------------------------------
    # Content analysis
    # --------------------------------

    print_section("CONTENT ANALYSIS")

    print(f"Content Score: {content['score']}/100")

    if content["categories"]:
        print("\nDetected categories:")

        for category, matches in content["categories"].items():
            print(
                f"  [!] {category}: "
                f"{', '.join(matches)}"
            )

    else:
        print("  No suspicious content indicators detected.")

    # --------------------------------
    # Findings
    # --------------------------------

    print_section("DETECTIONS")

    findings = risk.get("findings", [])

    if findings:
        print_list(findings)
    else:
        print("  No significant phishing indicators detected.")

    # --------------------------------
    # Recommendation
    # --------------------------------

    print_section("RECOMMENDATION")

    if risk["score"] >= 80:
        print("  Do not interact with links or attachments.")
        print("  Treat the email as potentially malicious.")
        print("  Investigate the extracted indicators.")
        print("  Verify the sender through an independent channel.")

    elif risk["score"] >= 60:
        print("  Exercise caution with this email.")
        print("  Investigate the detected indicators.")
        print("  Verify the sender before interacting.")

    elif risk["score"] >= 30:
        print("  Review the detected indicators.")
        print("  Verify suspicious links or sender information.")

    else:
        print("  No major phishing indicators detected.")
        print("  Continue normal email security procedures.")

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()