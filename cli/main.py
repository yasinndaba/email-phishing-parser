import argparse
import json
import sys

from analyzer.engine import analyze_email


def print_human_report(result: dict) -> None:
    email = result["email"]
    headers = result["headers"]
    iocs = result["iocs"]
    urls = result["urls"]
    content = result["content"]
    risk = result["risk"]

    print()
    print("=" * 60)
    print("              PHISHING EMAIL ANALYZER")
    print("=" * 60)

    print()
    print(f"VERDICT:    {risk['severity']}")
    print(f"RISK SCORE: {risk['score']}/100")

    print()
    print("Score Breakdown:")
    print(f"  Header Risk:  {risk['breakdown']['header']}")
    print(f"  URL Risk:     {risk['breakdown']['url']}")
    print(f"  Content Risk: {risk['breakdown']['content']}")
    print(f"  Raw Score:    {risk['raw_score']}")

    print()
    print("=" * 60)
    print("EMAIL")
    print("=" * 60)

    print(f"From:       {email.get('from', 'N/A')}")
    print(f"Reply-To:   {email.get('reply_to', 'N/A')}")
    print(f"Subject:    {email.get('subject', 'N/A')}")

    print()
    print("=" * 60)
    print("AUTHENTICATION")
    print("=" * 60)

    print(f"SPF:         {headers.get('spf', 'unknown').upper()}")
    print(f"DKIM:        {headers.get('dkim', 'unknown').upper()}")
    print(f"DMARC:       {headers.get('dmarc', 'unknown').upper()}")

    print()
    print("=" * 60)
    print("INDICATORS OF COMPROMISE")
    print("=" * 60)

    print(f"URLs:            {len(iocs.get('urls', []))}")
    print(f"Domains:         {len(iocs.get('domains', []))}")
    print(f"IP Addresses:    {len(iocs.get('ip_addresses', []))}")
    print(f"Email Addresses: {len(iocs.get('email_addresses', []))}")

    if urls:
        print()
        print("=" * 60)
        print("URL ANALYSIS")
        print("=" * 60)

        for url_result in urls:
            print()
            print(f"URL: {url_result.get('url', 'N/A')}")
            print(f"Hostname: {url_result.get('hostname', 'N/A')}")
            print(f"Score: {url_result.get('score', 0)}/100")

            brand = url_result.get("brand_impersonation", {})

            if brand.get("detected"):
                print(
                    f"Brand impersonation: "
                    f"{brand.get('brand', 'Unknown')}"
                )

            findings = url_result.get("findings", [])

            if findings:
                print("Findings:")

                for finding in findings:
                    print(f"  [!] {finding}")

            reputation = url_result.get("reputation")

            if reputation:
                print()
                print("Reputation:")

                if reputation.get("available"):
                    print(
                        f"  Reputation Score: "
                        f"{reputation.get('score', 0)}/100"
                    )

                    for finding in reputation.get("findings", []):
                        print(f"  [!] {finding}")
                else:
                    print("  Reputation data unavailable.")

    print()
    print("=" * 60)
    print("CONTENT ANALYSIS")
    print("=" * 60)

    print(f"Content Score: {content.get('score', 0)}/100")

    categories = content.get("categories", {})

    if categories:
        print()
        print("Detected categories:")

        for category, indicators in categories.items():
            if indicators:
                print(
                    f"  [!] {category}: "
                    f"{', '.join(indicators)}"
                )

    print()
    print("=" * 60)
    print("DETECTIONS")
    print("=" * 60)

    findings = risk.get("findings", [])

    if findings:
        for finding in findings:
            print(f"  - {finding}")
    else:
        print("  No significant detections.")

    print()
    print("=" * 60)
    print("RECOMMENDATION")
    print("=" * 60)

    if risk["severity"] in {"CRITICAL", "HIGH"}:
        print("  Do not interact with links or attachments.")
        print("  Treat the email as potentially malicious.")
        print("  Investigate the extracted indicators.")
        print("  Verify the sender through an independent channel.")
    elif risk["severity"] == "SUSPICIOUS":
        print("  Exercise caution with this email.")
        print("  Investigate suspicious indicators.")
        print("  Verify the sender through an independent channel.")
    else:
        print("  No major phishing indicators detected.")
        print("  Continue normal security awareness practices.")

    print()
    print("=" * 60)
    print()


def get_exit_code(severity: str) -> int:
    """
    Return a useful exit code for automation/SOC workflows.
    """

    return {
        "LOW": 0,
        "SUSPICIOUS": 1,
        "HIGH": 2,
        "CRITICAL": 3,
    }.get(severity, 1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze an email for phishing indicators."
    )

    parser.add_argument(
        "email",
        help="Path to the .eml email file to analyze.",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the analysis as JSON.",
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress human-readable output.",
    )

    args = parser.parse_args()

    try:
        result = analyze_email(args.email)

    except FileNotFoundError:
        print(
            f"Error: Email file not found: {args.email}",
            file=sys.stderr,
        )
        sys.exit(4)

    except Exception as exc:
        print(
            f"Error analyzing email: {exc}",
            file=sys.stderr,
        )
        sys.exit(5)

    if args.json:
        print(json.dumps(result, indent=2, default=str))

    elif not args.quiet:
        print_human_report(result)

    sys.exit(get_exit_code(result["risk"]["severity"]))


if __name__ == "__main__":
    main()