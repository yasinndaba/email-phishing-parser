import socket
from urllib.parse import urlparse

from analyzer.virustotal import query_domain


def resolve_domain(domain: str) -> dict:
    """
    Resolve a domain to its associated IPv4 addresses.

    This performs DNS resolution only and does not establish
    an HTTP connection to the target.
    """

    domain = domain.strip().lower()

    result = {
        "domain": domain,
        "resolved": False,
        "ips": [],
        "error": None,
    }

    if not domain:
        result["error"] = "Empty domain."
        return result

    try:
        addresses = socket.getaddrinfo(
            domain,
            None,
            socket.AF_INET,
        )

        ips = sorted(
            {
                address[4][0]
                for address in addresses
            }
        )

        result["ips"] = ips
        result["resolved"] = bool(ips)

    except socket.gaierror as exc:
        result["error"] = str(exc)

    except OSError as exc:
        result["error"] = str(exc)

    return result


def calculate_reputation_score(
    virustotal_result: dict,
) -> int:
    """
    Convert VirusTotal detections into a normalized
    reputation risk score from 0-30.

    This score represents reputation risk only.
    It is not the final phishing score.
    """

    if not virustotal_result.get("available"):
        return 0

    malicious = virustotal_result.get(
        "malicious",
        0,
    )

    suspicious = virustotal_result.get(
        "suspicious",
        0,
    )

    # Malicious detections carry significantly more weight.
    score = (malicious * 3) + (suspicious * 1)

    return min(score, 30)


def analyze_domain(
    domain: str,
    check_reputation: bool = True,
) -> dict:
    """
    Perform DNS and optional VirusTotal reputation analysis.

    Reputation checking is optional so the analyzer continues
    to function without an API key or internet access.
    """

    domain = domain.strip().lower()

    result = {
        "domain": domain,
        "dns": resolve_domain(domain),
        "reputation": {
            "available": False,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "reputation": 0,
            "source": None,
            "error": None,
        },
        "findings": [],
        "score": 0,
    }

    if not domain:
        result["findings"].append(
            "No domain provided."
        )
        return result

    # DNS analysis
    if result["dns"]["resolved"]:
        ips = result["dns"]["ips"]

        result["findings"].append(
            f"Domain resolves to {len(ips)} IPv4 address(es)."
        )
    else:
        result["findings"].append(
            "Domain does not currently resolve via IPv4 DNS."
        )

    # VirusTotal reputation
    if check_reputation:
        vt_result = query_domain(domain)

        result["reputation"] = vt_result

        reputation_score = calculate_reputation_score(
            vt_result
        )

        result["score"] = reputation_score

        if vt_result["available"]:
            malicious = vt_result["malicious"]
            suspicious = vt_result["suspicious"]

            if malicious > 0:
                result["findings"].append(
                    f"VirusTotal reports {malicious} "
                    f"malicious detection(s)."
                )

            if suspicious > 0:
                result["findings"].append(
                    f"VirusTotal reports {suspicious} "
                    f"suspicious detection(s)."
                )

            if malicious == 0 and suspicious == 0:
                result["findings"].append(
                    "VirusTotal reports no malicious "
                    "or suspicious detections."
                )

        elif vt_result.get("error"):
            result["findings"].append(
                f"VirusTotal unavailable: "
                f"{vt_result['error']}"
            )

    return result


def analyze_url_reputation(
    url: str,
    check_reputation: bool = True,
) -> dict:
    """
    Extract the hostname from a URL and perform
    domain reputation analysis.
    """

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    if not hostname:
        return {
            "url": url,
            "hostname": "",
            "domain_analysis": analyze_domain(
                "",
                check_reputation=check_reputation,
            ),
        }

    return {
        "url": url,
        "hostname": hostname.lower(),
        "domain_analysis": analyze_domain(
            hostname,
            check_reputation=check_reputation,
        ),
    }