import socket
from urllib.parse import urlparse


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


def analyze_domain(domain: str) -> dict:
    """
    Perform basic domain reputation analysis.

    This module intentionally does not claim that a domain is
    malicious based solely on DNS resolution.
    """

    domain = domain.strip().lower()

    result = {
        "domain": domain,
        "dns": resolve_domain(domain),
        "reputation": {
            "available": False,
            "malicious": False,
            "score": 0,
            "source": None,
        },
        "findings": [],
        "score": 0,
    }

    if not domain:
        result["findings"].append(
            "No domain provided."
        )
        return result

    # DNS resolution is informational.
    if result["dns"]["resolved"]:
        ips = result["dns"]["ips"]

        result["findings"].append(
            f"Domain resolves to {len(ips)} IPv4 address(es)."
        )
    else:
        result["findings"].append(
            "Domain does not currently resolve via IPv4 DNS."
        )

    return result


def analyze_url_reputation(url: str) -> dict:
    """
    Extract the hostname from a URL and perform domain analysis.
    """

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    if not hostname:
        return {
            "url": url,
            "hostname": "",
            "domain_analysis": analyze_domain(""),
        }

    return {
        "url": url,
        "hostname": hostname.lower(),
        "domain_analysis": analyze_domain(hostname),
    }