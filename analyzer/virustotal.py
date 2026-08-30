import os

import requests
from dotenv import load_dotenv


load_dotenv()

VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"


def get_api_key() -> str | None:
    """
    Return the VirusTotal API key from the environment.
    """

    return os.getenv("VIRUSTOTAL_API_KEY")


def query_domain(domain: str) -> dict:
    """
    Query VirusTotal for domain reputation.

    Returns a normalized result and gracefully handles
    missing API keys, invalid responses, and network errors.
    """

    domain = domain.strip().lower()

    result = {
        "domain": domain,
        "available": False,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "reputation": 0,
        "source": "VirusTotal",
        "error": None,
    }

    if not domain:
        result["error"] = "No domain provided."
        return result

    api_key = get_api_key()

    if not api_key:
        result["error"] = "VirusTotal API key not configured."
        return result

    headers = {
        "x-apikey": api_key,
    }

    try:
        response = requests.get(
            f"{VIRUSTOTAL_API_URL}/domains/{domain}",
            headers=headers,
            timeout=10,
        )

        if response.status_code == 404:
            result["error"] = "Domain not found in VirusTotal."
            return result

        response.raise_for_status()

        data = response.json()

        stats = (
            data
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )

        result["malicious"] = stats.get("malicious", 0)
        result["suspicious"] = stats.get("suspicious", 0)
        result["harmless"] = stats.get("harmless", 0)
        result["undetected"] = stats.get("undetected", 0)

        result["reputation"] = (
            data
            .get("data", {})
            .get("attributes", {})
            .get("reputation", 0)
        )

        result["available"] = True

    except requests.RequestException as exc:
        result["error"] = str(exc)

    except (ValueError, TypeError, AttributeError) as exc:
        result["error"] = f"Invalid VirusTotal response: {exc}"

    return result