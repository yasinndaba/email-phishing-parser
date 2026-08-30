from analyzer.iocs import extract_iocs
from analyzer.parser import parse_email


def test_ioc_extraction():
    email = parse_email("samples/test_email.eml")
    iocs = extract_iocs(email)

    assert "https://micros0ft-support.com/verify" in iocs["urls"]

    assert "micros0ft-support.com" in iocs["domains"]

    assert "security@micros0ft-support.com" in iocs["email_addresses"]
    assert "attacker@evil-example.com" in iocs["email_addresses"]

    assert iocs["ip_addresses"] == []