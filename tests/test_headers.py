from analyzer.parser import parse_email
from analyzer.headers import analyze_headers


def test_header_analysis():
    email = parse_email("samples/test_email.eml")
    results = analyze_headers(email)

    assert results["spf"] == "fail"
    assert results["dkim"] == "fail"
    assert results["dmarc"] == "fail"

    assert results["reply_to_mismatch"] is True
    assert results["return_path_mismatch"] is True

    assert len(results["findings"]) >= 5