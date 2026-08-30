from analyzer.virustotal import query_domain


def test_missing_api_key(monkeypatch):
    monkeypatch.delenv(
        "VIRUSTOTAL_API_KEY",
        raising=False,
    )

    result = query_domain("example.com")

    assert result["available"] is False
    assert result["error"] is not None
    assert result["source"] == "VirusTotal"


def test_empty_domain():
    result = query_domain("")

    assert result["available"] is False
    assert result["error"] == "No domain provided."