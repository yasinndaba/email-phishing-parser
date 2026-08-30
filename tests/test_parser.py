from analyzer.parser import parse_email


def test_parse_email():
    email = parse_email("samples/test_email.eml")

    assert email["from"] == "Microsoft Security <security@micros0ft-support.com>"
    assert email["to"] == "analyst@example.com"
    assert email["subject"] == (
        "URGENT: Your Microsoft 365 account will be suspended"
    )
    assert email["reply_to"] == "attacker@evil-example.com"
    assert email["return_path"] == "<attacker@evil-example.com>"
    assert email["authentication_results"] is not None
    assert len(email["received"]) == 0
    assert "verify your identity" in email["body"]
