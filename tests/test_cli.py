import json
import subprocess
import sys


EMAIL_SAMPLE = "samples/test_email.eml"


def run_cli(*args):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "cli.main",
            EMAIL_SAMPLE,
            *args,
        ],
        capture_output=True,
        text=True,
    )


def test_cli_human_output():
    result = run_cli()

    assert result.returncode == 3
    assert "PHISHING EMAIL ANALYZER" in result.stdout
    assert "VERDICT:    CRITICAL" in result.stdout
    assert "RISK SCORE: 97/100" in result.stdout


def test_cli_json_output():
    result = run_cli("--json")

    assert result.returncode == 3

    data = json.loads(result.stdout)

    assert data["risk"]["severity"] == "CRITICAL"
    assert data["risk"]["score"] == 97
    assert data["email"]["subject"] == (
        "URGENT: Your Microsoft 365 account will be suspended"
    )


def test_cli_json_contains_iocs():
    result = run_cli("--json")

    data = json.loads(result.stdout)

    assert len(data["iocs"]["urls"]) == 1
    assert "micros0ft-support.com" in data["iocs"]["domains"]


def test_cli_quiet_mode():
    result = run_cli("--quiet")

    assert result.returncode == 3
    assert result.stdout == ""


def test_cli_missing_file():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "cli.main",
            "samples/does-not-exist.eml",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 4
    assert "Email file not found" in result.stderr