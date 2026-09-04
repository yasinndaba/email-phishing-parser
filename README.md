# Phishing Email Analyzer

A Python-based phishing email analysis tool designed to simulate a lightweight **SOC email triage workflow**.

The analyzer parses `.eml` files, evaluates email authentication headers, extracts indicators of compromise (IOCs), analyzes URLs and email content, inspects attachments and HTML behavior, checks domain reputation, and combines the findings into an overall phishing risk score.

The project is designed as a practical **Blue Team / SOC Analyst portfolio project**, demonstrating how automated email triage can identify suspicious indicators before an analyst investigates an incident manually.

---

## Features

The analyzer currently supports:

* `.eml` email parsing
* SPF, DKIM, and DMARC analysis
* Sender / Reply-To mismatch detection
* Return-Path mismatch detection
* IOC extraction
* URL analysis
* IP-based URL detection
* Suspicious TLD detection
* Suspicious URL keyword detection
* Excessive subdomain detection
* URL encoding detection
* Suspicious hyphen detection
* Brand impersonation detection
* Fuzzy domain similarity analysis
* Domain and URL reputation analysis
* VirusTotal integration
* Phishing-content analysis
* Urgency detection
* Account-threat detection
* Credential-request detection
* Call-to-action detection
* Security-alert detection
* HTML email analysis
* HTML link extraction
* HTML link-text mismatch detection
* HTML form detection
* HTML script detection
* Suspicious HTML URL detection
* IP-based HTML links
* Attachment analysis
* Executable attachment detection
* Suspicious file-extension detection
* Double-extension detection
* Macro-enabled document detection
* MIME-extension mismatch detection
* Risk scoring
* Severity classification
* Human-readable CLI output
* JSON CLI output
* Quiet mode for automation
* Automated unit testing

---

## Architecture

The analyzer follows a modular detection pipeline:

```text
                         ┌──────────────────┐
                         │   .eml Email     │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │ Email Parser     │
                         │ parser.py        │
                         └────────┬─────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
              ▼                   ▼                   ▼
       ┌────────────┐      ┌────────────┐      ┌────────────┐
       │  Headers   │      │    IOCs    │      │  Content   │
       │  Analysis  │      │ Extraction │      │  Analysis  │
       └─────┬──────┘      └─────┬──────┘      └─────┬──────┘
             │                   │                   │
             │                   ▼                   │
             │            ┌────────────┐             │
             │            │    URLs    │             │
             │            │  Analysis  │             │
             │            └─────┬──────┘             │
             │                  │                    │
             │                  ▼                    │
             │           ┌──────────────┐            │
             │           │  Reputation  │            │
             │           │   Analysis   │            │
             │           └──────┬───────┘            │
             │                  │                    │
             └──────────────────┼────────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │  Risk Scoring    │
                       │    Engine        │
                       └────────┬─────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │ Final Assessment │
                       │ LOW              │
                       │ SUSPICIOUS       │
                       │ HIGH             │
                       │ CRITICAL         │
                       └──────────────────┘
```

Detailed architecture documentation is available in:

`docs/architecture.md`

Detection logic and scoring behavior are documented in:

`docs/detection-rules.md`

---

## Project Structure

```text
email-phishing-parser/
│
├── analyzer/
│   ├── __init__.py
│   ├── parser.py
│   ├── headers.py
│   ├── iocs.py
│   ├── urls.py
│   ├── content.py
│   ├── html_analysis.py
│   ├── attachments.py
│   ├── reputation.py
│   ├── virustotal.py
│   ├── scoring.py
│   └── engine.py
│
├── cli/
│   └── main.py
│
├── tests/
│   ├── test_parser.py
│   ├── test_headers.py
│   ├── test_iocs.py
│   ├── test_urls.py
│   ├── test_content.py
│   ├── test_html_analysis.py
│   ├── test_attachments.py
│   ├── test_reputation.py
│   ├── test_virustotal.py
│   ├── test_scoring.py
│   ├── test_engine.py
│   └── test_cli.py
│
├── samples/
│   └── test_email.eml
│
├── docs/
│   ├── architecture.md
│   └── detection-rules.md
│
├── requirements.txt
├── README.md
└── .gitignore
```

---

## Detection Pipeline

The analyzer does not rely on a single phishing indicator.

Instead, it correlates multiple signals.

For example:

```text
SPF failure
      +
DKIM failure
      +
DMARC failure
      +
Reply-To mismatch
      +
Brand impersonation
      +
Suspicious URL
      +
Urgent language
      +
Credential request
      =
High-confidence phishing assessment
```

This approach is important because individual indicators can produce false positives.

A legitimate organization can occasionally have an authentication failure. A URL containing the word `verify` is not automatically malicious. But several independent indicators appearing together significantly increase the likelihood that an email requires investigation.

---

## Detection Categories

### Email Authentication

The analyzer evaluates:

* SPF
* DKIM
* DMARC

Authentication failures contribute to the risk score because attackers commonly send messages from infrastructure that is not authorized to represent the claimed sender domain.

---

### Header Anomalies

The analyzer checks for inconsistencies between:

* From
* Reply-To
* Return-Path

A common phishing pattern is:

```text
From:
security@fake-microsoft-domain.com

Reply-To:
attacker@evil-domain.com
```

This can indicate that the attacker wants the victim's response to go somewhere different from the apparent sender.

---

### IOC Extraction

The analyzer extracts:

* URLs
* Domains
* IP addresses
* Email addresses

These indicators can subsequently be investigated using reputation services, threat intelligence platforms, SIEM searches, or analyst tooling.

---

### URL Analysis

URLs are evaluated for characteristics commonly associated with phishing.

The analyzer checks for:

* IP addresses instead of domains
* Suspicious TLDs
* Excessive subdomains
* Unusually long URLs
* Suspicious keywords
* `@` characters
* Excessive hyphens
* Percent encoding
* Brand impersonation

Example:

```text
https://micros0ft-support.com/verify
```

The domain resembles Microsoft's legitimate domain while replacing the `o` with `0`.

The analyzer identifies this as potential brand impersonation.

---

### Brand Impersonation

Known brands are compared against the observed domain.

Example:

```text
Expected:
microsoft.com

Observed:
micros0ft-support.com
```

The analyzer uses fuzzy matching to identify domains that are visually similar to known brands.

This is useful against:

* Typosquatting
* Character substitution
* Brand + malicious suffix domains
* Lookalike domains

---

### Content Analysis

Email body content is analyzed for phishing language.

Detection categories include:

* Urgency
* Account threats
* Credential requests
* Calls to action
* Security alerts

Example:

```text
Your account has been suspended.

Verify your identity immediately.

Complete verification within 24 hours.
```

The combination of account threats, urgency, and credential requests is a strong phishing signal.

---

### HTML Analysis

HTML emails receive additional inspection.

The analyzer checks for:

* HTML links
* Suspicious URLs
* IP-based links
* Link-text / destination mismatches
* HTML forms
* Embedded scripts

A particularly useful detection is a visible link that claims to point somewhere legitimate while actually directing the user elsewhere.

Example:

```text
Visible text:

https://microsoft.com/account

Actual destination:

https://micros0ft-support.com/login
```

---

### Attachment Analysis

Attachments are evaluated for suspicious characteristics.

The analyzer checks for:

* Executable files
* Suspicious extensions
* Double extensions
* Macro-enabled documents
* MIME-type / extension mismatches

Examples of suspicious filenames include:

```text
invoice.pdf.exe
document.docm
payment.xlsm
report.pdf.scr
```

Double extensions are particularly useful because attackers can attempt to disguise executable files as documents.

---

### Reputation Analysis

Domains and URLs can be evaluated against reputation information.

The analyzer supports:

* Domain resolution
* URL reputation analysis
* Malicious reputation detection
* Suspicious reputation detection
* Reputation score integration
* VirusTotal integration

External reputation services are treated as supporting evidence rather than absolute truth.

---

## Risk Scoring

The analyzer combines multiple detection categories into a numerical risk score from:

```text
0 - 100
```

The severity classification is:

|  Score | Severity   |
| -----: | ---------- |
|   0–29 | LOW        |
|  30–59 | SUSPICIOUS |
|  60–79 | HIGH       |
| 80–100 | CRITICAL   |

The score is capped at 100.

Individual components are also capped where appropriate to prevent one category from overwhelming the entire analysis.

The final assessment considers multiple components such as:

```text
Header Risk
URL Risk
Content Risk
Attachment Risk
Reputation Risk
```

This produces a more useful analyst-oriented result than simply returning:

```text
PHISHING = TRUE
```

---

## Example Analysis

The included sample email is intentionally designed to contain multiple phishing indicators.

Run:

```bash
python -m cli.main samples/test_email.eml
```

Example result:

```text
============================================================
              PHISHING EMAIL ANALYZER
============================================================

VERDICT:    CRITICAL
RISK SCORE: 97/100

Score Breakdown:
  Header Risk:  40
  URL Risk:     30
  Content Risk: 27
  Raw Score:    97
```

The sample contains:

```text
SPF: FAIL
DKIM: FAIL
DMARC: FAIL
```

It also contains:

```text
Reply-To mismatch
Return-Path mismatch
```

The URL:

```text
https://micros0ft-support.com/verify
```

is detected as potential Microsoft brand impersonation.

The body contains indicators associated with:

```text
Urgency
Account Threat
Credential Request
Call To Action
Security Alert
```

The analyzer therefore classifies the email as:

```text
CRITICAL
```

---

## CLI Usage

Basic analysis:

```bash
python -m cli.main samples/test_email.eml
```

JSON output:

```bash
python -m cli.main samples/test_email.eml --json
```

Quiet mode:

```bash
python -m cli.main samples/test_email.eml --quiet
```

JSON output is useful when integrating the analyzer with:

* SIEM platforms
* SOAR workflows
* Automation scripts
* REST APIs
* Security dashboards
* CI/CD pipelines

---

## Testing

The project uses `pytest`.

Run the complete test suite:

```bash
python -m pytest -v
```

Current test coverage includes:

```text
Email parsing
Header analysis
IOC extraction
URL analysis
Content analysis
HTML analysis
Attachment analysis
Domain reputation
VirusTotal handling
Risk scoring
Engine integration
CLI behavior
```

The current test suite contains **50 automated tests**.

Example:

```text
50 passed
```

Testing is treated as part of the detection-engineering workflow so that changes to detection logic do not silently break existing functionality.

---

## Installation

Clone the repository:

```bash
git clone repository-url](https://github.com/yasinndaba/email-phishing-parser
cd email-phishing-parser
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Linux:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the tests:

```bash
python -m pytest -v
```

Run the analyzer:

```bash
python -m cli.main samples/test_email.eml
```

---

## VirusTotal Integration

VirusTotal integration is optional.

The analyzer can operate without an API key.

If configured, the API key should be provided through an environment variable rather than hard-coded into the source code.

Example:

```bash
export VIRUSTOTAL_API_KEY="your-api-key"
```

Never commit API keys, credentials, or other secrets to GitHub.

---

## Technologies

Python, pytest, RapidFuzz, VirusTotal API, email parsing, DNS resolution, HTML parsing, regular expressions, JSON, Git, Linux

---

## Security Design Principles

This project follows several principles relevant to SOC detection engineering.

**Defense in depth**

No single detection determines whether an email is malicious.

**Explainability**

The analyzer provides findings explaining why a score was assigned.

**Evidence correlation**

Independent indicators are combined to produce a stronger assessment.

**Fail-safe behavior**

Unavailable external reputation services should not cause the analyzer to fail.

**Automation-friendly output**

JSON and quiet modes allow the tool to be integrated into larger security workflows.

**Test-driven detection logic**

Detection rules are covered by automated tests to reduce regressions.

---

## Limitations

This tool is intended for **security analysis and educational use**, not as a replacement for enterprise email security products.

It does not guarantee that an email is malicious or legitimate.

Potential limitations include:

* Domain reputation can change over time.
* Legitimate emails can trigger individual detection rules.
* Attackers can use compromised legitimate infrastructure.
* SPF/DKIM/DMARC results require contextual interpretation.
* Fuzzy domain matching can produce false positives.
* Static URL analysis cannot determine every malicious destination.
* Reputation services may be unavailable or rate-limited.
* Advanced malware analysis is outside the scope of this project.

The output should therefore be treated as **analyst decision support**, not absolute ground truth.

---

## Future Improvements

Planned improvements include:

* Microsoft Defender / Graph integration
* AbuseIPDB integration
* URLScan integration
* More advanced DNS analysis
* WHOIS-based enrichment
* Attachment hash generation
* YARA integration
* File sandbox integration
* QR-code phishing detection
* OCR-based phishing detection
* Screenshot analysis of suspicious webpages
* Machine-learning assisted classification
* REST API
* Web dashboard
* SIEM integration
* Splunk ingestion
* Microsoft Sentinel integration
* Automated incident-response workflows
* STIX/TAXII threat-intelligence support

---

## SOC Use Case

A possible SOC workflow would look like:

```text
              Incoming Email
                    │
                    ▼
            Email Analyzer
                    │
        ┌───────────┴───────────┐
        │                       │
        ▼                       ▼
     Extract                 Analyze
      IOCs                   Signals
        │                       │
        └───────────┬───────────┘
                    ▼
               Risk Score
                    │
          ┌─────────┼─────────┐
          │         │         │
          ▼         ▼         ▼
         LOW    SUSPICIOUS   HIGH+
          │         │         │
          ▼         ▼         ▼
       Monitor   Analyst    Investigate
                    Review       │
                                 ▼
                         Threat Intelligence
                                 │
                                 ▼
                           Containment
```

This mirrors the basic logic used in SOC environments:

**Collect → Enrich → Detect → Score → Investigate → Respond**

---

## Why I Built This

Phishing remains one of the most common initial-access techniques used against organizations.

I built this project to move beyond simply learning individual security tools and instead implement a small **detection-engineering pipeline** from the ground up.

The project demonstrates practical skills in:

* Email security
* Threat detection
* IOC analysis
* Threat intelligence
* Python automation
* Detection engineering
* Risk scoring
* Security testing
* CLI tooling
* SOC workflow design

The goal is to evolve the analyzer toward a system that could eventually feed detections into a SIEM or SOAR platform.

---

## Portfolio Relevance

This project demonstrates practical SOC Analyst capabilities rather than only theoretical cybersecurity knowledge.

It shows the ability to:

```text
Investigate suspicious emails
        ↓
Extract security-relevant evidence
        ↓
Develop detection logic
        ↓
Correlate multiple indicators
        ↓
Assign risk
        ↓
Explain the detection
        ↓
Automate the workflow
        ↓
Test the detection
```

That makes the project particularly relevant to:

* SOC Analyst
* Security Operations Analyst
* Blue Team Analyst
* Threat Detection Analyst
* Incident Response Analyst
* Junior Detection Engineer

---

## License

This project is intended for educational, research, and portfolio purposes.

Use responsibly and only against emails, systems, and infrastructure that you are authorized to analyze.
