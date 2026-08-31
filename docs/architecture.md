# Phishing Email Analyzer — Architecture

## 1. Overview

The Phishing Email Analyzer is a Python-based security analysis tool designed to examine suspicious email messages and identify indicators commonly associated with phishing attacks.

The analyzer follows a modular pipeline that processes an email from initial parsing through multiple detection stages before producing a final risk score and severity classification.

The primary workflow is:

```text
Email File (.eml)
       │
       ▼
┌─────────────────┐
│  Email Parser   │
└────────┬────────┘
         │
         ▼
┌──────────────────────────────────────────┐
│          Analysis Pipeline               │
│                                          │
│  ┌────────────┐    ┌──────────────┐      │
│  │  Headers   │    │     IOCs     │      │
│  │  Analysis  │    │  Extraction  │      │
│  └─────┬──────┘    └──────┬───────┘      │
│        │                  │              │
│        │          ┌───────▼───────┐      │
│        │          │ URL Analysis  │      │
│        │          └───────┬───────┘      │
│        │                  │              │
│        │          ┌───────▼────────┐     │
│        │          │   Reputation   │     │
│        │          │    Analysis    │     │
│        │          └───────┬────────┘     │
│        │                  │              │
│        │          ┌───────▼────────┐     │
│        │          │ HTML Analysis  │     │
│        │          └───────┬────────┘     │
│        │                  │              │
│        │          ┌───────▼────────┐     │
│        │          │   Attachment   │     │
│        │          │    Analysis    │     │
│        │          └───────┬────────┘     │
│        │                  │              │
│        │          ┌───────▼────────┐     │
│        └─────────►│    Content     │     │
│                   │    Analysis    │     │
│                   └───────┬────────┘     │
└───────────────────────────┼──────────────┘
                            │
                            ▼
                   ┌─────────────────┐
                   │   Risk Scoring  │
                   └────────┬────────┘
                            │
                            ▼
                   ┌─────────────────┐
                   │ Final Verdict   │
                   │                 │
                   │ LOW             │
                   │ SUSPICIOUS      │
                   │ HIGH            │
                   │ CRITICAL        │
                   └────────┬────────┘
                            │
                ┌───────────┴───────────┐
                ▼                       ▼
         Human-readable             JSON Output
              CLI                    / Automation
```

---

## 2. Design Goals

The architecture was designed around several security-analysis principles:

* Modular detection logic
* Explainable findings
* Multiple independent indicators
* Risk scoring instead of binary classification
* Safe handling of suspicious email content
* Automated testing
* CLI accessibility
* Machine-readable JSON output
* External reputation enrichment
* Extensibility for future detection modules

The analyzer does not rely on a single indicator to determine whether an email is malicious. Instead, multiple signals are collected and combined into an overall risk assessment.

---

## 3. Processing Pipeline

### 3.1 Email Input

The analyzer accepts email files in `.eml` format.

Example:

```bash
python -m cli.main samples/test_email.eml
```

The email is treated as untrusted input.

The analyzer extracts information such as:

* Sender
* Recipient
* Reply-To
* Return-Path
* Subject
* Authentication results
* Message body
* URLs
* Email addresses
* Domains
* IP addresses
* Attachments
* HTML content

---

### 3.2 Email Parser

The parser is responsible for converting the raw email message into structured data.

Module:

```text
analyzer/parser.py
```

The parser provides a normalized representation of the email that can be consumed by the other analysis modules.

Conceptually:

```text
Raw .eml
   │
   ▼
Email Parser
   │
   ├── Headers
   ├── Body
   ├── HTML
   └── Attachments
```

Keeping parsing separate from detection logic allows individual analyzers to operate independently.

---

## 4. Header Analysis

Module:

```text
analyzer/headers.py
```

The header analyzer examines email metadata and authentication results.

It currently evaluates indicators including:

* SPF
* DKIM
* DMARC
* Reply-To mismatches
* Return-Path mismatches
* Sender-domain relationships

Authentication failures contribute to the overall risk assessment.

For example:

```text
SPF:   FAIL
DKIM:  FAIL
DMARC: FAIL
```

Multiple authentication failures provide stronger evidence that the message may not originate from the claimed sender.

Header mismatches are also useful because attackers may use a legitimate-looking `From` address while directing replies to another domain.

---

## 5. IOC Extraction

Module:

```text
analyzer/iocs.py
```

The IOC extraction module identifies potentially useful indicators from the email.

Current IOC categories include:

```text
URLs
Domains
IP addresses
Email addresses
```

Example:

```text
URL:
https://micros0ft-support.com/verify

Domain:
micros0ft-support.com

Email:
attacker@evil-example.com
```

These indicators can then be passed to additional analysis modules.

IOC extraction is intentionally separated from IOC analysis. Extraction answers:

> What indicators are present?

Other modules answer:

> How suspicious are those indicators?

---

## 6. URL Analysis

Module:

```text
analyzer/urls.py
```

The URL analyzer examines URLs for characteristics frequently associated with phishing infrastructure.

Current checks include:

* HTTPS usage
* IP-based URLs
* Suspicious TLDs
* Excessive subdomains
* Unusually long URLs
* Suspicious keywords
* `@` symbols
* Excessive hyphens
* Percent encoding
* Brand impersonation

Example:

```text
https://micros0ft-support.com/verify
```

The analyzer can identify the similarity between:

```text
Observed:
micros0ft-support.com

Expected:
microsoft.com
```

This allows the system to detect common typosquatting and brand impersonation techniques.

Each URL receives its own analysis result and score.

---

## 7. Domain Reputation

Module:

```text
analyzer/reputation.py
```

The reputation module enriches extracted domains with external information where available.

The architecture separates reputation enrichment from the core URL analysis.

This is important because external reputation services may be:

* unavailable
* rate-limited
* missing an API key
* temporarily inaccessible
* unable to identify a domain

The analyzer therefore treats reputation data as enrichment rather than a mandatory dependency.

A failed reputation lookup should not cause the entire email analysis to fail.

---

## 8. VirusTotal Integration

Module:

```text
analyzer/virustotal.py
```

VirusTotal can be used to enrich domain and URL analysis with threat-intelligence information.

The integration is designed to degrade gracefully when an API key is unavailable.

Conceptually:

```text
IOC
 │
 ▼
VirusTotal
 │
 ├── Malicious detections
 ├── Suspicious detections
 ├── Reputation
 └── No available data
```

External intelligence is treated as one signal among several rather than the sole basis for the final verdict.

---

## 9. HTML Analysis

Module:

```text
analyzer/html_analysis.py
```

HTML emails can contain additional phishing indicators that are not visible from plain-text analysis.

The HTML analyzer checks for indicators such as:

* Embedded links
* Suspicious URLs
* Link-text mismatches
* IP-based links
* HTML forms
* JavaScript
* Other potentially dangerous HTML structures

For example:

```text
Displayed text:

    https://microsoft.com

Actual destination:

    https://micros0ft-support.com/verify
```

A mismatch between what the user sees and the actual destination can be a strong phishing indicator.

---

## 10. Attachment Analysis

Module:

```text
analyzer/attachments.py
```

Attachments are analyzed for characteristics commonly associated with malicious or socially engineered email attachments.

The analyzer checks for indicators including:

* Executable files
* Suspicious extensions
* Double extensions
* Macro-enabled documents
* MIME/extension mismatches

Examples:

```text
invoice.pdf.exe
document.docm
image.jpg.exe
```

Attachment analysis contributes additional evidence to the overall assessment.

The analyzer does not execute attachments.

This is an important security boundary.

---

## 11. Content Analysis

Module:

```text
analyzer/content.py
```

The content analyzer evaluates the message body for language commonly associated with phishing and social engineering.

Current detection categories include:

```text
Urgency
Account threats
Credential requests
Calls to action
Security alerts
```

Example:

```text
"Your account will be suspended."

"Verify your identity immediately."

"Complete verification within 24 hours."
```

The analyzer converts these indicators into a content risk score.

Content analysis is intentionally heuristic. The presence of a suspicious phrase does not automatically mean that an email is malicious.

---

## 12. Risk Scoring

Module:

```text
analyzer/scoring.py
```

The scoring engine combines evidence from the different analysis stages.

The architecture uses multiple component scores:

```text
Header Risk
URL Risk
Content Risk
Reputation Risk
Attachment Risk
HTML Risk
```

These signals are combined into an overall risk score.

The final score is capped at:

```text
100
```

The scoring system is designed to be explainable.

Instead of simply returning:

```text
PHISHING
```

the analyzer can explain why the message received its score.

Example:

```text
SPF authentication failed.
DKIM authentication failed.
DMARC authentication failed.
Reply-To address differs from sender domain.
Possible Microsoft brand impersonation detected.
URL contains potentially suspicious keywords.
Urgency indicators detected.
Credential request detected.
```

This makes the tool more useful for SOC analysts and incident responders.

---

## 13. Severity Classification

The final numerical score is converted into a severity level.

```text
0–29    LOW
30–59   SUSPICIOUS
60–79   HIGH
80–100  CRITICAL
```

The severity classification provides a simple way for analysts or automation systems to prioritize messages.

---

## 14. Analysis Engine

Module:

```text
analyzer/engine.py
```

The engine orchestrates the complete pipeline.

Conceptually:

```text
                  ┌──────────────┐
                  │ Email Parser │
                  └──────┬───────┘
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
     Headers           IOCs             Content
        │                │                │
        │        ┌───────┼────────┐       │
        │        ▼       ▼        ▼       │
        │       URLs Reputation HTML      │
        │        │       │        │       │
        │        └───────┼────────┘       │
        │                │                │
        │          Attachments            │
        │                │                │
        └────────────────┼────────────────┘
                         ▼
                  ┌──────────────┐
                  │ Risk Scoring │
                  └──────┬───────┘
                         ▼
                  ┌──────────────┐
                  │ Final Report │
                  └──────────────┘
```

The engine keeps orchestration separate from individual detection mechanisms.

This makes it possible to add new analyzers without rewriting the entire application.

---

## 15. CLI Layer

Module:

```text
cli/main.py
```

The command-line interface provides a user-facing interface to the analysis engine.

Example:

```bash
python -m cli.main samples/test_email.eml
```

The CLI supports:

```text
Human-readable output
JSON output
Quiet mode
Error handling
```

Human-readable output is designed for analysts.

JSON output is designed for:

* Automation
* SIEM ingestion
* SOAR workflows
* Scripts
* Future web interfaces
* API integrations

---

## 16. Testing Architecture

The project uses `pytest` for automated testing.

Test modules are located under:

```text
tests/
```

The tests cover individual components as well as the complete analysis pipeline.

Current test areas include:

```text
Parser
Headers
IOCs
URLs
Content
Scoring
Reputation
VirusTotal
HTML analysis
Attachments
CLI
Engine integration
```

The project currently contains a comprehensive automated test suite.

All tests should pass before major changes are committed.

Example:

```bash
python -m pytest -v
```

Expected result:

```text
50 passed
```

---

## 17. Project Structure

The current architecture is organized approximately as follows:

```text
email-phishing-parser/
│
├── analyzer/
│   ├── __init__.py
│   ├── parser.py
│   ├── headers.py
│   ├── iocs.py
│   ├── urls.py
│   ├── reputation.py
│   ├── virustotal.py
│   ├── content.py
│   ├── html_analysis.py
│   ├── attachments.py
│   ├── scoring.py
│   └── engine.py
│
├── cli/
│   └── main.py
│
├── samples/
│   └── test_email.eml
│
├── tests/
│   ├── test_parser.py
│   ├── test_headers.py
│   ├── test_iocs.py
│   ├── test_urls.py
│   ├── test_content.py
│   ├── test_reputation.py
│   ├── test_virustotal.py
│   ├── test_html_analysis.py
│   ├── test_attachments.py
│   ├── test_scoring.py
│   ├── test_engine.py
│   └── test_cli.py
│
├── docs/
│   └── architecture.md
│
├── README.md
├── requirements.txt
└── .gitignore
```

---

## 18. Security Boundaries

The analyzer is designed to inspect potentially malicious email content without interacting with the infrastructure contained within the message.

The tool should:

* Parse email content locally
* Extract indicators without visiting them
* Avoid automatically opening URLs
* Avoid executing attachments
* Treat HTML as untrusted input
* Handle external reputation services separately
* Never treat an external reputation result as absolute truth

The analyzer is therefore primarily a **static analysis tool**.

It should not be considered a malware sandbox or detonation environment.

---

## 19. Extensibility

The modular architecture allows additional detection capabilities to be added later.

Potential future modules include:

```text
├── DNS analysis
├── WHOIS analysis
├── URL redirect analysis
├── Homograph detection
├── Sender reputation
├── Domain age analysis
├── MX record analysis
├── Geographic/IP reputation
├── YARA integration
├── ML-based classification
├── Attachment hashing
├── Sandbox integration
├── STIX/TAXII enrichment
└── SIEM integration
```

Future integrations could also allow the analyzer to operate as part of a SOC workflow:

```text
Email
  │
  ▼
Phishing Analyzer
  │
  ▼
Risk Score
  │
  ├── LOW ─────────────► Archive
  │
  ├── SUSPICIOUS ──────► Analyst Review
  │
  ├── HIGH ────────────► SOC Investigation
  │
  └── CRITICAL ────────► Incident Response
```

---

## 20. Example Analysis

For the included phishing sample, the analyzer identifies multiple independent indicators.

```text
Authentication:
    SPF   → FAIL
    DKIM  → FAIL
    DMARC → FAIL

Header anomalies:
    Reply-To mismatch
    Return-Path mismatch

IOC:
    micros0ft-support.com

URL:
    Microsoft brand impersonation
    Suspicious keyword: verify

Content:
    Urgency indicators
    Account suspension threat
    Credential request
    Call to action
    Security alert
```

The combined evidence produces a high-confidence phishing assessment.

Example result:

```text
VERDICT:    CRITICAL
RISK SCORE: 97/100
```

The important architectural principle is that the verdict is supported by multiple observable indicators rather than a single rule.

---

## 21. Architectural Summary

The Phishing Email Analyzer uses a layered, modular architecture:

```text
Input
  │
  ▼
Parsing
  │
  ▼
Extraction
  │
  ├── Header Analysis
  ├── IOC Extraction
  ├── URL Analysis
  ├── Reputation
  ├── HTML Analysis
  ├── Attachment Analysis
  └── Content Analysis
          │
          ▼
     Risk Scoring
          │
          ▼
   Severity Classification
          │
          ▼
      Final Report
```

This architecture provides three major benefits:

1. **Explainability** — analysts can see which indicators contributed to the verdict.

2. **Modularity** — individual detection modules can be improved or replaced independently.

3. **Extensibility** — additional threat-intelligence sources, detection techniques, and automation integrations can be added without redesigning the entire application.

The overall design is intended to demonstrate practical SOC analyst skills including email investigation, IOC analysis, threat intelligence enrichment, detection engineering, risk assessment, automation, and security-focused Python development.
