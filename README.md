A Python-based phishing email analysis tool designed to assist SOC analysts in triaging suspicious emails.

The analyzer parses `.eml` files, extracts email headers and indicators of compromise (IOCs), analyzes sender and URL characteristics, performs optional OSINT reputation checks, and calculates a risk score indicating the likelihood that an email is a phishing attempt.

## Features

* Parse `.eml` email files
* Analyze email headers
* Extract sender, recipient, Reply-To and Message-ID information
* Detect sender/Reply-To mismatches
* Analyze SPF, DKIM and DMARC results
* Extract URLs, domains and IP addresses
* Detect suspicious URL characteristics
* Perform optional domain/IP reputation checks
* Identify common phishing indicators
* Calculate a risk score from 0–100
* Generate an analyst-friendly investigation report
* Command-line interface
* Unit tests for core analysis functions

## Project Goals

This project was built as a practical cybersecurity portfolio project to demonstrate skills relevant to a Security Operations Center (SOC) environment.

The primary objectives are:

1. Automate repetitive phishing-email triage tasks.
2. Extract useful indicators from suspicious emails.
3. Combine multiple signals into a transparent risk score.
4. Provide security analysts with an explainable verdict.
5. Demonstrate practical Python, email analysis and OSINT skills.

## Example Workflow

```text
Suspicious .eml file
        ↓
Email/Header Parsing
        ↓
IOC Extraction
        ↓
Header & Authentication Analysis
        ↓
URL & Domain Analysis
        ↓
OSINT Reputation Checks
        ↓
Risk Scoring
        ↓
Analyst Report
```

## Risk Classification

|  Score | Classification |
| -----: | -------------- |
|   0–29 | Low Risk       |
|  30–59 | Suspicious     |
|  60–79 | High Risk      |
| 80–100 | Critical       |

The score is intended to assist analyst triage and should not be treated as definitive proof that an email is malicious.

## Technologies

* Python
* Email parsing
* Regular expressions
* DNS/RDAP
* OSINT
* REST APIs
* JSON
* Pytest
* Git/GitHub

## Security Considerations

Sample emails used for testing should be sanitized and should not contain real credentials, personal information or sensitive organizational data.

API credentials must never be committed to the repository.

Malicious URLs should not be opened directly during analysis. URL investigation should be performed through appropriate security-analysis services or controlled environments.

## Future Improvements

* HTML email analysis
* Attachment analysis
* YARA integration
* Malware sandbox integration
* Screenshot generation for suspicious URLs
* Machine-learning-assisted classification
* Microsoft Defender/Sentinel integration
* Automated incident-report generation
* Web-based analyst dashboard
* SIEM ingestion

## Disclaimer

This project is intended for cybersecurity education, defensive security analysis and SOC training.

The risk score is an analytical aid and does not guarantee that an email is malicious or legitimate.
