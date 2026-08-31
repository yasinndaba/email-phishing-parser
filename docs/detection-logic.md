# Phishing Email Analyzer — Detection Logic

## 1. Purpose

The Phishing Email Analyzer uses multiple detection rules to identify characteristics commonly associated with phishing and social-engineering attacks.

No individual rule is treated as definitive proof of phishing. Instead, the analyzer collects independent signals and combines them into a risk score.

The detection pipeline evaluates:

```text
Email Authentication
        +
Header Anomalies
        +
IOC Analysis
        +
URL Characteristics
        +
Brand Impersonation
        +
Domain Reputation
        +
VirusTotal Intelligence
        +
HTML Indicators
        +
Attachment Indicators
        +
Content Indicators
        ↓
   Risk Score
        ↓
 Severity
```

This approach reduces dependence on a single detection mechanism and provides analysts with explainable findings.

---

# 2. Email Authentication Rules

## 2.1 SPF Failure

### What it looks for

The analyzer checks the email's SPF authentication result.

```text
SPF = fail
```

### Why it matters

Sender Policy Framework (SPF) allows a domain to specify which mail servers are authorized to send email on its behalf.

A failed SPF check can indicate that the sending infrastructure is not authorized by the claimed domain.

Attackers frequently send phishing emails from infrastructure that is unrelated to the impersonated organization.

### Risk contribution

```text
SPF failure: +20
```

Example:

```text
SPF: FAIL
```

Finding:

```text
SPF authentication failed.
```

---

# 3. DKIM Failure

### What it looks for

The analyzer checks whether the DKIM authentication result is:

```text
DKIM = fail
```

### Why it matters

DomainKeys Identified Mail (DKIM) uses cryptographic signatures to help verify that a message was authorized by the sending domain and was not altered after signing.

A failed DKIM check can indicate authentication problems or message tampering.

### Risk contribution

```text
DKIM failure: +20
```

Finding:

```text
DKIM authentication failed.
```

---

# 4. DMARC Failure

### What it looks for

The analyzer checks:

```text
DMARC = fail
```

### Why it matters

DMARC builds on SPF and DKIM and helps domains specify how receiving systems should handle messages that fail authentication or alignment checks.

A DMARC failure is particularly relevant when an attacker is impersonating a known organization.

### Risk contribution

```text
DMARC failure: +15
```

Finding:

```text
DMARC authentication failed.
```

---

# 5. Reply-To Mismatch

### What it looks for

The analyzer compares the sender's domain with the Reply-To domain.

Example:

```text
From:
security@micros0ft-support.com

Reply-To:
attacker@evil-example.com
```

### Why it matters

An attacker may make the visible sender appear legitimate while redirecting responses to infrastructure they control.

This technique can be used to collect:

* Credentials
* Sensitive information
* Financial information
* Victim responses

### Risk contribution

```text
Reply-To mismatch: +15
```

Finding:

```text
Reply-To address differs from sender domain.
```

---

# 6. Return-Path Mismatch

### What it looks for

The analyzer compares the Return-Path domain with the sender domain.

### Why it matters

The Return-Path identifies the address used for handling email bounces.

A mismatch is not automatically malicious because legitimate email infrastructure can use different domains.

However, when combined with authentication failures and other phishing indicators, it can increase confidence that the message is suspicious.

### Risk contribution

```text
Return-Path mismatch: +10
```

Finding:

```text
Return-Path differs from sender domain.
```

---

# 7. URL Analysis Rules

The URL analyzer evaluates each extracted URL independently.

Each URL receives its own score and findings.

---

# 8. Non-HTTPS URL

### What it looks for

The analyzer checks whether the URL uses HTTPS.

Example:

```text
http://example.com/login
```

### Why it matters

HTTPS provides encryption and server authentication.

Its absence does not prove that a URL is malicious, but phishing infrastructure may use unencrypted HTTP.

### Risk contribution

```text
HTTP URL: +10
```

Finding:

```text
URL does not use HTTPS.
```

HTTPS itself should not be interpreted as proof that a URL is safe. Attackers can obtain valid TLS certificates.

---

# 9. IP-Based URL

### What it looks for

The analyzer checks whether the URL uses an IP address instead of a domain.

Example:

```text
https://192.168.1.50/login
```

### Why it matters

Legitimate organizations generally use recognizable domain names for user-facing services.

An IP address can make infrastructure harder for victims to recognize and may be used by temporary phishing infrastructure.

### Risk contribution

```text
IP-based URL: +25
```

Finding:

```text
URL uses an IP address instead of a domain name.
```

This is one of the stronger URL-level indicators.

---

# 10. Suspicious TLD

### What it looks for

The analyzer maintains a list of TLDs frequently observed in suspicious or abusive infrastructure.

Examples include:

```text
.zip
.click
.download
.work
.top
.xyz
.tk
.gq
```

### Why it matters

Some inexpensive or heavily abused TLDs can appear frequently in malicious infrastructure.

However, a suspicious TLD is not inherently malicious.

For this reason, it is treated as a supporting signal.

### Risk contribution

```text
Suspicious TLD: +15
```

Finding:

```text
Domain uses a potentially suspicious TLD.
```

---

# 11. Excessive Subdomains

### What it looks for

The analyzer counts domain components.

Example:

```text
login.security.account.example.com
```

This contains multiple subdomains.

### Why it matters

Attackers can create long domain structures designed to make a malicious domain appear legitimate.

For example:

```text
microsoft.com.security-login.example.com
```

The presence of `microsoft.com` in the hostname may visually deceive users even though the actual registrable domain is `example.com`.

### Risk contribution

```text
Excessive subdomains: +10
```

The rule is triggered when the hostname contains more than three domain components.

---

# 12. Unusually Long URL

### What it looks for

The analyzer checks the total URL length.

URLs longer than the configured threshold are considered suspicious.

Current threshold:

```text
> 100 characters
```

### Why it matters

Long URLs may contain:

* Tracking parameters
* Encoded data
* Redirect parameters
* Obfuscated destinations
* Large query strings

Attackers may use these techniques to hide the actual destination.

### Risk contribution

```text
Long URL: +10
```

Finding:

```text
URL is unusually long.
```

---

# 13. Suspicious URL Keywords

### What it looks for

The analyzer searches the URL for keywords commonly associated with credential theft and account manipulation.

Examples:

```text
login
signin
verify
verification
account
password
credential
secure
security
update
confirm
authenticate
microsoft
paypal
apple
bank
```

### Why it matters

Phishing URLs frequently attempt to convince victims to:

* Log in
* Verify their identity
* Update account information
* Confirm credentials
* Resolve a supposed security issue

### Risk contribution

The analyzer adds:

```text
5 points per matched keyword
```

with a maximum contribution of:

```text
15 points
```

Example:

```text
https://example.com/verify/account/login
```

could match multiple keywords.

Finding:

```text
URL contains potentially suspicious keywords: account, login, verify
```

The keyword rule is intentionally capped to prevent URLs containing many keywords from dominating the entire analysis.

---

# 14. `@` Symbol in URL

### What it looks for

The analyzer checks whether an `@` symbol appears in the URL's network location.

Example:

```text
https://trusted.example@evil.example/login
```

### Why it matters

In URLs, the portion before `@` can represent user information while the actual hostname appears after it.

Attackers can abuse this behavior to make a URL visually appear associated with a trusted domain.

### Risk contribution

```text
@ symbol: +20
```

Finding:

```text
URL contains '@', which can be used to obscure the destination.
```

---

# 15. Excessive Hyphens

### What it looks for

The analyzer counts hyphens in the hostname.

Example:

```text
microsoft-account-security-login.example.com
```

### Why it matters

Phishing domains frequently use combinations of brand names and descriptive security terms.

Examples:

```text
microsoft-security-login.example
paypal-account-verification.example
apple-id-security.example
```

A high number of hyphens can therefore be a useful supporting indicator.

### Risk contribution

```text
3 or more hyphens: +10
```

---

# 16. Percent-Encoding

### What it looks for

The analyzer searches for percent-encoded characters.

Example:

```text
https://example.com/%6c%6f%67%69%6e
```

### Why it matters

Encoding can make URLs harder to read and may be used to obscure paths or parameters.

Encoding is also common in legitimate URLs, so this should not be interpreted as malicious by itself.

### Risk contribution

```text
Percent encoding: +5
```

Finding:

```text
URL contains percent-encoded characters.
```

---

# 17. Brand Impersonation

### What it looks for

The analyzer compares the hostname against known organizations.

Currently supported brands include:

```text
Microsoft
PayPal
Apple
Google
Amazon
LinkedIn
Facebook
```

The analyzer uses fuzzy string comparison to detect domains that resemble known brands without actually belonging to them.

Example:

```text
Expected:

microsoft.com

Observed:

micros0ft-support.com
```

### Why it matters

Typosquatting and lookalike domains are common phishing techniques.

Attackers may replace characters:

```text
o → 0
i → 1
l → 1
```

or append terms such as:

```text
-support
-security
-login
-verification
```

### Risk contribution

Brand impersonation contributes additional URL risk and produces a structured result containing:

```text
detected
brand
observed_domain
expected_domain
similarity
```

Example finding:

```text
Possible Microsoft brand impersonation detected.
Observed domain: micros0ft-support.com
Expected domain: microsoft.com
```

This is a high-value detection because it directly addresses impersonation of trusted organizations.

---

# 18. Domain Reputation

### What it looks for

The reputation module attempts to obtain information about the extracted domain.

Depending on the available provider, this may include:

```text
Domain reputation
Resolution status
Known malicious indicators
Suspicious indicators
External threat intelligence
```

### Why it matters

A domain may have characteristics that cannot be determined from the URL structure alone.

External reputation can provide additional context about previously observed malicious infrastructure.

### Risk contribution

Reputation is treated as an enrichment signal rather than absolute truth.

This is important because:

* New malicious domains may have no reputation
* Legitimate domains may occasionally be flagged incorrectly
* Reputation providers can disagree
* APIs can become unavailable

Unavailable reputation data should therefore not automatically increase the risk score.

---

# 19. VirusTotal Intelligence

### What it looks for

When configured with a VirusTotal API key, the analyzer can query threat intelligence associated with domains or URLs.

Potential information includes:

```text
Malicious detections
Suspicious detections
Security vendor verdicts
Reputation information
```

### Why it matters

Multiple independent security vendors identifying the same infrastructure as malicious provides stronger evidence than a local heuristic alone.

### Risk contribution

VirusTotal results are converted into a bounded reputation signal.

The score is capped to prevent an external service from completely dominating the analysis.

If no API key is configured, the analyzer continues operating without VirusTotal enrichment.

---

# 20. Content Analysis

The content analyzer evaluates the language contained in the email body.

---

# 21. Urgency Indicators

### What it looks for

Examples include:

```text
urgent
immediately
within 24 hours
act now
```

### Why it matters

Phishing campaigns often create artificial urgency to prevent victims from carefully examining the message.

The attacker wants the victim to act before questioning the request.

### Risk contribution

Matched urgency indicators contribute to the content score.

Example:

```text
Urgency indicators detected:
urgent, immediately, within 24 hours
```

---

# 22. Account Threat Indicators

### What it looks for

Examples:

```text
suspended
suspension
locked
disabled
terminated
```

### Why it matters

Attackers frequently claim that an account will be disabled or suspended unless the victim takes immediate action.

This creates fear and increases the likelihood that the victim will follow the attacker's instructions.

### Risk contribution

Matched account-threat indicators increase the content score.

Example:

```text
Account Threat indicators detected:
suspended, suspension
```

---

# 23. Credential Request Indicators

### What it looks for

Examples include:

```text
verify your identity
confirm your password
enter your credentials
verify your account
```

### Why it matters

Credential harvesting is one of the primary objectives of phishing attacks.

Requests for passwords, authentication details, or identity verification are therefore highly relevant.

### Risk contribution

Credential-request indicators increase the content score.

Example:

```text
Credential Request indicators detected:
verify your identity
```

---

# 24. Call-to-Action Indicators

### What it looks for

Examples:

```text
click here
complete verification
sign in
confirm now
verify now
```

### Why it matters

Phishing emails generally attempt to move the victim from reading the email to performing an action.

The action may lead to:

* Credential theft
* Malware delivery
* Fraud
* Data disclosure

### Risk contribution

Call-to-action indicators increase the content score.

---

# 25. Security Alert Indicators

### What it looks for

Examples include:

```text
suspicious activity
security alert
unusual login
unauthorized access
```

### Why it matters

Attackers often impersonate security teams and claim that suspicious activity has been detected.

The goal is to make the victim believe that immediate account verification is necessary.

### Risk contribution

Security-alert indicators increase the content score.

---

# 26. HTML Analysis

HTML messages receive additional inspection because the visible content may differ from the underlying HTML.

---

# 27. HTML Link Extraction

### What it looks for

The analyzer extracts links from HTML elements such as:

```html
<a href="https://example.com">
```

### Why it matters

The destination embedded in HTML may not be obvious from the visible email text.

Extracted URLs are passed to the URL-analysis pipeline.

---

# 28. Link-Text Mismatch

### What it looks for

The analyzer compares the displayed link text with the actual destination.

Example:

```text
Visible:

https://microsoft.com

Actual destination:

https://micros0ft-support.com/verify
```

### Why it matters

This is a classic phishing technique.

The attacker displays a trusted destination while redirecting the victim somewhere else.

### Risk contribution

A mismatch contributes additional HTML/URL risk and generates an analyst-visible finding.

---

# 29. HTML Form Detection

### What it looks for

The analyzer checks for forms embedded in HTML email content.

Example:

```html
<form>
```

### Why it matters

A form inside an email can potentially be used to collect sensitive information.

Although modern email clients restrict many active behaviors, the presence of credential-style forms is still suspicious.

---

# 30. Script Detection

### What it looks for

The analyzer searches for potentially dangerous scripting elements.

Example:

```html
<script>
```

### Why it matters

Scripts inside email content can represent an attempted active-content attack or suspicious embedded functionality.

The analyzer does not execute the script.

It only identifies its presence.

---

# 31. Attachment Analysis

Attachments are treated as untrusted input.

The analyzer performs static inspection and does not execute attachment contents.

---

# 32. Executable Attachment Detection

### What it looks for

Examples:

```text
.exe
.scr
.bat
.cmd
.com
.ps1
```

### Why it matters

Executable attachments can directly deliver malware or initiate malicious commands when executed by a victim.

### Risk contribution

Executable attachments contribute significantly to attachment risk.

---

# 33. Suspicious Extension Detection

### What it looks for

The analyzer checks attachment extensions against a list of potentially dangerous or suspicious file types.

### Why it matters

Attackers may disguise malicious files as ordinary documents or use uncommon extensions to evade user awareness.

### Risk contribution

Suspicious extensions contribute additional attachment risk.

---

# 34. Double Extension Detection

### What it looks for

Examples:

```text
invoice.pdf.exe
document.docx.exe
photo.jpg.scr
```

### Why it matters

Double extensions exploit the fact that operating systems may hide known file extensions.

A victim may see:

```text
invoice.pdf
```

while the actual file is:

```text
invoice.pdf.exe
```

### Risk contribution

Double-extension detection adds attachment risk and generates a finding.

---

# 35. Macro-Enabled Document Detection

### What it looks for

Examples:

```text
.docm
.xlsm
.pptm
```

### Why it matters

Macro-enabled Office documents can contain VBA macros capable of performing malicious actions when enabled.

The extension alone does not prove that the document is malicious, but it is an important phishing indicator.

### Risk contribution

Macro-enabled documents contribute additional attachment risk.

---

# 36. MIME/Extension Mismatch

### What it looks for

The analyzer compares the declared MIME type against the filename extension.

Example:

```text
Filename:
invoice.pdf

MIME:
application/x-msdownload
```

### Why it matters

An attacker may disguise a malicious file using a misleading filename.

A mismatch between the declared file type and filename can reveal this technique.

### Risk contribution

MIME mismatches increase attachment risk.

---

# 37. Risk Score Caps

Individual analysis components are bounded to prevent one category from dominating the entire system.

Examples include:

```text
Header score: capped
URL score: capped
Content score: capped
Attachment score: capped
Reputation score: capped
Final score: 0–100
```

The final risk score is always constrained to:

```text
0–100
```

This keeps the scoring system predictable and makes results easier to interpret.

---

# 38. Severity Classification

The final score is mapped to a severity level.

```text
0–29     LOW
30–59    SUSPICIOUS
60–79    HIGH
80–100   CRITICAL
```

The severity is intended for prioritization rather than absolute classification.

For example:

```text
95 → CRITICAL
72 → HIGH
45 → SUSPICIOUS
15 → LOW
```

---

# 39. Why Multiple Indicators Matter

The analyzer follows an evidence-based approach.

Consider this message:

```text
From:
security@micros0ft-support.com

SPF:
FAIL

DKIM:
FAIL

DMARC:
FAIL

Reply-To:
attacker@evil-example.com

URL:
https://micros0ft-support.com/verify

Content:
"Your account will be suspended.
Verify your identity immediately."
```

No single indicator proves that the message is phishing.

However, the indicators reinforce each other:

```text
Authentication failures
        +
Header mismatches
        +
Brand impersonation
        +
Suspicious URL
        +
Credential request
        +
Urgency
        +
Account threat
```

The combined evidence produces a much stronger assessment.

---

# 40. False Positive Considerations

Detection rules are heuristic and can produce false positives.

Examples:

A legitimate email may:

```text
Use a long URL
Use HTTP
Contain "verify"
Use a third-party Reply-To address
Use a suspicious-looking TLD
Contain an attachment
```

Therefore:

> A detection finding is evidence, not proof.

The analyzer should support analyst decision-making rather than replace human investigation.

---

# 41. Detection Philosophy

The project follows four principles:

### 1. Explainability

Every significant score contribution should have an associated finding.

### 2. Defense in Depth

Multiple independent indicators are preferred over a single detection rule.

### 3. Safe Analysis

Suspicious URLs and attachments are inspected statically rather than executed or automatically opened.

### 4. Graceful Degradation

External services such as reputation and VirusTotal should enhance the analysis without becoming mandatory dependencies.

---

# 42. Example Detection Chain

For the included phishing sample:

```text
Email
 │
 ├── SPF FAIL ────────────────► +20
 ├── DKIM FAIL ───────────────► +20
 ├── DMARC FAIL ──────────────► +15
 ├── Reply-To mismatch ───────► +15
 ├── Return-Path mismatch ────► +10
 │
 ├── Brand impersonation ─────► URL signal
 ├── "verify" keyword ────────► URL signal
 │
 ├── Urgency ─────────────────► Content signal
 ├── Account threat ──────────► Content signal
 ├── Credential request ──────► Content signal
 ├── Call to action ──────────► Content signal
 └── Security alert ──────────► Content signal
                  │
                  ▼
             Risk Engine
                  │
                  ▼
           97 / 100
                  │
                  ▼
              CRITICAL
```

This demonstrates how multiple weak and strong indicators can be combined into a single explainable security assessment.

---

# 43. Future Detection Improvements

Potential improvements include:

```text
DNS record analysis
Domain age detection
WHOIS enrichment
MX record analysis
SPF record inspection
DKIM alignment analysis
DMARC alignment analysis
Homograph detection
Unicode lookalike detection
Redirect-chain analysis
URL shortener detection
Certificate analysis
Geolocation analysis
Sender reputation
Threat-intelligence feeds
STIX/TAXII integration
Machine-learning classification
YARA integration
Sandbox integration
```

These should be added carefully so that additional signals improve detection quality without creating excessive false positives.

---

# 44. Summary

The analyzer uses layered detection rather than a single phishing rule.

The major detection categories are:

```text
Authentication
Header anomalies
IOC extraction
URL heuristics
Brand impersonation
Domain reputation
VirusTotal intelligence
Content analysis
HTML analysis
Attachment analysis
Risk scoring
```

The resulting verdict is therefore based on the combined evidence available at analysis time.

The system is designed to answer not only:

> "Is this email suspicious?"

but also:

> "Why is this email suspicious?"

That explainability is a core requirement for practical SOC analysis and incident investigation.
