# Phishing Email Analyzer — Detection Rules

## Overview

The Phishing Email Analyzer uses multiple detection layers to identify characteristics commonly associated with phishing emails.

The analyzer does not rely on a single indicator. Instead, it combines email authentication results, header anomalies, URL analysis, email content, HTML characteristics, attachments, domain reputation, and external reputation data.

Each detection produces findings and, where appropriate, contributes to the overall risk score.

The objective is to provide analysts with explainable detections rather than simply returning a binary malicious/benign verdict.

---

## Detection Pipeline

The analyzer follows this general workflow:

```text
                    Email (.eml)
                         |
                         v
                  +--------------+
                  | Email Parser |
                  +--------------+
                         |
          +--------------+--------------+
          |              |              |
          v              v              v
      Headers          IOCs          Content
          |              |              |
          v              v              v
   Authentication      URLs         Phishing
   Mismatches          Domains      Indicators
                       IPs          HTML
                       Emails       Attachments
          |              |              |
          +--------------+--------------+
                         |
                         v
                 Reputation Analysis
                         |
                         v
                   Risk Scoring
                         |
                         v
              Severity Classification
                         |
                         v
                 Analyst Report
```

The system is designed so that each layer can operate independently while contributing evidence to the final analysis.

---

# 1. Email Authentication

Email authentication detections examine SPF, DKIM, and DMARC results extracted from the email headers.

These mechanisms help determine whether an email was authorized to use a particular domain and whether its authentication requirements were satisfied.

## 1.1 SPF Failure

### What it looks for

The analyzer checks whether the SPF result is:

```text
fail
```

### Why it matters

Sender Policy Framework (SPF) allows a domain to specify which mail servers are authorized to send email on its behalf.

An SPF failure can indicate that the sending server is not authorized by the claimed domain.

This is particularly important when an email attempts to impersonate a trusted organization.

### Risk contribution

```text
SPF failure: +20
```

Example:

```text
SPF: FAIL
```

Detection:

```text
SPF authentication failed.
```

---

## 1.2 DKIM Failure

### What it looks for

The analyzer checks whether the DKIM authentication result is:

```text
fail
```

### Why it matters

DomainKeys Identified Mail (DKIM) provides cryptographic verification that an email was signed by an authorized system and that the signed content has not been improperly modified.

A failed DKIM check reduces confidence in the authenticity of the message.

### Risk contribution

```text
DKIM failure: +20
```

Detection:

```text
DKIM authentication failed.
```

---

## 1.3 DMARC Failure

### What it looks for

The analyzer checks whether the DMARC result is:

```text
fail
```

### Why it matters

DMARC builds on SPF and DKIM and provides domain-alignment and policy enforcement.

A DMARC failure is particularly relevant to phishing because attackers frequently attempt to impersonate legitimate organizations.

### Risk contribution

```text
DMARC failure: +15
```

Detection:

```text
DMARC authentication failed.
```

---

# 2. Header Mismatch Detection

Header analysis looks for inconsistencies between the visible sender and other email-routing information.

These checks are useful because attackers can make the visible sender appear trustworthy while using different infrastructure behind the scenes.

---

## 2.1 Reply-To Mismatch

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

A different Reply-To address can redirect responses to an attacker-controlled mailbox.

This is commonly useful in phishing campaigns where the attacker wants victims to respond with credentials, sensitive information, or other data.

### Risk contribution

```text
Reply-To mismatch: +15
```

Detection:

```text
Reply-To address differs from sender domain.
```

---

## 2.2 Return-Path Mismatch

### What it looks for

The analyzer compares the Return-Path domain with the sender domain.

### Why it matters

The Return-Path identifies the address used for email delivery and bounce handling.

A mismatch does not automatically mean that an email is malicious because legitimate email infrastructure can use different domains. However, combined with other indicators, it can increase suspicion.

### Risk contribution

```text
Return-Path mismatch: +10
```

Detection:

```text
Return-Path differs from sender domain.
```

---

# 3. IOC Extraction

IOC extraction identifies potentially useful indicators from the email.

The analyzer extracts:

```text
URLs
Domains
IP addresses
Email addresses
```

### Why it matters

Indicators of Compromise (IOCs) allow analysts to investigate and correlate suspicious activity.

For example, a suspicious domain extracted from an email can be searched across:

* SIEM logs
* DNS logs
* Proxy logs
* Endpoint telemetry
* Threat intelligence platforms
* VirusTotal
* Firewall logs

IOC extraction itself is primarily an analysis/enrichment step rather than a direct risk score.

---

# 4. URL Analysis

URLs are one of the most important phishing indicators because phishing emails frequently attempt to redirect victims to credential-harvesting or malicious websites.

The analyzer evaluates several URL characteristics.

---

## 4.1 HTTPS Detection

### What it looks for

The analyzer checks whether the URL uses:

```text
https://
```

### Why it matters

HTTPS encrypts traffic between the browser and website, but it does **not** prove that a website is legitimate.

Attackers can obtain HTTPS certificates for malicious domains.

Therefore, HTTPS is treated as a contextual signal rather than proof of legitimacy.

### Risk contribution

```text
No HTTPS: +10
```

---

# 5. IP-Based URLs

### What it looks for

The analyzer determines whether the hostname is a raw IPv4 or IPv6 address.

Example:

```text
http://192.168.1.50/login
```

### Why it matters

Legitimate services normally use recognizable domain names.

An IP address can be used to hide the identity of the destination and is therefore a useful phishing signal.

### Risk contribution

```text
IP-based URL: +25
```

Detection:

```text
URL uses an IP address instead of a domain name.
```

---

# 6. Suspicious TLD Detection

### What it looks for

The analyzer checks the domain against a list of potentially suspicious top-level domains.

Examples include:

```text
.zip
.mov
.click
.download
.work
.country
.gq
.tk
.top
.xyz
```

### Why it matters

Some TLDs have historically been heavily abused for malicious infrastructure.

However, a suspicious TLD does not automatically mean a domain is malicious.

### Risk contribution

```text
Suspicious TLD: +15
```

Detection:

```text
Domain uses a potentially suspicious TLD.
```

---

# 7. Excessive Subdomain Detection

### What it looks for

The analyzer counts domain components.

Example:

```text
login.security.account.example.com
```

This contains multiple subdomains.

### Why it matters

Attackers can create complicated domain structures designed to make the legitimate-looking portion of a domain appear more prominent.

Example:

```text
microsoft.com.attacker.example
```

The presence of `microsoft.com` may visually deceive a victim even though the actual registered domain is `attacker.example`.

### Risk contribution

```text
Excessive subdomains: +10
```

The detection is triggered when the hostname contains more than three domain components.

---

# 8. URL Length

### What it looks for

The analyzer checks whether the URL exceeds:

```text
100 characters
```

### Why it matters

Long URLs can contain:

* Tracking parameters
* Encoded data
* Redirect chains
* Obfuscated paths
* Long query strings
* Phishing payload parameters

Long URLs are not inherently malicious, so this is a weak contextual indicator.

### Risk contribution

```text
URL length > 100: +10
```

---

# 9. Suspicious URL Keywords

### What it looks for

The analyzer searches URLs for keywords commonly associated with authentication or account manipulation.

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

Phishing URLs frequently use language designed to convince victims to authenticate, verify their identity, update an account, or respond to a security event.

### Risk contribution

The analyzer assigns:

```text
5 points per matched keyword
```

with a maximum keyword contribution of:

```text
15 points
```

Example:

```text
https://example.com/account/verify
```

Finding:

```text
URL contains potentially suspicious keywords: account, verify
```

---

# 10. @ Symbol Detection

### What it looks for

The analyzer checks whether the URL's network location contains:

```text
@
```

Example:

```text
https://trusted.example@evil.example/login
```

### Why it matters

In URLs, the portion before `@` can be interpreted as user information while the actual destination is the hostname after it.

Attackers can abuse this behavior to make a malicious URL appear associated with a trusted domain.

### Risk contribution

```text
@ symbol: +20
```

Detection:

```text
URL contains '@', which can be used to obscure the destination.
```

---

# 11. Excessive Hyphens

### What it looks for

The analyzer counts hyphens in the hostname.

The detection triggers when there are at least:

```text
3 hyphens
```

### Why it matters

Phishing domains often use combinations such as:

```text
microsoft-security-account-verify.example
```

This can make a malicious domain visually resemble a legitimate service.

### Risk contribution

```text
3+ hyphens: +10
```

---

# 12. Percent-Encoding Detection

### What it looks for

The analyzer searches for percent-encoded characters.

Example:

```text
%20
%2F
%3D
```

### Why it matters

URL encoding can be legitimate, but excessive or unexpected encoding can make URLs harder for users and analysts to interpret.

Attackers may use encoding as part of URL obfuscation.

### Risk contribution

```text
Percent encoding: +5
```

---

# 13. Brand Impersonation Detection

### What it looks for

The analyzer maintains a list of known brands and their expected domains.

Example:

```text
Microsoft -> microsoft.com
PayPal -> paypal.com
Apple -> apple.com
Google -> google.com
Amazon -> amazon.com
LinkedIn -> linkedin.com
Facebook -> facebook.com
```

The analyzer uses fuzzy string comparison to identify domains that resemble known brands but do not match the expected domain.

Example:

```text
micros0ft-support.com
```

The attacker has replaced the letter:

```text
o -> 0
```

### Why it matters

Brand impersonation is one of the most common phishing techniques.

Attackers rely on small changes such as:

```text
character substitution
hyphen insertion
misspellings
additional words
look-alike domains
```

### Risk contribution

Brand impersonation contributes to the URL analysis score.

The analyzer also records structured information identifying:

```text
detected
brand
observed domain
expected domain
similarity
```

Example finding:

```text
Possible Microsoft brand impersonation detected.
Observed domain: micros0ft-support.com
Expected domain: microsoft.com
```

---

# 14. Email Content Analysis

The content analyzer searches the email body for language commonly associated with phishing.

It categorizes findings rather than treating all keywords as identical.

The current categories include:

```text
urgency
account_threat
credential_request
call_to_action
security_alert
```

---

## 14.1 Urgency Indicators

### What it looks for

Examples include:

```text
urgent
immediately
within 24 hours
```

### Why it matters

Attackers frequently create artificial deadlines to prevent victims from carefully evaluating an email.

### Risk contribution

Content indicators contribute to the content risk score.

Example:

```text
Urgency indicators detected:
urgent, immediately, within 24 hours
```

---

## 14.2 Account Threat Indicators

### What it looks for

Examples include:

```text
suspended
suspension
```

### Why it matters

Threatening account closure or suspension creates fear and encourages victims to follow instructions without verification.

### Risk contribution

Contributes to the content risk score.

---

## 14.3 Credential Request Indicators

### What it looks for

Examples include:

```text
verify your identity
```

and other language associated with requesting authentication information.

### Why it matters

Credential theft is a major objective of phishing campaigns.

### Risk contribution

Contributes to the content risk score.

---

## 14.4 Call-to-Action Indicators

### What it looks for

Examples include:

```text
complete verification
```

### Why it matters

Phishing emails generally attempt to make the victim perform an action.

Common actions include:

```text
click a link
verify an account
reset a password
open an attachment
submit credentials
```

### Risk contribution

Contributes to the content risk score.

---

## 14.5 Security Alert Indicators

### What it looks for

Examples include:

```text
suspicious activity
```

### Why it matters

Attackers frequently impersonate security teams and claim that suspicious activity has been detected.

This creates fear and encourages the recipient to "secure" their account through an attacker-controlled website.

### Risk contribution

Contributes to the content risk score.

---

# 15. HTML Email Analysis

HTML analysis examines the rendered structure of HTML email content.

This provides additional detection opportunities that plain-text analysis cannot identify.

---

## 15.1 HTML Email Detection

### What it looks for

The analyzer determines whether the email contains HTML content.

### Why it matters

HTML allows attackers to create visually convincing phishing messages containing:

* Styled buttons
* Embedded links
* Forms
* Scripts
* Hidden elements
* Images
* Mismatched hyperlinks

HTML itself is not malicious, so this detection provides context for deeper analysis.

---

# 16. HTML Link Extraction

### What it looks for

The analyzer extracts hyperlinks from HTML elements such as:

```html
<a href="...">
```

### Why it matters

The visible text of an HTML link can differ from its actual destination.

This is a common phishing technique.

Example:

```text
Visible text:
Microsoft Account Security

Actual destination:
https://evil-example.com/login
```

The destination should always be analyzed rather than trusting the visible text.

---

# 17. HTML Link Text Mismatch

### What it looks for

The analyzer compares the displayed link text with the actual destination.

### Why it matters

A phishing email can display a trusted-looking domain while redirecting the victim somewhere completely different.

This detection is particularly valuable because it identifies deception at the presentation layer.

---

# 18. HTML Form Detection

### What it looks for

The analyzer detects HTML forms embedded in email content.

Example:

```html
<form>
```

### Why it matters

Credential phishing can attempt to collect information directly through an embedded form.

Potential targets include:

```text
usernames
passwords
MFA codes
personal information
payment information
```

An HTML form inside an email is therefore a strong signal requiring investigation.

---

# 19. HTML Script Detection

### What it looks for

The analyzer detects script elements such as:

```html
<script>
```

### Why it matters

Scripts inside email content can indicate malicious or suspicious behavior.

Modern email clients generally restrict active scripting, but the presence of scripts is still an important artifact for analysis.

---

# 20. Attachment Analysis

Attachments are analyzed for characteristics frequently associated with malware delivery and phishing.

---

## 20.1 Executable Attachment Detection

### What it looks for

The analyzer identifies executable file extensions.

Examples include:

```text
.exe
.scr
.bat
.cmd
.com
.ps1
```

### Why it matters

Attackers commonly deliver malware through executable attachments.

### Risk contribution

Executable attachments contribute significantly to the attachment risk score.

---

# 21. Suspicious File Extension Detection

### What it looks for

The analyzer checks for extensions associated with potentially dangerous files.

Examples include:

```text
.js
.vbs
.ps1
.iso
img
lnk
```

### Why it matters

Attackers may use scripting files, disk images, shortcuts, or other file types to deliver malicious payloads.

---

# 22. Double Extension Detection

### What it looks for

The analyzer identifies filenames containing multiple extensions.

Example:

```text
invoice.pdf.exe
```

### Why it matters

The first extension is intended to make the file appear harmless while the final extension determines how the operating system treats the file.

This is a classic phishing technique.

---

# 23. Macro-Enabled Document Detection

### What it looks for

The analyzer identifies macro-enabled document formats.

Examples include:

```text
.docm
.xlsm
.pptm
```

### Why it matters

Macros have historically been abused to execute malicious code when documents are opened.

Macro-enabled documents therefore warrant additional scrutiny.

---

# 24. MIME Extension Mismatch

### What it looks for

The analyzer compares the declared MIME type with the filename extension.

### Why it matters

Attackers may disguise the actual file type by manipulating its filename or MIME metadata.

A mismatch can indicate attempted file-type deception.

---

# 25. Domain Reputation

Domain reputation provides additional context about extracted domains.

The analyzer can resolve domains and evaluate reputation information where available.

### Why it matters

A domain with a poor reputation provides additional evidence that a URL may be malicious.

However, reputation services can have:

```text
false positives
false negatives
unknown results
rate limits
network failures
```

Therefore, unavailable reputation data should not automatically increase the risk score.

---

# 26. VirusTotal Reputation

VirusTotal can provide external threat intelligence for domains and URLs.

### What it looks for

The analyzer can query VirusTotal when an API key is available.

The returned intelligence can indicate whether security vendors have previously classified an indicator as malicious or suspicious.

### Why it matters

External reputation provides evidence beyond static URL characteristics.

For example:

```text
Static analysis:
Suspicious

VirusTotal:
Multiple vendors flag domain as malicious
```

The combination is substantially stronger than either signal alone.

### Important design principle

Failure to query VirusTotal must not automatically classify an email as malicious.

Possible reasons for unavailable reputation include:

```text
No API key
Network failure
Rate limiting
Unknown indicator
Service unavailable
```

The analyzer therefore treats unavailable reputation as neutral evidence.

---

# 27. Risk Scoring Model

The analyzer uses an additive scoring model.

Individual detection signals contribute points to a risk score.

Conceptually:

```text
Risk Score =
    Header Risk
  + URL Risk
  + Content Risk
  + Attachment Risk
  + Reputation Risk
```

The score is capped at:

```text
100
```

This prevents an email with many overlapping indicators from producing an unintuitive score above the defined maximum.

---

# 28. Score Components

The analyzer keeps component scores separate so analysts can understand why an email received its final risk score.

Example:

```text
Header Risk:   40
URL Risk:      30
Content Risk:  27

Raw Score:     97
Final Score:   97
```

This is preferable to returning only:

```text
Risk: 97
```

because the analyst can immediately identify which detection layer contributed the most evidence.

---

# 29. Severity Classification

The final score is mapped to a severity level.

```text
80–100  CRITICAL
60–79   HIGH
30–59   SUSPICIOUS
0–29    LOW
```

## LOW

The email contains few or no suspicious indicators.

```text
0–29
```

The message may still require normal security awareness, but the analyzer has found limited evidence of phishing.

---

## SUSPICIOUS

The email contains meaningful indicators requiring investigation.

```text
30–59
```

Examples include suspicious URLs, phishing language, or isolated authentication anomalies.

---

## HIGH

The email contains multiple strong indicators.

```text
60–79
```

This may include combinations such as:

```text
Authentication failures
Header mismatches
Suspicious URLs
Credential requests
```

---

## CRITICAL

The email contains substantial evidence consistent with a phishing attack.

```text
80–100
```

A critical email may combine several independent signals, such as:

```text
SPF failure
DKIM failure
DMARC failure
Reply-To mismatch
Return-Path mismatch
Brand impersonation
Suspicious URL
Credential request
Urgency
Account threat
```

---

# 30. Why Multiple Detection Layers Matter

No individual phishing indicator is perfect.

For example:

```text
HTTPS
```

does not mean a website is safe.

Similarly:

```text
SPF failure
```

does not automatically mean an email is malicious.

Likewise:

```text
Suspicious TLD
```

is not sufficient by itself.

The analyzer therefore uses multiple independent signals.

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
Credential request
       +
Urgent language
```

provides substantially stronger evidence than any individual detection.

This approach mirrors how security analysts investigate suspicious emails: individual indicators provide context, while combinations of indicators provide confidence.

---

# 31. Explainability

A core design goal of the project is explainability.

The analyzer does not simply output:

```text
MALICIOUS
```

Instead, it provides:

```text
Verdict
Risk Score
Score Breakdown
Authentication Results
Extracted IOCs
URL Findings
Content Findings
Reputation Results
Detection Evidence
Recommendation
```

This allows an analyst to understand why the system reached its conclusion.

For a SOC environment, explainability is important because automated detections often need to be validated before escalation or response actions are taken.

---

# 32. Example Detection Chain

For the included test email:

```text
From:
security@micros0ft-support.com

Reply-To:
attacker@evil-example.com

URL:
https://micros0ft-support.com/verify
```

The analyzer identifies:

```text
SPF failure
DKIM failure
DMARC failure
Reply-To mismatch
Return-Path mismatch
Microsoft brand impersonation
Suspicious URL keyword
Urgency indicators
Account threat indicators
Credential request
Call-to-action indicators
Security alert indicators
```

The resulting analysis produces a high-confidence phishing assessment.

Example:

```text
VERDICT: CRITICAL
RISK SCORE: 97/100
```

The important point is that the verdict is supported by multiple independent detection layers rather than a single keyword or rule.

---

# 33. Detection Philosophy

The detection engine follows several principles:

1. **Layered detection**

   Multiple detection mechanisms are combined rather than relying on one rule.

2. **Explainability**

   Every significant detection should produce a human-readable finding.

3. **Scoring instead of binary classification**

   Indicators increase or decrease confidence rather than immediately declaring an email malicious.

4. **Context matters**

   Individual indicators such as HTTPS or a suspicious TLD should not be treated as definitive proof.

5. **External intelligence is supplementary**

   Reputation services enhance static analysis but should not become a single point of failure.

6. **Fail safely**

   Missing reputation data or unavailable external services should not automatically increase the risk score.

7. **Testability**

   Detection rules are covered by automated tests to reduce regressions when the analyzer evolves.

---

# 34. Testing Strategy

Each detection layer is covered by automated tests.

The project currently tests:

```text
Email parsing
Header analysis
IOC extraction
URL analysis
Brand impersonation
Content analysis
HTML analysis
Attachment analysis
Domain reputation
VirusTotal integration
Risk scoring
Severity classification
CLI output
JSON output
```

The test suite is executed with:

```bash
python -m pytest -v
```

All detection changes should be accompanied by appropriate tests.

---

# 35. Limitations

The analyzer is a defensive analysis tool and should not be treated as a perfect malware or phishing classifier.

Potential limitations include:

* Legitimate emails may trigger suspicious indicators.
* Sophisticated phishing campaigns may evade static detection.
* Reputation services may have incomplete information.
* URL analysis cannot determine the complete behavior of a website.
* SPF, DKIM, and DMARC results depend on the available email headers.
* HTML analysis may not perfectly reproduce the behavior of every email client.
* Attachments are analyzed primarily through metadata and characteristics rather than full malware execution.
* Reputation lookups may be unavailable because of API limits, missing credentials, or network conditions.

For these reasons, the analyzer should support analyst investigation rather than replace human judgment.

---

## Summary

The Phishing Email Analyzer combines:

```text
Email Authentication
        +
Header Analysis
        +
IOC Extraction
        +
URL Analysis
        +
Brand Impersonation Detection
        +
Content Analysis
        +
HTML Analysis
        +
Attachment Analysis
        +
Domain Reputation
        +
VirusTotal Intelligence
        +
Risk Scoring
        =
Explainable Phishing Detection
```

The resulting system provides a practical example of how a SOC analyst can combine multiple weak and strong indicators into a single explainable security assessment.
