# Email Threat Analyzer

A command-line tool to perform analysis of raw email files (`.eml`). This script identifies potential phishing attempts, malware indicators, and other security threats by performing heuristic checks and verification with external threat intelligence APIs.

---
##  Features

* **Comprehensive `.eml` Parsing**: Analyzes all parts of an email, including headers, body, and attachments, with special handling for nested/forwarded emails
* **Heuristic Analysis**: Detects common red flags without using APIs:
    * **Sender Mismatch**: Checks for discrepancies between the display name and actual sending address
    * **Return-Path Verification**: Compares the bounce-back address with the sender's address
    * **Suspicious Content**: Searches for urgent keywords, embedded forms, and password fields
    * **Deceptive Links**: Identifies links where the displayed text does not match the actual destination URL
* **Infrastructure Analysis**:
    * **Domain Age & Reputation**: Performs WHOIS lookups to check domain creation date and queries VirusTotal for reputation
    * **Domain Entropy**: Calculates the randomness of domain names to detect algorithmically generated domains (DGAs)
    * **ASN Lookup**: Identifies if the source IP belongs to a generic cloud provider vs. a legitimate corporate network
* **Threat Intelligence Integration**:
    * **VirusTotal**: Checks IP addresses and domains against dozens of antivirus engines
    * **AbuseIPDB**: Retrievs community-sourced abuse confidence score for IP addresses
    * **urlscan.io**: Submits URLs for sandboxed analysis and provides a link to the report
* **Risk Scoring**: Aggregates all findings into a final risk score and provides a clear verdict: **MALICIOUS**, **SUSPICIOUS**, or **LIKELY SAFE**

---
## ⚙️ Installation & Setup

git clone https://github.com/sidanttiru/email-analyzer.git

cd email-analyzer
