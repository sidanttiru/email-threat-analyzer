#   A command-line tool to analyze raw email files (.eml)

#   Usage: python main.py [filepath]

import sys
import re
import email
from email.header import decode_header
from datetime import datetime, timezone
import requests
import whois
from bs4 import BeautifulSoup
import time
import json
from urllib.parse import urlparse
from ipwhois import IPWhois
import math

VT_API_KEY = "[VirusTotalAPIKey]"
ABUSEIPDB_API_KEY = "[AbuseIPDBAPIKey]"
URLSCAN_API_KEY = "[urlscan.ioAPIKey]"

#   Scoring Constants
SCORE_THRESHOLD_MALICIOUS = 100
SCORE_THRESHOLD_SUSPICIOUS = 50

class AdvancedEmailAnalyzer:
    #All logic and data for analyzing .eml file
    
    #Using constructor method to store file, and initialize values to then be evaluated later in the program
    def __init__(self, email_path):
        self.email_path = email_path
        self.risk_score = 0
        self.report = []
        self.outer_message = None
        self.inner_message = None
        self.headers = {
            "Accept": "application/json",
            "x-apikey": VT_API_KEY
        }

    #Controls analysis workflow
    def run_full_analysis(self):
        print(f"[!] Starting advanced analysis for: {self.email_path}\n")
        if not self.parse_email_file():
            return

        print("\n--- Analyzing Outer Email Wrapper ---")
        self.perform_complete_analysis_on_message(self.outer_message, "[Outer Email]")
        
        if self.inner_message:
            print("\n\n--- Analyzing Inner Email (True Original Sender) ---")
            self.perform_complete_analysis_on_message(self.inner_message, "[Inner Email]")

        self.print_final_report()

    #Performs individual analysis steps
    def perform_complete_analysis_on_message(self, message_obj, context):
        html_body = self._get_html_body(message_obj)
        
        print(f"[!] Running Heuristic & Infrastructure Checks for {context}...")
        self.analyze_subject(message_obj, context)
        self.analyze_sender_mismatch(message_obj, context)
        self.analyze_return_path(message_obj, context)
        self.analyze_html_body_content(html_body, context)
        
        print(f"[!] Extracting and Analyzing Indicators for {context}...")
        indicators = self.extract_indicators(message_obj, html_body, context)
        
        if not indicators:
            print(f"[!] No indicators found in {context} part.")
            return
        
        self.analyze_domain_entropy(indicators, context)
        self.analyze_infrastructure(indicators, context)
        
        if indicators.get("ip"):
            self.analyze_ip(indicators["ip"], context)
        if indicators.get("domain"):
            self.analyze_domain(indicators["domain"], context)
        if indicators.get("urls"):
            for url in indicators["urls"]:
                self.analyze_url(url, context)

    #Adds a finding to report and updates risk score
    def add_finding(self, message, context, score=0, is_major=False, finding_type="heuristic"):
        self.risk_score += score
        prefix = "[!!]" if is_major else "[+]"
        self.report.append({
            "context": context,
            "prefix": prefix,
            "message": message,
            "score": score,
            "is_major": is_major,
            "type": finding_type
        })

    #Loads and parses .eml file
    def parse_email_file(self):
        try:
            with open(self.email_path, 'r', encoding='utf-8', errors='ignore') as f:
                self.outer_message = email.message_from_file(f)
            
            if self.outer_message.is_multipart():
                for part in self.outer_message.walk():
                    if part.get_content_type() == 'message/rfc822':
                        original_payload = part.get_payload()
                        if original_payload and isinstance(original_payload[0], email.message.Message):
                            self.inner_message = original_payload[0]
                            self.add_finding("Detected a bounce-back wrapper.", "[Analysis]")
                            break
            return True
        except Exception as e:
            print(f"[!] Error during parsing: {e}")
            return False
            
    #Extracts the HTML part of the email's body
    def _get_html_body(self, message_obj):
        if message_obj.is_multipart():
            for part in message_obj.walk():
                if part.get_content_type() == "text/html":
                    try:
                        return part.get_payload(decode=True).decode(errors='ignore')
                    except Exception:
                        continue
        elif message_obj.get_content_type() == "text/html":
            return message_obj.get_payload(decode=True).decode(errors='ignore')
        return None

    #Extracts IP, domain, and URL from message
    def extract_indicators(self, message_obj, html_body, context):
        indicators = {"urls": set()}
        received_headers = message_obj.get_all('Received', [])
        if received_headers:
            for header in reversed(received_headers):
                ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', header)
                if ip_match:
                    indicators["ip"] = ip_match.group(1)
                    break
        from_header = message_obj.get('From', '')
        domain_match = re.search(r'@([\w.-]+)', from_header)
        if domain_match:
            indicators["domain"] = domain_match.group(1).strip('>')
        
        if html_body:
            soup = BeautifulSoup(html_body, 'html.parser')
            for link in soup.find_all('a', href=True):
                indicators["urls"].add(link['href'])
        
        printable_indicators = indicators.copy()
        printable_indicators['urls'] = list(printable_indicators.get('urls', set()))
        print(f"[!] Extracted Indicators for {context}: {json.dumps(printable_indicators, indent=2)}")
        
        return indicators

    #   Heuristic & Infrastructure Functions
    def calculate_entropy(self, text):
        if not text:
            return 0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy
    
    #Checks for high-entropy domain name
    def analyze_domain_entropy(self, indicators, context):
        domain = indicators.get("domain")
        if not domain:
            return
        
        #Take only domain name
        domain_part = domain.split('.')[0]
        entropy = self.calculate_entropy(domain_part)

        #Uses threshold of 3.5
        if entropy > 3.5:
            self.add_finding(f"Domain '{domain_part}' has high entropy ({entropy:.2f}), suggesting it was auto-generated.", context, score=70, is_major=True)

    #Checks subject line for phrasing common in phishing attacks
    def analyze_subject(self, message_obj, context):
        subject = message_obj.get('Subject', '')
        suspicious_keywords = ['undeliverable', 'failure', 'delivery status notification', 'action required', 'verify your account', 'password reset', 'urgent']
        for keyword in suspicious_keywords:
            if keyword in subject.lower():
                self.add_finding(f"Subject contains suspicious keyword: '{keyword}'", context, score=40, is_major=True)
                break

    #Checks if display name and actual sender email address match
    def analyze_sender_mismatch(self, message_obj, context):
        from_header = message_obj.get('From', '')
        display_name, actual_address = email.utils.parseaddr(from_header)
        actual_domain_match = re.search(r'@([\w.-]+)', actual_address)
       
        if not actual_domain_match: return
        actual_domain = actual_domain_match.group(1)
        display_domain_match = re.search(r'([\w.-]+\.(com|net|org|io|gov|edu))', display_name, re.IGNORECASE)
        if display_domain_match:
            display_domain = display_domain_match.group(1)
            if display_domain.lower() not in actual_domain.lower():
                self.add_finding(f"Sender Mismatch: Display name domain '{display_domain}' != sending domain '{actual_domain}'", context, score=60, is_major=True)

    #Compares Return-Path and From domains
    def analyze_return_path(self, message_obj, context):
        return_path = message_obj.get('Return-Path', '').strip('<>')
        from_address = email.utils.parseaddr(message_obj.get('From', ''))[1]
        if return_path and from_address and return_path != from_address:
            return_domain_match = re.search(r'@([\w.-]+)', return_path)
            from_domain_match = re.search(r'@([\w.-]+)', from_address)
            if return_domain_match and from_domain_match and return_domain_match.group(1) != from_domain_match.group(1):
                self.add_finding(f"Return-Path domain ({return_domain_match.group(1)}) != From domain ({from_domain_match.group(1)})", context, score=30, is_major=True)
                
    #Checks for direct login forms and deceptive links
    def analyze_html_body_content(self, html_body, context):
        if not html_body: return
        
        soup = BeautifulSoup(html_body, 'html.parser')
        
        if soup.find('form'):
            self.add_finding("HTML body contains a <form> tag.", context, score=50, is_major=True)
        if soup.find('input', {'type': 'password'}):
            self.add_finding("HTML body contains a password input field.", context, score=80, is_major=True)
        for link in soup.find_all('a', href=True):
            link_text = link.get_text().strip()
            href = link['href']
            if '.' in link_text and ' ' not in link_text and 'http' in link_text.lower():
                try:
                    text_domain = urlparse(link_text).netloc
                    href_domain = urlparse(href).netloc
                    if text_domain and href_domain and text_domain.lower() != href_domain.lower():
                         self.add_finding(f"Deceptive Link: Text shows '{text_domain}' but links to '{href_domain}'", context, score=75, is_major=True)
                except Exception: continue

    #Uses IPWhois to check if sender IP or URL are linked to cloud providers
    def analyze_infrastructure(self, indicators, context):
        ip = indicators.get("ip")
        if ip:
            try:
                obj = IPWhois(ip)
                results = obj.lookup_rdap(depth=1)
                asn_description = results.get('asn_description', '').lower()
                cloud_providers = ['amazon', 'google', 'microsoft', 'azure', 'ovh', 'digitalocean', 'hetzner', 'linode']
                for provider in cloud_providers:
                    if provider in asn_description:
                        self.add_finding(f"Originating IP ({ip}) is from a cloud service: {asn_description.upper()}", context, score=50, is_major=True)
                        break
            except Exception as e:
                self.add_finding(f"IP ASN lookup failed for {ip}: {e}", context)

        #Tracks flagged cloud hostnames with URLs
        flagged_cloud_hostnames = set()
        for url in indicators.get("urls", set()):
            try:
                hostname = urlparse(url).hostname
                if not hostname or hostname in flagged_cloud_hostnames: 
                    continue #Skip if no hostname or hostname is already flagged
                cloud_storage_keywords = ['s3.amazonaws.com', 'storage.googleapis.com', 'blob.core.windows.net']
                for keyword in cloud_storage_keywords:
                    if keyword in hostname:
                        self.add_finding(f"Payload URL uses cloud storage: {hostname}", context, score=60, is_major=True)
                        flagged_cloud_hostnames.add(hostname) #Adds hostname to set to reduce redundancy
                        break
            except Exception: 
                continue

    #   API Analysis Functions ---

    #Uses VirusTotal to analyze sender IP and retrieves number of vendors who flagged IP as malicious, adding to score accordingly
    def analyze_ip(self, ip, context):
        if VT_API_KEY.startswith("YOUR_"): self.add_finding("VirusTotal API key not set.", context, finding_type="api"); return
        
        try:
            response = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=self.headers)
            res = response.json().get("data", {}).get("attributes", {})
            stats = res.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            self.add_finding(f"VirusTotal IP: {malicious_count} vendors flagged as malicious.", context, score=malicious_count * 10, is_major=malicious_count > 0, finding_type="api")
        except requests.RequestException as e: self.add_finding(f"VirusTotal IP check failed: {e}", context, is_major=True, finding_type="api")
    
    #Uses Whois and VirusTotal to check domain
    def analyze_domain(self, domain, context):
        try:
            domain_info = whois.whois(domain)
            created = domain_info.creation_date
            if created:
                age = (datetime.now(timezone.utc) - (created[0] if isinstance(created, list) else created).replace(tzinfo=timezone.utc)).days
                self.add_finding(f"Domain '{domain}' created {age} days ago.", context, score=50 if age < 90 else 0, is_major=age < 90, finding_type="heuristic")
            else: self.add_finding("Could not determine domain creation date.", context, score=20, is_major=True, finding_type="heuristic")
        except Exception: self.add_finding(f"WHOIS lookup failed for '{domain}'. It may not be registered.", context, score=60, is_major=True, finding_type="heuristic")      
        
        if VT_API_KEY.startswith("YOUR_"): self.add_finding("VirusTotal API key not set.", context, finding_type="api"); return
        try:
            response = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=self.headers)
            res = response.json().get("data", {}).get("attributes", {})
            stats = res.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            self.add_finding(f"VirusTotal Domain '{domain}': {malicious_count} vendors flagged as malicious.", context, score=malicious_count * 10, is_major=malicious_count > 0, finding_type="api")
        except requests.RequestException as e: self.add_finding(f"VirusTotal Domain check failed: {e}", context, is_major=True, finding_type="api")
        
        if VT_API_KEY.startswith("YOUR_"): self.add_finding("VirusTotal API key not set.", context); return
        try:
            response = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=self.headers)
            res = response.json().get("data", {}).get("attributes", {})
            stats = res.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            self.add_finding(f"VirusTotal Domain '{domain}': {malicious_count} vendors flagged as malicious.", context, score=malicious_count * 10, is_major=malicious_count > 0)
        except requests.RequestException as e: self.add_finding(f"VirusTotal Domain check failed: {e}", context, is_major=True)

    #Uses urlscan.io to analyze URL payload
    def analyze_url(self, url, context):
        if URLSCAN_API_KEY.startswith("YOUR_"): self.add_finding("urlscan.io API key not set.", context, finding_type="api"); return
        try:
            scan_headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
            data = {"url": url, "visibility": "private"}
            response = requests.post('https://urlscan.io/api/v1/scan/', headers=scan_headers, data=json.dumps(data))
            submit_res = response.json()
            self.add_finding(f"urlscan.io report for '{url[:50]}...': {submit_res.get('result')}", context, finding_type="api")
        except requests.RequestException as e: self.add_finding(f"urlscan.io submission failed: {e}", context, is_major=True, finding_type="api")

    # Prints the final report cleanly
    def print_final_report(self):
        print("\n" + "="*25 + " FINAL REPORT " + "="*25)
        
        # Print structural analysis findings first
        for finding in self.report:
            if finding["type"] == "meta":
                 print(f"{finding['context']} {finding['prefix']} {finding['message']}")

        print("\n--- Heuristic & Infrastructure Findings ---")
        for finding in self.report:
            if finding["type"] == "heuristic":
                print(f"{finding['context']} {finding['prefix']} {finding['message']} (Score +{finding['score']})")
        
        print("\n--- Reputation Findings (API) ---")
        for finding in self.report:
            if finding["type"] == "api":
                print(f"{finding['context']} {finding['prefix']} {finding['message']} (Score +{finding['score']})")

        print("\n" + "="*22 + " FINAL ASSESSMENT " + "="*21)
        print(f"TOTAL RISK SCORE: {self.risk_score}")
        
        if self.risk_score >= SCORE_THRESHOLD_MALICIOUS:
            print("VERDICT: MALICIOUS")

            has_critical_heuristic = any(f['type'] == 'heuristic' and f['is_major'] for f in self.report)

            malicious_api_sources = set()
            for f in self.report:
                if f['type'] == 'api' and f['score'] > 0:
                    message = f['message'].lower()
                    if 'virustotal' in message:
                        malicious_api_sources.add('VirusTotal')
                    elif 'urlscan.io' in message:
                        malicious_api_sources.add('urlscan.io')

            num_malicious_apis = len(malicious_api_sources)

            reasoning_parts = []
            if has_critical_heuristic:
                reasoning_parts.append("critical heuristic/infrastructure failures")
            if num_malicious_apis > 0:
                plural = "s" if num_malicious_apis > 1 else ""
                reasoning_parts.append(f"malicious indicators from {num_malicious_apis} external API{plural}")
            
            if reasoning_parts:
                reasoning = " and ".join(reasoning_parts)
                print(f"Reasoning: High score from {reasoning}.")
            else:
                #In case small indicators add up
                print("Reasoning: High score from accumulation of multiple suspicious indicators.")
        
        elif self.risk_score >= SCORE_THRESHOLD_SUSPICIOUS:
            print("VERDICT: SUSPICIOUS")
            print("Reasoning: Contains several red flags but lacks definitive malicious indicators.")
        else:
            print("VERDICT: LIKELY SAFE")
            print("Reasoning: Low risk score. No major suspicious indicators were found.")
        print("="*64)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py /path/to/email.eml")
        sys.exit(1)
    
    if any(key.startswith("YOUR_") for key in [VT_API_KEY, ABUSEIPDB_API_KEY, URLSCAN_API_KEY]):
        print("[WARNING] One or more API keys are missing. Please edit the script and add them.")

    analyzer = AdvancedEmailAnalyzer(sys.argv[1])
    analyzer.run_full_analysis()

