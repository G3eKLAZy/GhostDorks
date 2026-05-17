#!/usr/bin/env python3
"""
================================================================================
GHOSTRECON v1 — Unified OSINT & cPanel/WHM Reconnaissance Engine
Created by: L4ZYG33K | Enhanced with Dork Engine + gf/arjun/subjack
================================================================================
Passive Modules (always run):
  • Subdomain Enum (crt.sh, OTX, HackerTarget, subfinder)
  • WHOIS Intelligence
  • DNS Record Map + SPF/DMARC Security Checks
  • Wayback Machine Sensitive File Discovery
  • Shodan InternetDB (ports + CVEs)
  • theHarvester (emails/hosts/IPs)
  • Reverse IP Lookup
  • Katana Passive (Wayback/CommonCrawl)
  • cPanel/WHM Detection & Passive Fingerprinting
  • CVE-2026-41940 Patch Assessment
  • subjack (subdomain takeover fingerprinting)
  • gf (pattern matching on endpoints)

Active Modules (--active):
  • dnsx resolution + takeover detection
  • naabu port scan
  • httpx probing (title/server/tech/TLS)
  • katana active crawl
  • nuclei vulnerability scan
  • arjun (hidden parameter discovery)
  • cPanel CVE-2026-41940 Remote Probe (WHM only)

Usage:
  python ghostreconv1.py -d example.com
  python ghostreconv1.py -d example.com --active
  python ghostreconv1.py -d example.com --active --nuclei --cpanel-probe --gf --arjun --subjack
================================================================================
"""

import os
import sys
import urllib.parse
import html
import argparse
import requests
import socket
import subprocess
import shutil
import json
import re
import tempfile
import ssl
import time
import random
from urllib.parse import urlparse
from datetime import datetime

# ─────────────────────────────────────────────
# Configuration & Constants
# ─────────────────────────────────────────────

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive"
}

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0"
]

# cPanel CVE-2026-41940 Advisory Data (April 28-29, 2026)
PATCHED_BUILDS_RE = re.compile(r'11\.(86\.0\.41|94\.0\.28|102\.0\.39|110\.0\.(97|103)|118\.0\.63|124\.0\.35|126\.0\.54|130\.0\.19|132\.0\.29|134\.0\.20|136\.0\.5)')
UNPATCHABLE_TIERS_RE = re.compile(r'11\.(112|114|116|120|122|128)\..*')
WP2_PATCHED = "136.1.7"
CPANEL_MIN_SIZE = 8000
CPANEL_TIMEOUT = 15
CPANEL_CONNECT_TIMEOUT = 8
PROBE_TIMEOUT = 20

# ─────────────────────────────────────────────
#Ghost Dork Templates
# ─────────────────────────────────────────────

DORK_TEMPLATES = {
    "🐱 Subdomain Recon": [
        'site:*.{target}',
        'site:*.{target} -www',
        '"@{target}" -site:www.{target} -site:{target}',
        'intitle:"index of" "parent directory" site:{target}',
        'inurl:dmarc domain={target}',
        'ext:txt {target} (vhost OR hostname OR nameserver)',
        'filetype:env {target}',
        'inurl:(admin | login | panel) site:*.{target}',
        'site:*.{target} inurl:api',
        'site:{target} inurl:staging',
        'site:{target} inurl:dev',
        'site:{target} inurl:test',
        'site:*.{target} inurl:*.api',
        'site:{target} inurl:mail',
        'site:{target} inurl:ftp',
        'site:{target} inurl:cdn',
        'allintitle:"index of/admin"',
        'allintitle:"index of/root"',
        'allintitle:restricted filetype:mail',
        'site:{target} inurl:vpn',
    ],
    "📁 Directory & File Exposure": [
        'intitle:"index of" site:{target}',
        'intitle:"index of /backup"',
        'intitle:"index of /admin"',
        'inurl:/db_backup OR inurl:/database_backup site:{target}',
        'ext:sql | ext:dbf | ext:mdb | ext:ora site:{target}',
        'filetype:log site:{target}',
        'inurl:wp-config.php site:{target}',
        'inurl:/.env site:{target}',
        'intitle:"index of" +passwd site:{target}',
        'intitle:"index of" +git site:{target}',
        'intitle:"index of" +config site:{target}',
        'inurl:sitemap.xml site:{target}',
        'inurl:robots.txt site:{target}',
        'intitle:"index of" +sql site:{target}',
        'intitle:"index of" +backup site:{target}',
        'inurl:/backup/ site:{target}',
        'inurl:/dump/ site:{target}',
    ],
    "🔑 Secrets & Configs": [
        'ext:env | ext:.env site:{target}',
        'intext:"DB_PASSWORD" site:{target}',
        'intext:"AWS_ACCESS_KEY_ID" site:{target}',
        'filetype:json "api_key" site:{target}',
        'inurl:.git/config site:{target}',
        'intext:"DATABASE_URL" site:{target}',
        'intext:"SLACK_BOT_TOKEN" site:{target}',
        'ext:key site:{target}',
        'ext:pem site:{target}',
        'intext:"BEGIN RSA PRIVATE" site:{target}',
        'filetype:pfx site:{target}',
        'intext:"password" filetype:xml site:{target}',
        'intext:"secret" filetype:conf site:{target}',
        'intext:"token" filetype:json site:{target}',
        'intext:"api_secret" site:{target}',
        'intext:"client_secret" site:{target}',
        'inurl:.env.{target}',
        'intext:"-----BEGIN OPENSSH PRIVATE KEY-----" site:{target}',
        'intext:"-----BEGIN PGP PRIVATE KEY BLOCK-----" site:{target}',
    ],
    "⚠️ Admin Panels & Auth": [
        'inurl:admin/login.php site:{target}',
        'inurl:wp-login.php site:{target}',
        'intitle:"admin panel" | intitle:"control panel" site:{target}',
        'intitle:"phpMyAdmin" site:{target}',
        'inurl:cpanel site:{target}',
        'intitle:"Jenkins" site:{target}',
        'intitle:"Citrix" site:{target}',
        'inurl:login site:{target}',
        'inurl:signin site:{target}',
        'inurl:dashboard site:{target}',
        'inurl:portal site:{target}',
        'inurl:administrator site:{target}',
        'intitle:"login" "password" site:{target}',
        'inurl:auth site:{target}',
        'inurl:oauth site:{target}',
        'inurl:saml site:{target}',
    ],
    "💥 Vulnerable Files & Errors": [
        'intitle:"phpinfo()" site:{target}',
        'inurl:/vendor/ site:{target}',
        'intext:"sql syntax error" site:{target}',
        'intext:"Warning: include" site:{target}',
        'inurl:phpshell site:{target}',
        'inurl:webshell site:{target}',
        'inurl:backdoor site:{target}',
        'intext:"Fatal error" site:{target}',
        'intext:"Stack trace" site:{target}',
        'intext:"syntax error" site:{target}',
        'intext:"Connection refused" site:{target}',
        'intext:"403 Forbidden" site:{target}',
        'intitle:"Apache2 Ubuntu Default Page" site:{target}',
        'intitle:"IIS Windows Server" site:{target}',
        'intitle:"Welcome to nginx" site:{target}',
        'inurl:phpmyadmin site:{target}',
        'inurl:adminer.php site:{target}',
    ],
    "🔌 APIs & Documentation": [
        'inurl:api/ | inurl:rest/ | inurl:v1/ site:{target}',
        'inurl:swagger | inurl:redoc site:{target}',
        'site:*.{target} (inurl:swagger OR inurl:api-docs)',
        'inurl:graphql site:{target}',
        'inurl:openapi.json site:{target}',
        'inurl:api-docs site:{target}',
        'inurl:postman site:{target}',
        'inurl:graphql site:{target}',
        'intitle:"Swagger UI" site:{target}',
        'intext:"paths" "swagger" site:{target}',
        'inurl:/api/v1/ site:{target}',
        'inurl:/api/v2/ site:{target}',
        'inurl:/rest/ site:{target}',
        'inurl:/graphql/ site:{target}',
        'inurl:/soap/ site:{target}',
        'inurl:/wsdl site:{target}',
    ],
    "🚨 Error & Debug Leaks": [
        'intext:"Warning: mysql" site:{target}',
        'intext:"Stack trace" site:{target}',
        'intext:"Fatal error" site:{target}',
        'intext:"syntax error" site:{target}',
        'intext:"Connection refused" site:{target}',
        'intext:"403 Forbidden" site:{target}',
        'intext:"500 Internal Server Error" site:{target}',
        'intext:"Debug mode" site:{target}',
        'intext:"Traceback" site:{target}',
        'intext:"Exception" site:{target}',
        'intext:"NullPointerException" site:{target}',
        'intext:"django" "debug" site:{target}',
        'intext:"laravel" "debug" site:{target}',
        'intext:"symfony" "debug" site:{target}',
        'intext:"php error" site:{target}',
    ],
    "📄 Documents & Leaks": [
        'filetype:pdf site:{target}',
        'filetype:doc | filetype:docx site:{target}',
        'filetype:xls | filetype:xlsx site:{target}',
        'intext:"confidential" site:{target}',
        'intext:"internal use only" site:{target}',
        'site:{target} "employee handbook" filetype:pdf',
        'intext:"password" filetype:xls site:{target}',
        'intext:"classified" site:{target}',
        'intext:"proprietary" site:{target}',
        'intext:"NDA" site:{target}',
        'intext:"do not distribute" site:{target}',
        'filetype:ppt | filetype:pptx site:{target}',
        'filetype:csv site:{target}',
        'filetype:txt site:{target}',
    ],
    "🕳️ Paste & Git Leaks": [
        'site:pastebin.com "{target}"',
        'site:github.com "{target}" intext:"password"',
        'site:*.stackexchange.com {target} password',
        'site:gist.github.com {target}',
        'site:github.com "{target}" "api_key"',
        'site:github.com "{target}" "secret"',
        'site:github.com "{target}" "token"',
        'site:gitlab.com "{target}"',
        'site:bitbucket.org "{target}"',
        'site:pastebin.com "{target}" password',
        'site:controlc.com "{target}"',
        'site:ideone.com "{target}"',
    ],
    "🔗 Takeover & Third-Party": [
        'inurl:herokuapp.com site:{target}',
        'inurl:*.cloudfront.net site:{target}',
        'inurl:github.io {target}',
        'inurl:s3.amazonaws.com {target}',
        'inurl:azurewebsites.net site:{target}',
        'inurl:firebaseapp.com site:{target}',
        'inurl:netlify.app site:{target}',
        'inurl:vercel.app site:{target}',
        'inurl:fastly.net site:{target}',
        'inurl:bitbucket.io site:{target}',
        'inurl:repl.co site:{target}',
        'inurl:glitch.me site:{target}',
        'inurl:webflow.io site:{target}',
        'inurl:readme.io site:{target}',
    ],
    "☁️ Cloud Storage & Buckets": [
        'site:s3.amazonaws.com "{target}"',
        'site:storage.googleapis.com {target}',
        'site:blob.core.windows.net {target}',
        'inurl:bucket site:{target}',
        'site:s3.amazonaws.com "{target}" "index of"',
        'site:storage.googleapis.com "{target}"',
        'site:amazonaws.com "{target}"',
        'site:cloudfront.net "{target}"',
        'inurl:s3.amazonaws.com inurl:{target}',
        'inurl:googleapis.com inurl:{target}',
        'intext:"bucket" "{target}" site:amazonaws.com',
    ],
    "🏗️ Dev / Test / Staging": [
        'site:{target} inurl:staging',
        'site:{target} inurl:dev',
        'site:{target} inurl:test',
        'site:{target} inurl:sandbox',
        'site:{target} inurl:localhost',
        'site:{target} inurl:beta',
        'site:{target} inurl:alpha',
        'site:{target} inurl:qa',
        'site:{target} inurl:uat',
        'site:{target} inurl:preprod',
        'site:{target} inurl:preview',
        'site:{target} inurl:demo',
        'site:dev.{target}',
        'site:staging.{target}',
        'site:test.{target}',
    ],
    "💼 Social & Employee Intel": [
        'site:linkedin.com/in/ "{target}"',
        'site:linkedin.com "{target}" (engineer OR admin)',
        'site:twitter.com {target}',
        '"@{target}" site:twitter.com',
        'site:facebook.com "{target}"',
        'site:instagram.com "{target}"',
        'site:youtube.com "{target}"',
        'site:reddit.com "{target}"',
        'site:medium.com "{target}"',
        'site:about.me "{target}"',
    ],
    "🎛️ cPanel/WHM & Hosting": [
        'inurl:cpanel site:{target}',
        'inurl:whm site:{target}',
        'inurl:webmail site:{target}',
        'inurl:roundcube site:{target}',
        'inurl:squirrelmail site:{target}',
        'inurl:horde site:{target}',
        'inurl:2083 site:{target}',
        'inurl:2087 site:{target}',
        'intitle:"cPanel" site:{target}',
        'intitle:"WebHost Manager" site:{target}',
    ],
    "🗄️ Database & Backup Leaks": [
        'ext:sql site:{target}',
        'ext:dump site:{target}',
        'ext:bak site:{target}',
        'ext:backup site:{target}',
        'ext:mdb site:{target}',
        'ext:sqlite site:{target}',
        'ext:db site:{target}',
        'inurl:phpmyadmin site:{target}',
        'inurl:adminer site:{target}',
        'intext:"database dump" site:{target}',
        'intext:"mysql dump" site:{target}',
        'intext:"pg_dump" site:{target}',
        'intext:"mongodb" "dump" site:{target}',
    ],
    "📡 IoT & Network Devices": [
        'intitle:"Router" site:{target}',
        'intitle:"Switch" site:{target}',
        'intitle:"Firewall" site:{target}',
        'intitle:"VPN" site:{target}',
        'intitle:"Network Camera" site:{target}',
        'intitle:"Webcam" site:{target}',
        'inurl:axis-cgi site:{target}',
        'intitle:"Live View / - AXIS" site:{target}',
        'inurl:viewerframe?mode= site:{target}',
        'intitle:"DVR" site:{target}',
        'intitle:"NAS" site:{target}',
        'inurl:printer site:{target}',
    ],
}

# ─────────────────────────────────────────────
# Utility Functions
# ─────────────────────────────────────────────

def pick_ua():
    return random.choice(USER_AGENTS)

def curl_cmd(url, headers=None, timeout=15, follow_redirects=True, verify=False):
    """Build and execute curl as subprocess for edge cases."""
    cmd = ["curl", "-s", "-L" if follow_redirects else "", "--max-time", str(timeout),
           "--connect-timeout", str(CPANEL_CONNECT_TIMEOUT), "-A", pick_ua()]
    if not verify:
        cmd.append("-k")
    if headers:
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
    cmd.append(url)
    cmd = [c for c in cmd if c]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+5)
        return result.stdout, result.stderr, result.returncode
    except Exception as e:
        return "", str(e), 1

# ─────────────────────────────────────────────
# Original GhostDorks Modules
# ─────────────────────────────────────────────

def fetch_subdomains(domain):
    subdomains = set()
    timeout_limit = 45

    print(f"[*] Querying crt.sh for subdomains of {domain}...")
    url_crtsh = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url_crtsh, headers=HEADERS, timeout=timeout_limit)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name_values = entry.get('name_value', '').split('\n')
                for sub in name_values:
                    sub = sub.strip().lower()
                    if sub.startswith('*.'):
                        sub = sub[2:]
                    if sub.endswith(domain) and sub != domain:
                        subdomains.add(sub)
            if subdomains:
                print(f"[+] Successfully extracted {len(subdomains)} unique subdomains from crt.sh.")
        else:
            print(f"[-] crt.sh returned a non-200 status code: {response.status_code}")
    except requests.exceptions.Timeout:
        print("[-] crt.sh query timed out.")
    except KeyboardInterrupt:
        print("\n[!] User interrupted crt.sh scan (Ctrl+C).")
    except Exception as e:
        print(f"[-] Error querying crt.sh: {e}")

    if not subdomains:
        print(f"[*] Falling back to AlienVault OTX for passive DNS enumeration...")
        url_otx = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        try:
            response = requests.get(url_otx, headers=HEADERS, timeout=timeout_limit)
            if response.status_code == 200:
                data = response.json()
                passive_dns = data.get('passive_dns', [])
                for entry in passive_dns:
                    sub = entry.get('hostname', '').strip().lower()
                    if sub.startswith('*.'):
                        sub = sub[2:]
                    if sub.endswith(domain) and sub != domain:
                        subdomains.add(sub)
                if subdomains:
                    print(f"[+] Successfully extracted {len(subdomains)} unique subdomains from AlienVault OTX.")
            else:
                print(f"[-] AlienVault OTX returned a non-200 status code: {response.status_code}")
        except requests.exceptions.Timeout:
            print("[-] AlienVault OTX query timed out.")
        except KeyboardInterrupt:
            print("\n[!] User interrupted AlienVault scan (Ctrl+C).")
        except Exception as e:
            print(f"[-] Error querying AlienVault OTX: {e}")

    if not subdomains:
        print(f"[*] Falling back to HackerTarget for host search...")
        url_ht = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            response = requests.get(url_ht, headers=HEADERS, timeout=timeout_limit)
            if response.status_code == 200:
                if "error" not in response.text.lower() and "exceeded" not in response.text.lower():
                    lines = response.text.split('\n')
                    for line in lines:
                        parts = line.split(',')
                        if len(parts) > 0:
                            sub = parts[0].strip().lower()
                            if sub.startswith('*.'):
                                sub = sub[2:]
                            if sub.endswith(domain) and sub != domain:
                                subdomains.add(sub)
                    if subdomains:
                        print(f"[+] Successfully extracted {len(subdomains)} unique subdomains from HackerTarget.")
                else:
                    print(f"[-] HackerTarget API limit reached or error returned.")
            else:
                print(f"[-] HackerTarget returned a non-200 status code: {response.status_code}")
        except requests.exceptions.Timeout:
            print("[-] HackerTarget query timed out.")
        except KeyboardInterrupt:
            print("\n[!] User interrupted HackerTarget scan (Ctrl+C).")
        except Exception as e:
            print(f"[-] Error querying HackerTarget: {e}")

    return sorted(list(subdomains))

def fetch_whois_info(domain):
    print(f"[*] Running WHOIS lookup for {domain}...")
    whois_data = {
        "registrar": "N/A", "creation_date": "N/A", "expiry_date": "N/A",
        "updated_date": "N/A", "organization": "N/A", "country": "N/A",
        "name_servers": [], "registrant_email": "N/A", "dnssec": "N/A", "raw": ""
    }
    if not shutil.which("whois"):
        print("[-] 'whois' command not found. Skipping WHOIS module.")
        return whois_data
    try:
        result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=30)
        raw_output = result.stdout
        whois_data["raw"] = raw_output
        patterns = {
            "registrar": r"(?:Registrar|registrar)\s*:\s*(.+)",
            "creation_date": r"(?:Creation Date|Created|created|Registration Date)\s*:\s*(.+)",
            "expiry_date": r"(?:Expir(?:y|ation) Date|Registry Expiry Date|paid-till)\s*:\s*(.+)",
            "updated_date": r"(?:Updated Date|Last Updated|last-modified)\s*:\s*(.+)",
            "organization": r"(?:Registrant Organization|Org(?:anization)?|org-name)\s*:\s*(.+)",
            "country": r"(?:Registrant Country|Country|country)\s*:\s*(.+)",
            "registrant_email": r"(?:Registrant Email|e-mail)\s*:\s*(.+)",
            "dnssec": r"(?:DNSSEC)\s*:\s*(.+)",
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, raw_output, re.IGNORECASE)
            if match:
                whois_data[key] = match.group(1).strip()
        ns_matches = re.findall(r"(?:Name Server|nserver|nameserver)\s*:\s*(.+)", raw_output, re.IGNORECASE)
        if ns_matches:
            whois_data["name_servers"] = list(set([ns.strip().lower() for ns in ns_matches]))
        ns_count = len(whois_data['name_servers'])
        print(f"[+] WHOIS data retrieved. Registrar: {whois_data['registrar']}, Nameservers: {ns_count}")
    except subprocess.TimeoutExpired:
        print("[-] WHOIS query timed out.")
    except KeyboardInterrupt:
        print("\n[!] User interrupted WHOIS query (Ctrl+C). Skipping...")
    except Exception as e:
        print(f"[-] Error running WHOIS: {e}")
    return whois_data

def fetch_wayback_urls(domain):
    print(f"[*] Querying Wayback Machine for exposed files on {domain}...")
    urls = []
    wayback_url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&collapse=urlkey&output=json&fl=original&filter=statuscode:200&filter=mimetype:text/plain|application/json|application/zip|application/x-sql"
    try:
        response = requests.get(wayback_url, headers=HEADERS, timeout=20)
        if response.status_code == 200:
            try:
                data = response.json()
                if len(data) > 1:
                    for row in data[1:]:
                        urls.append(row[0])
            except ValueError:
                print("[-] Wayback Machine returned invalid JSON.")
        else:
            print(f"[-] Wayback Machine returned a non-200 status code: {response.status_code}")
    except requests.exceptions.Timeout:
        print("[-] Wayback Machine query timed out.")
    except Exception as e:
        print(f"[-] Error querying Wayback Machine: {e}")
    sensitive_exts = ('.env', '.sql', '.bak', '.config', '.json', '.pem', '.key', '.yml', '.yaml', '.log', '.zip', '.tar.gz')
    juicy_urls = [u for u in urls if any(u.lower().endswith(ext) or ext+"?" in u.lower() for ext in sensitive_exts)]
    if juicy_urls:
        print(f"[+] Successfully extracted {len(juicy_urls)} archived URLs from Wayback Machine.")
    else:
        print("[-] No sensitive archived files found on Wayback Machine.")
    return juicy_urls

def fetch_open_ports(ip):
    print(f"[*] Querying Shodan InternetDB for ports on {ip}...")
    ports = []
    cves = []
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=15)
        if response.status_code == 200:
            data = response.json()
            ports = data.get('ports', [])
            cves = data.get('vulns', [])
            print(f"[+] Found {len(ports)} open ports and {len(cves)} vulnerabilities.")
        elif response.status_code == 404:
            print(f"[-] No Shodan data found for this IP.")
        else:
            print(f"[-] Shodan API returned status code: {response.status_code}")
    except requests.exceptions.Timeout:
        print("[-] Shodan query timed out.")
    except KeyboardInterrupt:
        print("\n[!] User interrupted Shodan scan (Ctrl+C).")
    except Exception as e:
        print(f"[-] Error querying Shodan: {e}")
    return ports, cves

def fetch_dns_records(domain):
    print(f"[*] Querying DNS records for {domain}...")
    dns_data = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "SOA": [], "CNAME": [], "security_notes": []}
    if not shutil.which("dig"):
        print("[-] 'dig' command not found. Skipping DNS map module.")
        return dns_data
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    for rtype in record_types:
        try:
            result = subprocess.run(["dig", "+short", rtype, domain], capture_output=True, text=True, timeout=10)
            lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            dns_data[rtype] = lines
        except Exception:
            continue
    txt_records = " ".join(dns_data.get("TXT", [])).lower()
    if "spf1" not in txt_records:
        dns_data["security_notes"].append("⚠️ No SPF record found — high risk of email spoofing")
    try:
        dmarc_result = subprocess.run(["dig", "+short", "TXT", f"_dmarc.{domain}"], capture_output=True, text=True, timeout=10)
        if not dmarc_result.stdout.strip():
            dns_data["security_notes"].append("⚠️ No DMARC record found — phishing risk")
    except Exception:
        pass
    total = sum(len(v) for k, v in dns_data.items() if k in record_types)
    print(f"[+] DNS enumeration complete. {total} total records found.")
    if dns_data["security_notes"]:
        for note in dns_data["security_notes"]:
            print(f"    {note}")
    return dns_data

def fetch_emails_theharvester(domain):
    print(f"[*] Running theHarvester for email/host enumeration on {domain}...")
    harvest_data = {"emails": [], "hosts": [], "ips": []}
    if not shutil.which("theHarvester"):
        print("[-] 'theHarvester' command not found. Skipping email harvesting module.")
        return harvest_data
    tmp_dir = tempfile.mkdtemp(prefix="ghostdorks_")
    output_base = os.path.join(tmp_dir, "harvest")
    try:
        result = subprocess.run(
            ["theHarvester", "-d", domain, "-b", "anubis,crtsh,dnsdumpster,duckduckgo,hackertarget,rapiddns,urlscan",
             "-l", "200", "-f", output_base],
            capture_output=True, text=True, timeout=120
        )
        json_path = output_base + ".json"
        local_json_path = "harvest.json"
        target_json = None
        if os.path.exists(json_path): target_json = json_path
        elif os.path.exists(local_json_path): target_json = local_json_path
        if target_json:
            with open(target_json, 'r') as f:
                data = json.load(f)
            harvest_data["emails"] = sorted(set(data.get("emails", [])))
            harvest_data["hosts"] = sorted(set(data.get("hosts", [])))
            harvest_data["ips"] = sorted(set(data.get("ips", [])))
            print(f"[+] theHarvester found: {len(harvest_data['emails'])} emails, {len(harvest_data['hosts'])} hosts, {len(harvest_data['ips'])} IPs")
        else:
            print("[-] theHarvester JSON output not found, parsing stdout...")
            email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
            found_emails = email_pattern.findall(result.stdout)
            harvest_data["emails"] = sorted(set(found_emails))
            if harvest_data["emails"]:
                print(f"[+] Parsed {len(harvest_data['emails'])} emails from stdout.")
            else:
                print("[-] No emails found.")
    except Exception as e:
        print(f"[-] Error running theHarvester: {e}")
    finally:
        try:
            import shutil as sh
            sh.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass
    return harvest_data

def fetch_reverse_ip(ip):
    print(f"[*] Running reverse IP lookup for {ip}...")
    domains = []
    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=15)
        if response.status_code == 200:
            lines = response.text.splitlines()
            if len(lines) > 0 and "No DNS A records found" not in lines[0] and "API count exceeded" not in lines[0]:
                domains = [line.strip() for line in lines if line.strip()]
                print(f"[+] Found {len(domains)} domains co-hosted on {ip}.")
            else:
                print(f"[-] No co-hosted domains found for {ip} or API limit reached.")
        else:
            print(f"[-] HackerTarget API returned status code: {response.status_code}")
    except Exception as e:
        print(f"[-] Error running reverse IP lookup: {e}")
    return domains

def run_subfinder(domain):
    print(f"[*] Running subfinder for passive subdomain enumeration on {domain}...")
    results = []
    if not shutil.which("subfinder"):
        print("[-] 'subfinder' not found. Skipping.")
        return results
    try:
        proc = subprocess.run(["subfinder", "-d", domain, "-silent", "-all"], capture_output=True, text=True, timeout=120)
        for line in proc.stdout.strip().splitlines():
            sub = line.strip().lower()
            if sub and sub.endswith(domain):
                results.append(sub)
        results = sorted(set(results))
        print(f"[+] subfinder found {len(results)} subdomains.")
    except subprocess.TimeoutExpired:
        print("[-] subfinder timed out.")
    except KeyboardInterrupt:
        print("\n[!] Interrupted subfinder (Ctrl+C).")
    except Exception as e:
        print(f"[-] subfinder error: {e}")
    return results

def run_dnsx(subdomains):
    print(f"[*] Running dnsx to validate {len(subdomains)} subdomains...")
    resolved = []
    takeover_candidates = []
    if not subdomains:
        return resolved, takeover_candidates
    if not shutil.which("dnsx"):
        print("[-] 'dnsx' not found. Skipping DNS validation.")
        return resolved, takeover_candidates
    try:
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', prefix='ghostdorks_', delete=False)
        tmp.write('\n'.join(subdomains))
        tmp.close()
        proc = subprocess.run(["dnsx", "-l", tmp.name, "-a", "-cname", "-resp", "-json", "-silent"], capture_output=True, text=True, timeout=180)
        os.unlink(tmp.name)
        for line in proc.stdout.strip().splitlines():
            try:
                entry = json.loads(line)
                host = entry.get("host", "")
                if not host:
                    continue
                a_records = entry.get("a", [])
                cname = entry.get("cname", [])
                if a_records:
                    resolved.append({"host": host, "ips": a_records, "cname": cname})
                elif cname:
                    takeover_candidates.append({"host": host, "cname": cname})
            except json.JSONDecodeError:
                continue
        print(f"[+] dnsx resolved {len(resolved)} live hosts, {len(takeover_candidates)} potential takeover candidates.")
    except subprocess.TimeoutExpired:
        print("[-] dnsx timed out.")
    except KeyboardInterrupt:
        print("\n[!] Interrupted dnsx (Ctrl+C).")
    except Exception as e:
        print(f"[-] dnsx error: {e}")
    return resolved, takeover_candidates

def run_naabu(resolved_hosts, rate=1000):
    print(f"[*] Running naabu port scan on {len(resolved_hosts)} hosts (rate={rate})...")
    port_results = []
    if not resolved_hosts:
        return port_results
    if not shutil.which("naabu"):
        print("[-] 'naabu' not found. Skipping.")
        return port_results
    try:
        hosts = [h["host"] for h in resolved_hosts]
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', prefix='ghostdorks_naabu_', delete=False)
        tmp.write('\n'.join(hosts))
        tmp.close()
        proc = subprocess.run(["naabu", "-list", tmp.name, "-top-ports", "1000", "-rate", str(rate), "-json", "-silent"], capture_output=True, text=True, timeout=300)
        os.unlink(tmp.name)
        for line in proc.stdout.strip().splitlines():
            try:
                entry = json.loads(line)
                host = entry.get("host", "")
                port = entry.get("port", 0)
                ip   = entry.get("ip", "")
                if host and port:
                    port_results.append({"host": host, "port": port, "ip": ip})
            except json.JSONDecodeError:
                continue
        print(f"[+] naabu found {len(port_results)} open port(s) across all hosts.")
    except subprocess.TimeoutExpired:
        print("[-] naabu timed out.")
    except KeyboardInterrupt:
        print("\n[!] Interrupted naabu (Ctrl+C).")
    except Exception as e:
        print(f"[-] naabu error: {e}")
    return port_results

def run_httpx(resolved_hosts, naabu_results=None):
    print(f"[*] Running httpx to probe live HTTP services...")
    http_hosts = []
    if not resolved_hosts:
        return http_hosts
    if not shutil.which("httpx"):
        print("[-] 'httpx' not found. Skipping.")
        return http_hosts
    try:
        targets = []
        if naabu_results:
            valid_http_ports = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 8081, 9000}
            targets = list(set(f"{r['host']}:{r['port']}" for r in naabu_results if int(r['port']) in valid_http_ports))
        if not targets:
            targets = [h["host"] for h in resolved_hosts]
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', prefix='ghostdorks_httpx_', delete=False)
        tmp.write('\n'.join(targets))
        tmp.close()
        proc = subprocess.run(["httpx", "-l", tmp.name, "-status-code", "-title", "-server", "-tech-detect", "-follow-redirects", "-json", "-silent", "-threads", "50"], capture_output=True, text=True, timeout=300)
        os.unlink(tmp.name)
        for line in proc.stdout.strip().splitlines():
            try:
                entry = json.loads(line)
                url = entry.get("url", "")
                if not url:
                    continue
                http_hosts.append({
                    "url": url,
                    "status": entry.get("status_code", entry.get("status-code", 0)),
                    "title": entry.get("title", ""),
                    "server": entry.get("webserver", entry.get("server", "")),
                    "tech": entry.get("tech", []),
                    "content_length": entry.get("content_length", entry.get("content-length", 0)),
                })
            except json.JSONDecodeError:
                continue
        print(f"[+] httpx found {len(http_hosts)} live HTTP endpoint(s).")
    except subprocess.TimeoutExpired:
        print("[-] httpx timed out.")
    except KeyboardInterrupt:
        print("\n[!] Interrupted httpx (Ctrl+C).")
    except Exception as e:
        print(f"[-] httpx error: {e}")
    return http_hosts

def run_katana(domain, http_hosts=None, resolved_hosts=None, passive=True):
    mode_str = "passive (Wayback/CommonCrawl)" if passive else "active crawl"
    print(f"[*] Running katana [{mode_str}] for endpoint discovery...")
    endpoints = []
    if not shutil.which("katana"):
        print("[-] 'katana' not found. Skipping.")
        return endpoints
    try:
        tmp = None
        if passive:
            targets = [h["host"] for h in (resolved_hosts or [])] or [domain]
            tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', prefix='ghostdorks_katana_passive_', delete=False)
            tmp.write('\n'.join(targets))
            tmp.close()
            cmd = ["katana", "-list", tmp.name, "-ps", "-jsonl", "-silent"]
        else:
            targets = [h["url"] for h in (http_hosts or [])] or [f"https://{domain}"]
            tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', prefix='ghostdorks_katana_active_', delete=False)
            tmp.write('\n'.join(targets))
            tmp.close()
            cmd = ["katana", "-list", tmp.name, "-d", "3", "-jc", "-jsonl", "-silent", "-c", "20"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if tmp:
            try:
                os.unlink(tmp.name)
            except Exception:
                pass
        sensitive_ext = {'.env', '.sql', '.bak', '.json', '.xml', '.yaml', '.yml', '.log', '.conf', '.config', '.key', '.pem'}
        api_patterns = re.compile(r'/(api|v\d|graphql|rest|swagger|openapi)', re.I)
        for line in proc.stdout.strip().splitlines():
            try:
                entry = json.loads(line)
                url = entry.get("request", {}).get("endpoint", "") or entry.get("endpoint", "")
                if not url:
                    continue
                ext = os.path.splitext(url.split('?')[0])[1].lower()
                is_sensitive = ext in sensitive_ext
                is_api = bool(api_patterns.search(url))
                endpoints.append({"url": url, "sensitive": is_sensitive, "api": is_api})
            except (json.JSONDecodeError, AttributeError):
                continue
        print(f"[+] katana discovered {len(endpoints)} endpoint(s).")
    except subprocess.TimeoutExpired:
        print("[-] katana timed out.")
    except KeyboardInterrupt:
        print("\n[!] Interrupted katana (Ctrl+C).")
    except Exception as e:
        print(f"[-] katana error: {e}")
    return endpoints

def run_nuclei(http_hosts, katana_endpoints=None, rate=150):
    print(f"[*] Running nuclei vulnerability scan (rate={rate})...")
    findings = []
    if not http_hosts and not katana_endpoints:
        print("[-] No HTTP targets for nuclei. Skipping.")
        return findings
    if not shutil.which("nuclei"):
        print("[-] 'nuclei' not found. Skipping.")
        return findings
    if katana_endpoints:
        targets = list(set(e["url"] for e in katana_endpoints))[:500]
    else:
        targets = [h["url"] for h in http_hosts]
    try:
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', prefix='ghostdorks_nuclei_', delete=False)
        tmp.write('\n'.join(targets))
        tmp.close()
        proc = subprocess.run(
            ["nuclei", "-l", tmp.name, "-t", "exposures/", "-t", "misconfiguration/", "-t", "takeovers/",
             "-severity", "critical,high,medium,low", "-rate-limit", str(rate), "-json", "-silent", "-no-color"],
            capture_output=True, text=True, timeout=600
        )
        os.unlink(tmp.name)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for line in proc.stdout.strip().splitlines():
            try:
                entry = json.loads(line)
                sev = entry.get("info", {}).get("severity", "info").lower()
                findings.append({
                    "template": entry.get("template-id", "unknown"),
                    "name": entry.get("info", {}).get("name", ""),
                    "severity": sev,
                    "severity_order": severity_order.get(sev, 5),
                    "url": entry.get("matched-at", entry.get("host", "")),
                    "description": entry.get("info", {}).get("description", ""),
                    "reference": entry.get("info", {}).get("reference", []),
                    "curl": entry.get("curl-command", ""),
                })
            except json.JSONDecodeError:
                continue
        findings.sort(key=lambda x: x["severity_order"])
        crit = sum(1 for f in findings if f["severity"] == "critical")
        high = sum(1 for f in findings if f["severity"] == "high")
        print(f"[+] nuclei found {len(findings)} findings ({crit} critical, {high} high).")
    except subprocess.TimeoutExpired:
        print("[-] nuclei timed out after 600s.")
    except KeyboardInterrupt:
        print("\n[!] Interrupted nuclei (Ctrl+C).")
    except Exception as e:
        print(f"[-] nuclei error: {e}")
    return findings


# ─────────────────────────────────────────────
# NEW: gf, arjun, subjack Integrations
# ─────────────────────────────────────────────

def run_gf(endpoints, wayback_urls=None):
    """Run gf pattern matching on katana endpoints + wayback URLs."""
    print(f"[*] Running gf pattern matching on {len(endpoints)} endpoints...")
    gf_results = {}
    if not shutil.which("gf"):
        print("[-] 'gf' not found. Skipping gf module.")
        return gf_results

    # Common gf patterns to check
    patterns = ["xss", "sqli", "ssrf", "redirect", "aws-keys", "s3-buckets", 
                "debug-pages", "base64", "jwt", "idor", "lfi", "rce", 
                "takeovers", "upload-fields", "php-errors", "git", "cors"]

    # Combine endpoints and wayback URLs
    all_urls = [e["url"] for e in endpoints]
    if wayback_urls:
        all_urls.extend(wayback_urls)
    all_urls = sorted(set(all_urls))

    if not all_urls:
        print("[-] No URLs to analyze with gf.")
        return gf_results

    try:
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', prefix='ghostdorks_gf_', delete=False)
        tmp.write('\n'.join(all_urls))
        tmp.close()

        for pattern in patterns:
            try:
                proc = subprocess.run(
                    ["bash", "-c", f"cat {tmp.name} | gf {pattern}"],
                    capture_output=True, text=True, timeout=60
                )
                matches = [line.strip() for line in proc.stdout.strip().splitlines() if line.strip()]
                if matches:
                    gf_results[pattern] = matches
                    print(f"    [+] gf {pattern}: {len(matches)} matches")
            except Exception as e:
                continue

        os.unlink(tmp.name)
        total = sum(len(v) for v in gf_results.values())
        print(f"[+] gf analysis complete. {total} total pattern matches across {len(gf_results)} patterns.")
    except Exception as e:
        print(f"[-] gf error: {e}")
    return gf_results

def run_arjun(http_hosts):
    """Run arjun hidden parameter discovery on live HTTP hosts."""
    print(f"[*] Running arjun for hidden parameter discovery on {len(http_hosts)} hosts...")
    arjun_results = []
    if not shutil.which("arjun"):
        print("[-] 'arjun' not found. Skipping arjun module.")
        return arjun_results

    # Limit to top 50 unique hosts to avoid excessive scanning
    targets = list(set(h["url"] for h in http_hosts))[:50]

    for target in targets:
        try:
            proc = subprocess.run(
                ["arjun", "-u", target, "-oJ", "-o", "/tmp/arjun_ghostdorks.json", "-t", "20"],
                capture_output=True, text=True, timeout=120
            )
            if os.path.exists("/tmp/arjun_ghostdorks.json"):
                with open("/tmp/arjun_ghostdorks.json", 'r') as f:
                    data = json.load(f)
                for entry in data:
                    arjun_results.append({
                        "url": entry.get("url", target),
                        "params": entry.get("params", []),
                        "method": entry.get("method", "GET"),
                        "type": entry.get("type", "query")
                    })
                os.unlink("/tmp/arjun_ghostdorks.json")
        except Exception as e:
            continue

    total_params = sum(len(r["params"]) for r in arjun_results)
    print(f"[+] arjun found {total_params} hidden parameters across {len(arjun_results)} hosts.")
    return arjun_results

def run_subjack(subdomains):
    """Run subjack subdomain takeover check on all discovered subdomains."""
    print(f"[*] Running subjack on {len(subdomains)} subdomains...")
    subjack_results = []
    if not shutil.which("subjack"):
        print("[-] 'subjack' not found. Skipping subjack module.")
        return subjack_results

    try:
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', prefix='ghostdorks_subjack_', delete=False)
        tmp.write('\n'.join(subdomains))
        tmp.close()

        proc = subprocess.run(
            ["subjack", "-w", tmp.name, "-v", "-t", "100", "-timeout", "30", "-ssl"],
            capture_output=True, text=True, timeout=300
        )
        os.unlink(tmp.name)

        for line in proc.stdout.strip().splitlines():
            if "[Vulnerable]" in line or "dead" in line.lower() or "takeover" in line.lower():
                parts = line.split()
                host = parts[0] if parts else ""
                service = ""
                status = "CONFIRMED" if "[Vulnerable]" in line else "POTENTIAL"

                # Extract service name if present
                for p in parts:
                    if any(s in p.lower() for s in ["github", "heroku", "aws", "azure", "fastly", "shopify", "pantheon", "tumblr", "wordpress", "teamwork", "helpjuice", "helpscout", "feedpress", "surge", "webflow", "kajabi", "jetbrains", "cloudfront", "zendesk", "readme"]):
                        service = p
                        break

                subjack_results.append({
                    "host": host,
                    "service": service,
                    "status": status,
                    "raw": line
                })

        confirmed = sum(1 for r in subjack_results if r["status"] == "CONFIRMED")
        print(f"[+] subjack found {len(subjack_results)} takeovers ({confirmed} confirmed, {len(subjack_results)-confirmed} potential).")
    except subprocess.TimeoutExpired:
        print("[-] subjack timed out.")
    except KeyboardInterrupt:
        print("\n[!] Interrupted subjack (Ctrl+C).")
    except Exception as e:
        print(f"[-] subjack error: {e}")
    return subjack_results


# ─────────────────────────────────────────────
# cPanel/WHM Reconnaissance Modules
# (Ported from cpanel_scan_v2.sh)
# ─────────────────────────────────────────────

def validate_cpanel_response(body, size):
    """Validate if response is cPanel/WHM based on content markers."""
    if size < CPANEL_MIN_SIZE:
        return False
    markers = 0
    cpanel_markers = ['cpanel', 'whm', 'webhost manager', 'cpsrvd', 'cprelogin', 'cpsession', 'whostmgrsession']
    body_lower = body.lower()
    for marker in cpanel_markers:
        if marker in body_lower:
            markers += 1
    return markers >= 2

def extract_ip_info(target):
    """Extract IP using dig."""
    if not shutil.which("dig"):
        return ""
    for qtype in ["A", "AAAA"]:
        try:
            result = subprocess.run(["dig", "+short", qtype, target], capture_output=True, text=True, timeout=10)
            lines = [l.strip() for l in result.stdout.splitlines() if l.strip() and not l.strip().endswith('.')]
            if lines:
                return lines[0]
        except Exception:
            continue
    return ""

def fetch_geo_ip(ip):
    """Fetch geo/ISP data from ip-api.com."""
    if not ip or ':' in ip:
        return {}
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,as,org", timeout=8)
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass
    return {}

def extract_ssl_info(target, port):
    """Extract SSL certificate info using openssl."""
    if not shutil.which("openssl"):
        return ""
    try:
        result = subprocess.run(
            ["bash", "-c", f"echo | openssl s_client -connect {target}:{port} 2>/dev/null | openssl x509 -noout -text 2>/dev/null"],
            capture_output=True, text=True, timeout=15
        )
        lines = []
        for line in result.stdout.splitlines():
            if any(k in line for k in ["Subject:", "Issuer:", "DNS:", "Not Before", "Not After"]):
                lines.append(line.strip())
        return "\n".join(lines)
    except Exception:
        return ""

def extract_passive_versions(body, headers_text):
    """Extract cPanel version indicators from response body and headers."""
    versions = set()

    # 1. Server header cpsrvd
    srv_match = re.search(r'Server:\s*cpsrvd/([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)', headers_text, re.IGNORECASE)
    if srv_match:
        versions.add(srv_match.group(1))

    # 2. cPanel magic revision timestamps
    rev_matches = re.findall(r'cPanel_magic_revision_([0-9]+)', body)
    for rev in rev_matches:
        versions.add(f"rev_{rev}")

    # 3. Explicit version strings in HTML/JS
    ver_matches = re.findall(r'(?:version|v|build)="?([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)"?', body, re.IGNORECASE)
    versions.update(ver_matches)

    # 4. URL path versions
    path_matches = re.findall(r'/([0-9]+\.[0-9]+\.[0-9]+)(?:/|["\'])', body)
    versions.update(path_matches)

    # 5. Meta/data-version attributes
    data_matches = re.findall(r'data-version="?([0-9]+\.[0-9]+(?:\.[0-9]+)?)', body, re.IGNORECASE)
    versions.update(data_matches)

    # 6. Cookie hints
    cookie_match = re.search(r'cpsession=%3a([^%]+)', body, re.IGNORECASE)
    if cookie_match:
        versions.add(f"cpsession:{cookie_match.group(1)}")

    return sorted(list(versions))

def assess_patch_status(versions):
    """Assess CVE-2026-41940 patch status from extracted versions."""
    if not versions:
        return "UNKNOWN", "No version indicators in response body"

    for ver in versions:
        # Check patched builds
        if PATCHED_BUILDS_RE.search(ver):
            return "PATCHED", f"Detected patched build: {ver}"
        if ver == WP2_PATCHED:
            return "PATCHED", f"WP Squared patched build: {ver}"
        # Check unpatchable tiers
        if UNPATCHABLE_TIERS_RE.search(ver):
            return "NO_VENDOR_PATCH", f"Tier {ver} has NO patch available. Must upgrade or firewall immediately."
        # Check tier range
        tier_match = re.match(r'11\.([0-9]+)\.', ver)
        if tier_match:
            tier = int(tier_match.group(1))
            if tier < 86:
                return "LIKELY_VULNERABLE", f"Pre-11.86 tier ({ver}). No supported patch path. Assume vulnerable."

    # If we have some 11.x version but no specific match
    for ver in versions:
        if re.match(r'11\.[0-9]+\.', ver):
            return "LIKELY_VULNERABLE", f"Version {ver} detected but no patched build string confirmed."

    return "UNKNOWN", "Version data found but no cPanel build match."

def probe_cve_2026_41940(target, port):
    """Active probe for CVE-2026-41940 via /json-api/version."""
    probe_url = f"https://{target}:{port}/json-api/version?api.version=1"
    try:
        response = requests.get(
            probe_url,
            headers={
                "User-Agent": pick_ua(),
                "Authorization": "Basic Y3BhbmVsOmZvcmJpZGRlbg==",
                "Accept": "application/json"
            },
            timeout=PROBE_TIMEOUT,
            verify=False
        )
        if response.status_code == 200 and ('"version"' in response.text or '"build"' in response.text):
            return "VULNERABLE", "Remote probe returned 200 with API version data (CVE-2026-41940)"
        elif response.status_code in (401, 403):
            return "SAFE", f"Remote probe returned {response.status_code} (patched or not WHM)"
        else:
            return "INCONCLUSIVE", f"Remote probe returned HTTP {response.status_code}"
    except requests.exceptions.Timeout:
        return "INCONCLUSIVE", "Remote probe timed out"
    except Exception as e:
        return "INCONCLUSIVE", f"Remote probe error: {str(e)}"

def calculate_cpanel_risk(service_type, patch_status, probe_status, has_security_headers, is_letsencrypt):
    """Calculate risk score for cPanel/WHM target."""
    score = 0
    if service_type == "WHM":
        score += 2

    risk_map = {
        "NO_VENDOR_PATCH": 5,
        "LIKELY_VULNERABLE": 3,
        "UNKNOWN": 2,
        "PATCHED": -2
    }
    score += risk_map.get(patch_status, 0)

    probe_map = {
        "VULNERABLE": 5,
        "SAFE": -1,
        "INCONCLUSIVE": 1,
        "NOT_TESTED": 0
    }
    score += probe_map.get(probe_status, 0)

    if not has_security_headers:
        score += 1

    if score >= 6:
        return "CRITICAL", score
    elif score >= 4:
        return "HIGH", score
    elif score >= 2:
        return "MEDIUM", score
    else:
        return "LOW", score

def detect_cpanel_services(target, active_probe=False):
    """
    Detect cPanel/WHM on ports 2083/2087.
    Returns dict with all recon data or None if not detected.
    """
    print(f"[*] Checking {target} for cPanel/WHM on ports 2083/2087...")

    cpanel_data = {
        "detected": False,
        "service_type": "NONE",
        "port": None,
        "target_ip": "",
        "body_size": 0,
        "response_time": 0,
        "versions": [],
        "patch_status": "UNKNOWN",
        "patch_detail": "No version data",
        "probe_status": "NOT_TESTED",
        "probe_detail": "Probe disabled",
        "risk_level": "N/A",
        "risk_score": 0,
        "security_headers": False,
        "letsencrypt": False,
        "ssl_info": "",
        "geo_data": {},
        "headers": "",
        "body_snippet": ""
    }

    for port in [2083, 2087]:
        url = f"https://{target}:{port}"
        try:
            start = time.time()
            response = requests.get(
                url, headers={"User-Agent": pick_ua()}, 
                timeout=CPANEL_TIMEOUT, verify=False,
                allow_redirects=True
            )
            elapsed = time.time() - start
            size = len(response.content)

            if not validate_cpanel_response(response.text, size):
                continue

            cpanel_data["detected"] = True
            cpanel_data["port"] = port
            cpanel_data["service_type"] = "cPanel" if port == 2083 else "WHM"
            cpanel_data["body_size"] = size
            cpanel_data["response_time"] = round(elapsed, 2)
            cpanel_data["headers"] = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
            cpanel_data["body_snippet"] = response.text[:2000]

            print(f"[!] {cpanel_data['service_type']} Detected on port {port} (size: {size}B, time: {elapsed:.2f}s)")

            # Infrastructure
            cpanel_data["target_ip"] = extract_ip_info(target)
            if cpanel_data["target_ip"]:
                print(f"[+] IP: {cpanel_data['target_ip']}")
                cpanel_data["geo_data"] = fetch_geo_ip(cpanel_data["target_ip"])
                if cpanel_data["geo_data"].get("country"):
                    print(f"[+] Geo: {cpanel_data['geo_data'].get('city', 'N/A')}, {cpanel_data['geo_data'].get('country', 'N/A')} — {cpanel_data['geo_data'].get('isp', 'N/A')}")

            # Headers & Hardening
            headers_lower = cpanel_data["headers"].lower()
            cpanel_data["security_headers"] = any(h in headers_lower for h in [
                'x-frame-options', 'x-content-type-options', 'content-security-policy', 'strict-transport-security'
            ])
            cpanel_data["letsencrypt"] = "let's encrypt" in headers_lower

            if cpanel_data["security_headers"]:
                print("[+] Security headers present")
            else:
                print("[-] Missing security headers (X-Frame-Options, X-Content-Type-Options, HSTS, CSP)")
            if cpanel_data["letsencrypt"]:
                print("[+] Certificate: Let's Encrypt")

            # SSL
            cpanel_data["ssl_info"] = extract_ssl_info(target, port)
            if cpanel_data["ssl_info"]:
                print("[+] SSL certificate data extracted")

            # Passive Version Fingerprinting
            cpanel_data["versions"] = extract_passive_versions(response.text, cpanel_data["headers"])
            if cpanel_data["versions"]:
                print(f"[+] Extracted version indicators: {', '.join(cpanel_data['versions'][:10])}")
            else:
                print("[-] No version indicators found in passive content")

            # Patch Assessment
            patch_status, patch_detail = assess_patch_status(cpanel_data["versions"])
            cpanel_data["patch_status"] = patch_status
            cpanel_data["patch_detail"] = patch_detail

            status_colors = {
                "PATCHED": "[+]",
                "NO_VENDOR_PATCH": "[!!!] CRITICAL:",
                "LIKELY_VULNERABLE": "[!] WARNING:",
                "UNKNOWN": "[?]"
            }
            print(f"{status_colors.get(patch_status, '[?]')} CVE-2026-41940 Patch Status: {patch_detail}")

            # Active Probe (WHM only, if enabled)
            if active_probe and cpanel_data["service_type"] == "WHM":
                print("\n--- ACTIVE REMOTE PROBE (CVE-2026-41940) ---")
                probe_status, probe_detail = probe_cve_2026_41940(target, port)
                cpanel_data["probe_status"] = probe_status
                cpanel_data["probe_detail"] = probe_detail

                if probe_status == "VULNERABLE":
                    print(f"[!!!] VULNERABLE: {probe_detail}")
                elif probe_status == "SAFE":
                    print(f"[+] SAFE: {probe_detail}")
                else:
                    print(f"[?] INCONCLUSIVE: {probe_detail}")

            # Risk Score
            risk_level, risk_score = calculate_cpanel_risk(
                cpanel_data["service_type"], patch_status, 
                cpanel_data["probe_status"], cpanel_data["security_headers"], cpanel_data["letsencrypt"]
            )
            cpanel_data["risk_level"] = risk_level
            cpanel_data["risk_score"] = risk_score

            if risk_level == "CRITICAL":
                print(f"\n[!!!] RISK LEVEL: {risk_level} (score: {risk_score})\n      ACTION REQUIRED: Assume compromise risk. Firewall 2083/2087 immediately.")
            elif risk_level == "HIGH":
                print(f"\n[!] RISK LEVEL: {risk_level} (score: {risk_score})\n      ACTION REQUIRED: Patch or restrict access urgently.")
            else:
                print(f"\n[!] RISK LEVEL: {risk_level} (score: {risk_score})")

            return cpanel_data

        except requests.exceptions.Timeout:
            continue
        except requests.exceptions.ConnectionError:
            continue
        except Exception as e:
            print(f"[-] Error checking port {port}: {e}")
            continue

    if not cpanel_data["detected"]:
        print(f"[-] No cPanel/WHM detected on {target} (ports 2083/2087).")
    return cpanel_data


# ─────────────────────────────────────────────
# Dashboard Generator
# ─────────────────────────────────────────────

def generate_ghost_dashboard(target, cfg=None):
    if cfg is None:
        cfg = {}
    active   = cfg.get("active", False)
    do_nuclei = cfg.get("nuclei", False)
    rate     = cfg.get("rate", 1000)
    cpanel_probe = cfg.get("cpanel_probe", False)
    do_gf    = cfg.get("gf", False)
    do_arjun = cfg.get("arjun", False)
    do_subjack = cfg.get("subjack", False)
    safe_target = html.escape(target)

    print("\n" + "="*55)
    print("  🕵️  PROJECT GHOST ENGINE — Unified Recon Pipeline v4.0")
    print("  DorkEye Dork Engine | gf | arjun | subjack | cPanel Triage")
    print("="*55)
    if active:
        print("  ⚠️  ACTIVE MODE enabled (naabu + httpx + katana)")
    if do_nuclei:
        print("  💀  NUCLEI enabled — vulnerability scanning active")
    if cpanel_probe:
        print("  🎯  CPANEL PROBE enabled — CVE-2026-41940 active test")
    if do_gf:
        print("  🔎  GF enabled — pattern matching on endpoints")
    if do_arjun:
        print("  🕵️  ARJUN enabled — hidden parameter discovery")
    if do_subjack:
        print("  🎣  SUBJACK enabled — subdomain takeover scanning")
    print("="*55 + "\n")

    # ── Passive baseline ────────────────────
    discovered_subdomains = fetch_subdomains(target)
    sf_subs = run_subfinder(target)
    all_subdomains = sorted(set(discovered_subdomains) | set(sf_subs))
    if sf_subs:
        print(f"[+] Combined subdomain list: {len(all_subdomains)} unique entries.")
    else:
        all_subdomains = discovered_subdomains

    resolved_hosts, takeover_candidates = run_dnsx(all_subdomains)
    discovered_wayback_urls = fetch_wayback_urls(target)

    target_ip = ""
    open_ports = []
    vulns = []
    try:
        target_ip = socket.gethostbyname(target)
        open_ports, vulns = fetch_open_ports(target_ip)
    except socket.gaierror:
        print(f"[-] Could not resolve IP address for {target}. Skipping Shodan scan.")

    whois_info = fetch_whois_info(target)
    dns_records = fetch_dns_records(target)
    harvest_data = fetch_emails_theharvester(target)
    co_hosted_domains = fetch_reverse_ip(target_ip) if target_ip else []
    katana_endpoints = run_katana(target, resolved_hosts=resolved_hosts, passive=True)

    # ── NEW: subjack (always runs if enabled) ──
    subjack_results = []
    if do_subjack:
        subjack_results = run_subjack(all_subdomains)

    # ── NEW: cPanel/WHM Detection (always runs as passive) ──
    cpanel_data = detect_cpanel_services(target, active_probe=cpanel_probe)

    # ── Active pipeline ─────────────────────
    naabu_results  = []
    http_hosts     = []
    nuclei_findings = []
    gf_results = {}
    arjun_results = []

    if active and resolved_hosts:
        naabu_results = run_naabu(resolved_hosts, rate=rate)
        http_hosts = run_httpx(resolved_hosts, naabu_results=naabu_results)
        if http_hosts:
            katana_endpoints = run_katana(target, http_hosts=http_hosts, passive=False)

    # ── NEW: gf pattern matching ──
    if do_gf:
        gf_results = run_gf(katana_endpoints, discovered_wayback_urls)

    # ── NEW: arjun parameter discovery ──
    if do_arjun and http_hosts:
        arjun_results = run_arjun(http_hosts)

    if do_nuclei:
        if not http_hosts and resolved_hosts:
            print("[*] --nuclei requires httpx; running httpx first...")
            http_hosts = run_httpx(resolved_hosts)
        nuclei_findings = run_nuclei(http_hosts, katana_endpoints=katana_endpoints, rate=150)

    # ── Dork Map Generation ─────────────────
    dork_map = {}

    # Add discovered subdomains as their own category
    if all_subdomains:
        sub_dorks = [f"site:{sub}" for sub in all_subdomains[:50]]
        dork_map["🌐 Discovered Subdomains"] = sub_dorks

    # Build dorks from templates with target interpolation
    for category, templates in DORK_TEMPLATES.items():
        dork_map[category] = []
        for template in templates:
            # Replace {target} with actual domain
            dork = template.replace("{target}", target)
            dork_map[category].append(dork)

    # Add subdomain-specific variants for key categories
    if all_subdomains:
        for sub in all_subdomains[:20]:
            dork_map["🐱 Subdomain Recon"].append(f"site:{sub}")
            dork_map["🏗️ Dev / Test / Staging"].append(f"site:{sub}")

    # ── HTML Generation ─────────────────────
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>GhostDorks v4.0 - {safe_target}</title>
        <style>
            :root {{ --main-green: #00ff41; --bg-black: #0d0d0d; --card-bg: #1a1a1a; --blue: #00ccff; --wayback-yellow: #ffb800; --shodan-red: #ff3333; --whois-cyan: #00e5ff; --dns-purple: #b388ff; --harvest-orange: #ff9100; --reverse-teal: #1de9b6; --dnsx-lime: #c6ff00; --httpx-pink: #ff4081; --katana-sky: #40c4ff; --nuclei-crit: #ff1744; --nuclei-high: #ff6d00; --nuclei-med: #ffd600; --nuclei-low: #69f0ae; --cpanel-orange: #ff6f00; --cpanel-red: #d50000; --cpanel-amber: #ffab00; --gf-purple: #e040fb; --arjun-blue: #448aff; --subjack-red: #ff5252; }}
            body {{ font-family: 'Courier New', monospace; background-color: var(--bg-black); color: var(--main-green); margin: 0; padding: 20px; }}
            .container {{ max-width: 1200px; margin: auto; }}
            header {{ border-bottom: 2px solid var(--main-green); padding-bottom: 20px; margin-bottom: 30px; text-align: center; }}
            h1 {{ text-shadow: 0 0 15px var(--main-green); letter-spacing: 2px; margin-bottom: 5px; }}
            .stats {{ color: #888; font-size: 14px; margin-top: 5px; line-height: 1.6; }}
            .controls {{ display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; justify-content: center; }}
            .search-box {{ flex-grow: 1; padding: 12px; background: #111; border: 1px solid var(--main-green); color: var(--main-green); font-size: 16px; outline: none; }}
            .btn {{ background: transparent; border: 1px solid var(--main-green); color: var(--main-green); padding: 10px 20px; cursor: pointer; transition: 0.3s; font-family: inherit; }}
            .btn:hover {{ background: var(--main-green); color: black; font-weight: bold; }}
            .category-section {{ margin-bottom: 30px; border: 1px solid #333; padding: 15px; border-radius: 5px; background: #0a0a0a; }}
            h2 {{ color: #ff003c; font-size: 20px; margin-top: 0; border-bottom: 1px solid #222; padding-bottom: 10px; }}
            .intel-table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
            .intel-table td {{ padding: 8px 12px; border-bottom: 1px solid #222; vertical-align: top; }}
            .intel-table td:first-child {{ color: #888; white-space: nowrap; width: 180px; font-weight: bold; }}
            .intel-table td:last-child {{ color: #ddd; word-break: break-all; }}
            .dns-badge {{ display: inline-block; padding: 3px 10px; margin: 3px; border-radius: 3px; font-size: 12px; border: 1px solid #333; }}
            .security-note {{ color: var(--shodan-red); padding: 6px 10px; margin: 4px 0; font-size: 13px; background: rgba(255,51,51,0.1); border-left: 3px solid var(--shodan-red); }}
            .email-chip {{ display: inline-block; padding: 5px 12px; margin: 3px; border-radius: 20px; font-size: 13px; background: rgba(255,145,0,0.15); border: 1px solid var(--harvest-orange); color: var(--harvest-orange); }}
            .host-chip {{ display: inline-block; padding: 5px 12px; margin: 3px; border-radius: 20px; font-size: 13px; background: rgba(0,229,255,0.1); border: 1px solid var(--whois-cyan); color: var(--whois-cyan); }}
            .sev-badge {{ display: inline-block; padding: 2px 10px; border-radius: 3px; font-size: 11px; font-weight: bold; margin-right: 8px; text-transform: uppercase; }}
            .sev-critical {{ background: var(--nuclei-crit); color: #000; }}
            .sev-high {{ background: var(--nuclei-high); color: #000; }}
            .sev-medium {{ background: var(--nuclei-med); color: #000; }}
            .sev-low {{ background: var(--nuclei-low); color: #000; }}
            .sev-info {{ background: #444; color: #fff; }}
            .finding-item {{ padding: 10px 12px; border-left: 3px solid #333; margin: 6px 0; background: #0d0d0d; }}
            .httpx-row {{ display: grid; grid-template-columns: 60px 1fr 120px 1fr; gap: 8px; align-items: center; padding: 8px 12px; border-bottom: 1px solid #1a1a1a; font-size: 13px; }}
            .httpx-row:hover {{ background: #111; }}
            .status-2xx {{ color: #69f0ae; font-weight: bold; }}
            .status-3xx {{ color: #ffb800; font-weight: bold; }}
            .status-4xx {{ color: #ff9100; font-weight: bold; }}
            .status-5xx {{ color: #ff1744; font-weight: bold; }}
            .tech-pill {{ display: inline-block; padding: 2px 8px; margin: 2px; border-radius: 10px; font-size: 11px; background: rgba(64,196,255,0.15); border: 1px solid var(--katana-sky); color: var(--katana-sky); }}
            .dork-list {{ display: grid; grid-template-columns: 1fr; gap: 8px; }}
            .dork-item {{ background: #111; padding: 10px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; border: 1px solid #222; transition: 0.2s; }}
            .dork-item:hover {{ border-color: #444; background: #151515; }}
            .dork-text {{ color: var(--blue); text-decoration: none; font-size: 14px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex-grow: 1; margin-right: 15px; }}
            .dork-text:hover {{ text-decoration: underline; color: #fff; }}
            .wayback-link {{ color: var(--wayback-yellow); }}
            .copy-btn {{ font-size: 11px; padding: 6px 12px; border: 1px solid #444; color: #888; background: #222; cursor: pointer; font-weight: bold; transition: 0.2s; }}
            .copy-btn:hover {{ color: #000; background: var(--main-green); border-color: var(--main-green); }}
            .alert {{ position: fixed; bottom: 20px; right: 20px; background: var(--main-green); color: black; padding: 10px 20px; display: none; font-weight: bold; z-index: 1000; box-shadow: 0 0 10px var(--main-green); }}

            /* cPanel-specific styles */
            .cpanel-banner {{ background: linear-gradient(90deg, rgba(255,111,0,0.1), rgba(213,0,0,0.1)); border: 1px solid var(--cpanel-orange); padding: 15px; margin-bottom: 20px; border-radius: 5px; }}
            .cpanel-banner h2 {{ color: var(--cpanel-orange); border-bottom: 1px solid var(--cpanel-orange); }}
            .risk-critical {{ color: var(--cpanel-red); font-weight: bold; text-shadow: 0 0 10px var(--cpanel-red); }}
            .risk-high {{ color: var(--nuclei-high); font-weight: bold; }}
            .risk-medium {{ color: var(--cpanel-amber); font-weight: bold; }}
            .risk-low {{ color: var(--main-green); font-weight: bold; }}
            .risk-na {{ color: #666; }}
            .cpanel-badge {{ display: inline-block; padding: 4px 12px; margin: 3px; border-radius: 3px; font-size: 12px; font-weight: bold; border: 1px solid; }}
            .badge-patched {{ border-color: var(--main-green); color: var(--main-green); background: rgba(0,255,65,0.1); }}
            .badge-vulnerable {{ border-color: var(--cpanel-red); color: var(--cpanel-red); background: rgba(213,0,0,0.1); }}
            .badge-unknown {{ border-color: #888; color: #888; background: rgba(136,136,136,0.1); }}
            .badge-nopatch {{ border-color: var(--cpanel-amber); color: var(--cpanel-amber); background: rgba(255,171,0,0.1); }}
            .code-block {{ background: #111; border: 1px solid #333; padding: 10px; font-size: 12px; color: #aaa; overflow-x: auto; white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow-y: auto; }}

            /* gf styles */
            .gf-banner {{ background: linear-gradient(90deg, rgba(224,64,251,0.1), rgba(68,138,255,0.1)); border: 1px solid var(--gf-purple); padding: 15px; margin-bottom: 20px; border-radius: 5px; }}
            .gf-banner h2 {{ color: var(--gf-purple); border-bottom: 1px solid var(--gf-purple); }}
            .gf-pattern {{ margin-bottom: 15px; }}
            .gf-pattern-name {{ color: var(--gf-purple); font-weight: bold; font-size: 14px; margin-bottom: 5px; }}
            .gf-match {{ color: #aaa; font-size: 12px; padding: 3px 0; border-bottom: 1px solid #1a1a1a; }}
            .gf-match:last-child {{ border-bottom: none; }}

            /* arjun styles */
            .arjun-banner {{ background: linear-gradient(90deg, rgba(68,138,255,0.1), rgba(0,204,255,0.1)); border: 1px solid var(--arjun-blue); padding: 15px; margin-bottom: 20px; border-radius: 5px; }}
            .arjun-banner h2 {{ color: var(--arjun-blue); border-bottom: 1px solid var(--arjun-blue); }}
            .arjun-host {{ margin-bottom: 12px; }}
            .arjun-host-name {{ color: var(--arjun-blue); font-weight: bold; font-size: 14px; margin-bottom: 5px; }}
            .arjun-param {{ display: inline-block; padding: 2px 8px; margin: 2px; border-radius: 10px; font-size: 11px; background: rgba(68,138,255,0.15); border: 1px solid var(--arjun-blue); color: var(--arjun-blue); }}

            /* subjack styles */
            .subjack-banner {{ background: linear-gradient(90deg, rgba(255,82,82,0.1), rgba(255,23,68,0.1)); border: 1px solid var(--subjack-red); padding: 15px; margin-bottom: 20px; border-radius: 5px; }}
            .subjack-banner h2 {{ color: var(--subjack-red); border-bottom: 1px solid var(--subjack-red); }}
            .subjack-confirmed {{ color: var(--subjack-red); font-weight: bold; }}
            .subjack-potential {{ color: var(--cpanel-amber); font-weight: bold; }}
            .subjack-item {{ padding: 8px 12px; border-left: 3px solid #333; margin: 4px 0; background: #0d0d0d; font-size: 13px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>🕵️ PROJECT GHOST ENGINE v4.0</h1>
                <h3>created by: L4ZYG33K | DorkEye + gf + arjun + subjack + cPanel</h3>
                <p>Target: <strong style="color: #fff;">{safe_target}</strong> {f"({target_ip})" if target_ip else ""}</p>
                <div class="stats">
                    Subdomains: <strong style="color: var(--main-green);">{len(all_subdomains)}</strong> |
                    Resolved Live: <strong style="color: var(--dnsx-lime);">{len(resolved_hosts)}</strong> |
                    Takeover Candidates: <strong style="color: var(--shodan-red);">{len(takeover_candidates)}</strong> |
                    Wayback Files: <strong style="color: var(--wayback-yellow);">{len(discovered_wayback_urls)}</strong><br>
                    Open Ports: <strong style="color: var(--shodan-red);">{len(open_ports)}</strong> |
                    CVEs: <strong style="color: var(--shodan-red);">{len(vulns)}</strong> |
                    Emails: <strong style="color: var(--harvest-orange);">{len(harvest_data['emails'])}</strong> |
                    Co-Hosted: <strong style="color: var(--reverse-teal);">{len(co_hosted_domains)}</strong><br>
                    HTTP Hosts: <strong style="color: var(--httpx-pink);">{len(http_hosts)}</strong> |
                    Endpoints: <strong style="color: var(--katana-sky);">{len(katana_endpoints)}</strong> |
                    Nuclei Findings: <strong style="color: var(--nuclei-crit);">{len(nuclei_findings)}</strong>
                    {f' | GF Patterns: <strong style="color: var(--gf-purple);">{len(gf_results)}</strong>' if gf_results else ''}
                    {f' | Arjun Params: <strong style="color: var(--arjun-blue);">{sum(len(r["params"]) for r in arjun_results)}</strong>' if arjun_results else ''}
                    {f' | Subjack: <strong style="color: var(--subjack-red);">{len(subjack_results)}</strong>' if subjack_results else ''}
                    {f' | cPanel/WHM: <strong style="color: var(--cpanel-orange);">{html.escape(cpanel_data["service_type"])}</strong> | Risk: <strong style="color: {"var(--cpanel-red)" if cpanel_data["risk_level"] == "CRITICAL" else "var(--nuclei-high)" if cpanel_data["risk_level"] == "HIGH" else "var(--cpanel-amber)" if cpanel_data["risk_level"] == "MEDIUM" else "var(--main-green)"}">{html.escape(cpanel_data["risk_level"])}</strong>' if cpanel_data["detected"] else ''}
                </div>
            </header>

            <div class="controls">
                <input type="text" class="search-box" id="searchInput" placeholder="Filter by keyword (e.g. 'sql', 'env', 'login')...">
                <button class="btn" onclick="window.print()">Export PDF</button>
            </div>

            <div id="dorkContainer">
    """

    # ── cPanel/WHM Section ──
    if cpanel_data["detected"]:
        risk_class = {
            "CRITICAL": "risk-critical",
            "HIGH": "risk-high", 
            "MEDIUM": "risk-medium",
            "LOW": "risk-low",
            "N/A": "risk-na"
        }.get(cpanel_data["risk_level"], "risk-na")

        patch_badge_class = {
            "PATCHED": "badge-patched",
            "LIKELY_VULNERABLE": "badge-vulnerable",
            "NO_VENDOR_PATCH": "badge-nopatch",
            "UNKNOWN": "badge-unknown"
        }.get(cpanel_data["patch_status"], "badge-unknown")

        probe_badge_class = {
            "VULNERABLE": "badge-vulnerable",
            "SAFE": "badge-patched",
            "INCONCLUSIVE": "badge-unknown",
            "NOT_TESTED": "badge-unknown"
        }.get(cpanel_data["probe_status"], "badge-unknown")

        geo_str = ""
        if cpanel_data.get("geo_data"):
            gd = cpanel_data["geo_data"]
            geo_str = f"{gd.get('city', 'N/A')}, {gd.get('country', 'N/A')} — {gd.get('isp', 'N/A')}"

        ns_list = ", ".join(whois_info.get("name_servers", [])) or "N/A"

        html_content += f"""
        <div class="category-section cpanel-banner">
            <h2>🎛️ cPanel/WHM Reconnaissance & CVE-2026-41940 Triage</h2>
            <table class="intel-table">
                <tr><td>Service</td><td><strong style="color: var(--cpanel-orange);">{html.escape(cpanel_data["service_type"])}</strong> on port {cpanel_data["port"]} ({cpanel_data["body_size"]}B, {cpanel_data["response_time"]}s)</td></tr>
                <tr><td>Target IP</td><td>{html.escape(cpanel_data["target_ip"] or "N/A")}</td></tr>
                <tr><td>Geolocation</td><td>{html.escape(geo_str)}</td></tr>
                <tr><td>Risk Level</td><td><span class="{risk_class}">{html.escape(cpanel_data["risk_level"])}</span> (score: {cpanel_data["risk_score"]})</td></tr>
                <tr><td>Patch Status</td><td><span class="cpanel-badge {patch_badge_class}">{html.escape(cpanel_data["patch_status"])}</span> — {html.escape(cpanel_data["patch_detail"])}</td></tr>
                <tr><td>Probe Status</td><td><span class="cpanel-badge {probe_badge_class}">{html.escape(cpanel_data["probe_status"])}</span> — {html.escape(cpanel_data["probe_detail"])}</td></tr>
                <tr><td>Security Headers</td><td>{"✅ Present" if cpanel_data["security_headers"] else "❌ Missing (X-Frame-Options, X-Content-Type-Options, HSTS, CSP)"}</td></tr>
                <tr><td>Certificate</td><td>{"Let's Encrypt" if cpanel_data["letsencrypt"] else "Other / Unknown"}</td></tr>
                <tr><td>Version Indicators</td><td>{", ".join(html.escape(v) for v in cpanel_data["versions"][:15]) or "None extracted"}</td></tr>
                <tr><td>Name Servers</td><td>{html.escape(ns_list)}</td></tr>
            </table>

            {f'<div style="margin-top: 12px;"><strong style="color: #888;">SSL Certificate Info:</strong><div class="code-block">{html.escape(cpanel_data["ssl_info"])}</div></div>' if cpanel_data["ssl_info"] else ''}

            {f'<div style="margin-top: 12px;"><strong style="color: #888;">Response Headers:</strong><div class="code-block">{html.escape(cpanel_data["headers"])}</div></div>' if cpanel_data["headers"] else ''}

            {f'<div style="margin-top: 12px;"><strong style="color: #888;">Body Snippet:</strong><div class="code-block">{html.escape(cpanel_data["body_snippet"][:1500])}</div></div>' if cpanel_data["body_snippet"] else ''}
        </div>"""

    # ── subjack Section ──
    if subjack_results:
        confirmed = [r for r in subjack_results if r["status"] == "CONFIRMED"]
        potential = [r for r in subjack_results if r["status"] != "CONFIRMED"]
        html_content += f"""
        <div class="category-section subjack-banner">
            <h2>🎣 Subjack Takeover Results — {len(subjack_results)} found ({len(confirmed)} confirmed, {len(potential)} potential)</h2>
            <div>"""
        if confirmed:
            html_content += '<div style="margin-bottom: 12px;"><strong style="color: var(--subjack-red);">CONFIRMED VULNERABLE:</strong><br>'
            for r in confirmed[:50]:
                svc = f" [{html.escape(r['service'])}]" if r["service"] else ""
                html_content += f'<div class="subjack-item"><span class="subjack-confirmed">⚠️ {html.escape(r["host"])}{svc}</span><br><span style="color:#555;font-size:11px;">{html.escape(r["raw"])}</span></div>'
            html_content += '</div>'
        if potential:
            html_content += '<div><strong style="color: var(--cpanel-amber);">POTENTIAL TAKEOVERS:</strong><br>'
            for r in potential[:50]:
                svc = f" [{html.escape(r['service'])}]" if r["service"] else ""
                html_content += f'<div class="subjack-item"><span class="subjack-potential">? {html.escape(r["host"])}{svc}</span><br><span style="color:#555;font-size:11px;">{html.escape(r["raw"])}</span></div>'
            html_content += '</div>'
        html_content += '</div></div>'

    # ── gf Section ──
    if gf_results:
        html_content += f"""
        <div class="category-section gf-banner">
            <h2>🔎 GF Pattern Matches — {len(gf_results)} patterns, {sum(len(v) for v in gf_results.values())} total matches</h2>
            <div>"""
        for pattern, matches in gf_results.items():
            html_content += f'<div class="gf-pattern"><div class="gf-pattern-name">🎯 {html.escape(pattern.upper())} ({len(matches)} matches)</div>'
            for match in matches[:30]:
                safe_match = html.escape(match)
                html_content += f'<div class="gf-match"><a href="{safe_match}" target="_blank" style="color:#aaa;text-decoration:none;">{safe_match}</a></div>'
            html_content += '</div>'
        html_content += '</div></div>'

    # ── arjun Section ──
    if arjun_results:
        html_content += f"""
        <div class="category-section arjun-banner">
            <h2>🕵️ Hidden Parameters (Arjun) — {sum(len(r["params"]) for r in arjun_results)} params across {len(arjun_results)} hosts</h2>
            <div>"""
        for entry in arjun_results[:50]:
            params_html = " ".join(f'<span class="arjun-param">{html.escape(p)}</span>' for p in entry["params"])
            html_content += f'<div class="arjun-host"><div class="arjun-host-name">{html.escape(entry["url"])} <span style="color:#555;font-size:12px;">({html.escape(entry["method"])} / {html.escape(entry["type"])})</span></div>{params_html}</div>'
        html_content += '</div></div>'

    # ── WHOIS ──
    if whois_info and whois_info.get("registrar") != "N/A":
        ns_list = ", ".join(whois_info.get("name_servers", [])) or "N/A"
        html_content += f"""
        <div class="category-section">
            <h2 style="color: var(--whois-cyan);">🔍 WHOIS Intelligence</h2>
            <table class="intel-table">
                <tr><td>Registrar</td><td>{html.escape(whois_info.get('registrar', 'N/A'))}</td></tr>
                <tr><td>Organization</td><td>{html.escape(whois_info.get('organization', 'N/A'))}</td></tr>
                <tr><td>Country</td><td>{html.escape(whois_info.get('country', 'N/A'))}</td></tr>
                <tr><td>Creation Date</td><td>{html.escape(whois_info.get('creation_date', 'N/A'))}</td></tr>
                <tr><td>Expiry Date</td><td>{html.escape(whois_info.get('expiry_date', 'N/A'))}</td></tr>
                <tr><td>Updated Date</td><td>{html.escape(whois_info.get('updated_date', 'N/A'))}</td></tr>
                <tr><td>Registrant Email</td><td>{html.escape(whois_info.get('registrant_email', 'N/A'))}</td></tr>
                <tr><td>DNSSEC</td><td>{html.escape(whois_info.get('dnssec', 'N/A'))}</td></tr>
                <tr><td>Name Servers</td><td>{html.escape(ns_list)}</td></tr>
            </table>
        </div>"""

    # ── DNS ──
    dns_record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    has_dns = any(dns_records.get(rt) for rt in dns_record_types)
    if has_dns:
        html_content += f"""
        <div class="category-section">
            <h2 style="color: var(--dns-purple);">🧬 DNS Record Map</h2>"""
        if dns_records.get("security_notes"):
            for note in dns_records["security_notes"]:
                html_content += f'<div class="security-note">{html.escape(note)}</div>'
        html_content += '<table class="intel-table">'
        for rt in dns_record_types:
            records = dns_records.get(rt, [])
            if records:
                records_html = "<br>".join([html.escape(r) for r in records])
                html_content += f'<tr><td style="color: var(--dns-purple);">{rt}</td><td>{records_html}</td></tr>'
        html_content += '</table></div>'

    # ── Emails ──
    if harvest_data.get("emails") or harvest_data.get("hosts"):
        html_content += f"""
        <div class="category-section">
            <h2 style="color: var(--harvest-orange);">📧 Harvested Emails & Hosts (theHarvester)</h2>
            <div style="margin-bottom: 15px;">"""
        if harvest_data.get("emails"):
            html_content += '<div style="margin-bottom: 10px;"><strong style="color: #888;">Emails:</strong><br>'
            for email in harvest_data["emails"]:
                html_content += f'<span class="email-chip">{html.escape(email)}</span>'
            html_content += '</div>'
        if harvest_data.get("hosts"):
            html_content += '<div style="margin-bottom: 10px;"><strong style="color: #888;">Discovered Hosts:</strong><br>'
            for h in harvest_data["hosts"][:100]:
                html_content += f'<span class="host-chip">{html.escape(h)}</span>'
            html_content += '</div>'
        if harvest_data.get("ips"):
            html_content += '<div><strong style="color: #888;">Associated IPs:</strong><br>'
            for ip in harvest_data["ips"][:50]:
                html_content += f'<span class="dns-badge" style="border-color: var(--harvest-orange); color: var(--harvest-orange);">{html.escape(ip)}</span>'
            html_content += '</div>'
        html_content += '</div></div>'

    # ── Reverse IP ──
    if co_hosted_domains:
        html_content += f"""
        <div class="category-section">
            <h2 style="color: var(--reverse-teal);">🗺️ Co-Hosted Domains (Reverse IP: {target_ip})</h2>
            <div class="dork-list">"""
        for co_domain in co_hosted_domains[:200]:
            safe_co = html.escape(co_domain)
            google_url = f"https://www.google.com/search?q=site:{urllib.parse.quote_plus(co_domain)}"
            html_content += f"""
                <div class="dork-item">
                    <a href="{google_url}" target="_blank" class="dork-text" style="color: var(--reverse-teal);">{safe_co}</a>
                    <button class="copy-btn" data-dork="{safe_co}" onclick="copyToClipboard(this.getAttribute('data-dork'))">COPY</button>
                </div>"""
        html_content += '</div></div>'

    # ── dnsx ──
    if resolved_hosts or takeover_candidates:
        html_content += f"""
        <div class="category-section">
            <h2 style="color: var(--dnsx-lime);">🧬 Live Resolved Hosts (dnsx) — {len(resolved_hosts)} live</h2>"""
        if takeover_candidates:
            for tc in takeover_candidates:
                safe_h = html.escape(tc['host'])
                safe_c = html.escape(', '.join(tc.get('cname', [])))
                html_content += f'<div class="security-note">⚠️ Takeover Candidate: <strong>{safe_h}</strong> → CNAME: {safe_c}</div>'
        if resolved_hosts:
            html_content += '<table class="intel-table" style="margin-top:10px;"><tr><td style="color:#888;width:40%">Host</td><td style="color:#888;">IPs</td></tr>'
            for rh in resolved_hosts[:150]:
                safe_h  = html.escape(rh['host'])
                safe_ip = html.escape(', '.join(rh.get('ips', [])))
                html_content += f'<tr><td style="color:var(--dnsx-lime);">{safe_h}</td><td style="color:#aaa;">{safe_ip}</td></tr>'
            html_content += '</table>'
        html_content += '</div>'

    # ── httpx ──
    if http_hosts:
        html_content += f"""
        <div class="category-section">
            <h2 style="color: var(--httpx-pink);">🌐 Live HTTP Services (httpx) — {len(http_hosts)} hosts</h2>
            <div style="font-size:12px;color:#555;margin-bottom:8px;">Status | URL | Server | Technologies</div>"""
        for hh in http_hosts[:200]:
            sc = hh.get("status", 0)
            sc_class = "status-2xx" if 200<=sc<300 else "status-3xx" if 300<=sc<400 else "status-4xx" if 400<=sc<500 else "status-5xx"
            safe_url   = html.escape(hh.get("url", ""))
            safe_srv   = html.escape(hh.get("server", "") or "")
            safe_title = html.escape(hh.get("title", "") or "")
            tech_html  = "".join(f'<span class="tech-pill">{html.escape(str(t))}</span>' for t in (hh.get("tech") or [])[:6])
            html_content += f'<div class="httpx-row"><span class="{sc_class}">{sc}</span><a href="{safe_url}" target="_blank" style="color:var(--httpx-pink);text-decoration:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="{safe_title}">{safe_url}</a><span style="color:#666;font-size:12px;">{safe_srv}</span><span>{tech_html}</span></div>'
        html_content += '</div>'

    # ── Katana ──
    if katana_endpoints:
        sensitive_eps = [e for e in katana_endpoints if e.get("sensitive")]
        api_eps       = [e for e in katana_endpoints if e.get("api")]
        other_eps     = [e for e in katana_endpoints if not e.get("sensitive") and not e.get("api")]
        html_content += f"""
        <div class="category-section">
            <h2 style="color: var(--katana-sky);">🕸️ Crawled Endpoints (katana) — {len(katana_endpoints)} total</h2>"""
        if sensitive_eps:
            html_content += f'<div style="margin-bottom:12px;"><strong style="color:#888;">Sensitive Files ({len(sensitive_eps)}):</strong><br>'
            for e in sensitive_eps[:50]:
                su = html.escape(e["url"])
                html_content += f'<div class="dork-item" style="margin:3px 0;"><a href="{su}" target="_blank" class="dork-text" style="color:var(--shodan-red);">{su}</a><button class="copy-btn" onclick="copyToClipboard('{su}')">COPY</button></div>'
            html_content += '</div>'
        if api_eps:
            html_content += f'<div style="margin-bottom:12px;"><strong style="color:#888;">API Endpoints ({len(api_eps)}):</strong><br>'
            for e in api_eps[:50]:
                su = html.escape(e["url"])
                html_content += f'<div class="dork-item" style="margin:3px 0;"><a href="{su}" target="_blank" class="dork-text" style="color:var(--katana-sky);">{su}</a><button class="copy-btn" onclick="copyToClipboard('{su}')">COPY</button></div>'
            html_content += '</div>'
        if other_eps:
            html_content += f'<div><strong style="color:#888;">Other Endpoints ({len(other_eps)}):</strong><br>'
            for e in other_eps[:100]:
                su = html.escape(e["url"])
                html_content += f'<div class="dork-item" style="margin:3px 0;"><a href="{su}" target="_blank" class="dork-text">{su}</a><button class="copy-btn" onclick="copyToClipboard('{su}')">COPY</button></div>'
            html_content += '</div>'
        html_content += '</div>'

    # ── Nuclei ──
    if nuclei_findings:
        crit_count = sum(1 for f in nuclei_findings if f["severity"] == "critical")
        high_count = sum(1 for f in nuclei_findings if f["severity"] == "high")
        html_content += f"""
        <div class="category-section">
            <h2 style="color: var(--nuclei-crit);">💀 Nuclei Findings — {len(nuclei_findings)} total ({crit_count} critical, {high_count} high)</h2>"""
        border_colors = {"critical":"var(--nuclei-crit)","high":"var(--nuclei-high)","medium":"var(--nuclei-med)","low":"var(--nuclei-low)"}
        for finding in nuclei_findings[:300]:
            sev    = finding.get("severity", "info")
            name   = html.escape(finding.get("name", ""))
            tmpl   = html.escape(finding.get("template", ""))
            furl   = html.escape(finding.get("url", ""))
            desc   = html.escape(finding.get("description", "") or "")
            refs   = finding.get("reference", []) or []
            border = border_colors.get(sev, "#444")
            ref_html = " ".join(f'<a href="{html.escape(r)}" target="_blank" style="color:#555;font-size:11px;">[ref]</a>' for r in refs[:3])
            desc_html = f'<div style="color:#666;font-size:12px;margin-top:4px;">{desc}</div>' if desc else ''
            html_content += f'<div class="finding-item" style="border-left-color:{border};"><div><span class="sev-badge sev-{sev}">{sev}</span><strong style="color:#ddd;">{name}</strong><span style="color:#555;font-size:12px;margin-left:8px;">[{tmpl}]</span> {ref_html}</div><div style="margin-top:4px;"><a href="{furl}" target="_blank" style="color:{border};font-size:13px;">{furl}</a></div>{desc_html}</div>'
        html_content += '</div>'

    # ── Shodan ──
    if open_ports or vulns:
        html_content += f"""
        <div class="category-section">
            <h2 style="color: var(--shodan-red);">🛑 Shodan Intel (IP: {target_ip})</h2>
            <div class="dork-list">"""
        if open_ports:
            ports_str = ", ".join(map(str, open_ports))
            html_content += f"""
                <div class="dork-item" style="display: block;">
                    <span class="dork-text" style="color: #fff; text-decoration: none; cursor: default; white-space: normal; word-wrap: break-word; line-height: 1.5;"><strong>Open Ports:</strong> {ports_str}</span>
                </div>"""
        if vulns:
            vulns_str = ", ".join(vulns)
            html_content += f"""
                <div class="dork-item" style="display: block;">
                    <span class="dork-text" style="color: var(--shodan-red); text-decoration: none; cursor: default; white-space: normal; word-wrap: break-word; line-height: 1.5;"><strong>CVEs Found:</strong> {vulns_str}</span>
                </div>"""
        html_content += "</div></div>"

    # ── Wayback ──
    if discovered_wayback_urls:
        html_content += f"""
        <div class="category-section">
            <h2 style="color: var(--wayback-yellow);">🕰️ Archived Sensitive Files (Wayback Machine)</h2>
            <div class="dork-list">"""
        for w_url in discovered_wayback_urls:
            safe_w_url = html.escape(w_url)
            html_content += f"""
                <div class="dork-item">
                    <a href="{safe_w_url}" target="_blank" class="dork-text wayback-link">{safe_w_url}</a>
                    <button class="copy-btn" data-dork="{safe_w_url}" onclick="copyToClipboard(this.getAttribute('data-dork'))">COPY</button>
                </div>"""
        html_content += "</div></div>"

    # ── Dorks ──
    for category, queries in dork_map.items():
        html_content += f"""
        <div class="category-section">
            <h2>{category}</h2>
            <div class="dork-list">"""
        for q in queries:
            encoded_q = urllib.parse.quote_plus(q) 
            url = f"https://www.google.com/search?q={encoded_q}"
            safe_q = html.escape(q).replace('"', '&quot;')
            html_content += f"""
                <div class="dork-item">
                    <a href="{url}" target="_blank" class="dork-text">{html.escape(q)}</a>
                    <button class="copy-btn" data-dork="{safe_q}" onclick="copyToClipboard(this.getAttribute('data-dork'))">COPY</button>
                </div>"""
        html_content += "</div></div>"

    html_content += """
            </div>
            <div id="copyAlert" class="alert">COPIED TO CLIPBOARD</div>
        </div>

        <script>
            document.getElementById('searchInput').addEventListener('keyup', function() {
                let filter = this.value.toUpperCase();
                let sections = document.getElementsByClassName('category-section');
                for (let i = 0; i < sections.length; i++) {
                    let items = sections[i].getElementsByClassName('dork-item');
                    let sectionHasMatch = false;
                    for (let j = 0; j < items.length; j++) {
                        let text = items[j].getElementsByClassName('dork-text')[0];
                        if (text.innerHTML.toUpperCase().indexOf(filter) > -1) {
                            items[j].style.display = "flex";
                            sectionHasMatch = true;
                        } else {
                            items[j].style.display = "none";
                        }
                    }
                    sections[i].style.display = sectionHasMatch ? "" : "none";
                }
            });

            function copyToClipboard(text) {
                if (navigator.clipboard) {
                    navigator.clipboard.writeText(text).then(() => {
                        showAlert();
                    }).catch(err => {
                        console.error('Failed to copy: ', err);
                    });
                } else {
                    const el = document.createElement('textarea');
                    el.value = text;
                    document.body.appendChild(el);
                    el.select();
                    document.execCommand('copy');
                    document.body.removeChild(el);
                    showAlert();
                }
            }

            function showAlert() {
                const alert = document.getElementById('copyAlert');
                alert.style.display = 'block';
                setTimeout(() => { alert.style.display = 'none'; }, 1500);
            }
        </script>
    </body>
    </html>
    """

    filename = f"ghost_dorks_{target.replace('.', '_')}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)

    json_filename = f"ghost_dorks_{target.replace('.', '_')}.json"
    summary = {
        "target": target,
        "target_ip": target_ip,
        "subdomains": all_subdomains,
        "resolved_hosts": resolved_hosts,
        "takeover_candidates": takeover_candidates,
        "subjack_results": subjack_results,
        "wayback_urls": discovered_wayback_urls,
        "open_ports": open_ports,
        "cves": vulns,
        "emails": harvest_data.get("emails", []),
        "harvested_hosts": harvest_data.get("hosts", []),
        "co_hosted_domains": co_hosted_domains,
        "naabu_ports": naabu_results,
        "http_hosts": http_hosts,
        "katana_endpoints": katana_endpoints,
        "gf_results": gf_results,
        "arjun_results": arjun_results,
        "nuclei_findings": nuclei_findings,
        "cpanel_recon": cpanel_data,
        "whois": whois_info,
        "dns": dns_records,
        "dorks": dork_map,
        "generated_at": datetime.now().isoformat()
    }
    with open(json_filename, "w", encoding="utf-8") as jf:
        json.dump(summary, jf, indent=2)

    print(f"\n[+] Ghost Dashboard Generated : {filename}")
    print(f"[+] JSON Summary Saved        : {json_filename}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PROJECT GHOST ENGINE v4.0 — Unified OSINT & cPanel/WHM Reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Passive recon only:
    python ghostdorks.py -d example.com

  With active scanning:
    python ghostdorks.py -d example.com --active

  Full nuclear mode + all new modules:
    python ghostdorks.py -d example.com --active --nuclei --cpanel-probe --gf --arjun --subjack

  Stealth mode with new tools:
    python ghostdorks.py -d example.com --gf --subjack --rate 300

  Throttle active tools:
    python ghostdorks.py -d example.com --active --rate 300
"""
    )
    parser.add_argument("-d", "--domain", help="Target domain (e.g., example.com)", required=True)
    parser.add_argument("--active", action="store_true",
        help="Enable active scanning: naabu + httpx + katana. Sends packets directly to target.")
    parser.add_argument("--nuclei", action="store_true",
        help="Enable nuclei vulnerability scanning. Requires --active or will auto-run httpx first.")
    parser.add_argument("--cpanel-probe", action="store_true",
        help="Enable active CVE-2026-41940 probe against WHM /json-api/version endpoint. "
             "Only use with explicit authorization.")
    parser.add_argument("--gf", action="store_true",
        help="Enable gf pattern matching on katana endpoints and wayback URLs.")
    parser.add_argument("--arjun", action="store_true",
        help="Enable arjun hidden parameter discovery on live HTTP hosts.")
    parser.add_argument("--subjack", action="store_true",
        help="Enable subjack subdomain takeover scanning on all discovered subdomains.")
    parser.add_argument("--rate", type=int, default=1000, metavar="N",
        help="Rate limit for active tools. Default: 1000. Lower for stealth (e.g. 300).")
    args = parser.parse_args()

    domain = args.domain.strip()
    if domain:
        generate_ghost_dashboard(domain, cfg={
            "active":  args.active,
            "nuclei":  args.nuclei,
            "rate":    args.rate,
            "cpanel_probe": args.cpanel_probe,
            "gf": args.gf,
            "arjun": args.arjun,
            "subjack": args.subjack,
        })
    else:
        print("[!] Domain cannot be empty.")
