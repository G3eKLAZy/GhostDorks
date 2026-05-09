import os
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

# Modern browser headers to bypass basic anti-bot protections/WAFs
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive"
}

def fetch_subdomains(domain):
    """
    Passively fetches subdomains using a triple-redundant fallback system:
    1. crt.sh -> 2. AlienVault OTX -> 3. HackerTarget
    """
    subdomains = set()
    timeout_limit = 45 # Increased timeout to 45 seconds for slow APIs

    # --- ATTEMPT 1: crt.sh ---
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

    # --- ATTEMPT 2: AlienVault OTX (Fallback) ---
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

    # --- ATTEMPT 3: HackerTarget (Fallback) ---
    if not subdomains:
        print(f"[*] Falling back to HackerTarget for host search...")
        url_ht = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            response = requests.get(url_ht, headers=HEADERS, timeout=timeout_limit)
            if response.status_code == 200:
                # HackerTarget returns API errors as plain text sometimes, we need to filter that out
                if "error" not in response.text.lower() and "exceeded" not in response.text.lower():
                    lines = response.text.split('\n')
                    for line in lines:
                        # Returns data like: sub.domain.com,1.2.3.4
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
    """
    Passively fetches WHOIS data for the target domain using the system 'whois' command.
    Parses registrar, dates, organization, country, and nameservers.
    """
    print(f"[*] Running WHOIS lookup for {domain}...")
    whois_data = {
        "registrar": "N/A",
        "creation_date": "N/A",
        "expiry_date": "N/A",
        "updated_date": "N/A",
        "organization": "N/A",
        "country": "N/A",
        "name_servers": [],
        "registrant_email": "N/A",
        "dnssec": "N/A",
        "raw": ""
    }
    
    if not shutil.which("whois"):
        print("[-] 'whois' command not found. Skipping WHOIS module.")
        return whois_data
    
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=30
        )
        raw_output = result.stdout
        whois_data["raw"] = raw_output
        
        # Parse key fields (case-insensitive, handles various WHOIS formats)
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
        
        # Parse nameservers (multiple lines)
        ns_matches = re.findall(r"(?:Name Server|nserver|nameserver)\s*:\s*(.+)", raw_output, re.IGNORECASE)
        if ns_matches:
            whois_data["name_servers"] = list(set([ns.strip().lower() for ns in ns_matches]))
        
        ns_count = len(whois_data['name_servers'])
        print(f"[+] WHOIS data retrieved. Registrar: {whois_data['registrar']}, Nameservers: {ns_count}")
        
    except subprocess.TimeoutExpired:
        print("[-] WHOIS lookup timed out.")
    except KeyboardInterrupt:
        print("\n[!] User interrupted WHOIS lookup (Ctrl+C).")
    except Exception as e:
        print(f"[-] Error running WHOIS: {e}")
    
    return whois_data

def fetch_dns_records(domain):
    """
    Fetches DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME) using 'dig'.
    Also analyzes SPF, DKIM, and DMARC policies from TXT records.
    """
    print(f"[*] Querying DNS records for {domain}...")
    dns_data = {
        "A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [],
        "SOA": [], "CNAME": [],
        "spf": None, "dmarc": None, "dkim": None,
        "security_notes": []
    }
    
    if not shutil.which("dig"):
        print("[-] 'dig' command not found. Skipping DNS module.")
        return dns_data
    
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    
    for rtype in record_types:
        try:
            result = subprocess.run(
                ["dig", "+short", domain, rtype],
                capture_output=True, text=True, timeout=15
            )
            lines = [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]
            dns_data[rtype] = lines
        except subprocess.TimeoutExpired:
            print(f"[-] DNS query for {rtype} records timed out.")
        except Exception as e:
            print(f"[-] Error querying {rtype} records: {e}")
    
    # Analyze SPF, DMARC, DKIM from TXT records
    for txt_record in dns_data["TXT"]:
        if "v=spf1" in txt_record.lower():
            dns_data["spf"] = txt_record
    
    # Check DMARC via _dmarc subdomain
    try:
        result = subprocess.run(
            ["dig", "+short", f"_dmarc.{domain}", "TXT"],
            capture_output=True, text=True, timeout=15
        )
        dmarc_out = result.stdout.strip()
        if dmarc_out:
            dns_data["dmarc"] = dmarc_out
    except Exception:
        pass
    
    # Security analysis
    if not dns_data["spf"]:
        dns_data["security_notes"].append("⚠️ No SPF record found — domain is vulnerable to email spoofing")
    elif "+all" in (dns_data["spf"] or ""):
        dns_data["security_notes"].append("⚠️ SPF uses +all (permissive) — effectively no protection")
    
    if not dns_data["dmarc"]:
        dns_data["security_notes"].append("⚠️ No DMARC record found — phishing risk")
    elif "p=none" in (dns_data["dmarc"] or "").lower():
        dns_data["security_notes"].append("⚠️ DMARC policy is 'none' — monitoring only, no enforcement")
    
    total = sum(len(v) for k, v in dns_data.items() if k in record_types)
    print(f"[+] DNS enumeration complete. {total} total records found.")
    if dns_data["security_notes"]:
        for note in dns_data["security_notes"]:
            print(f"    {note}")
    
    return dns_data

def fetch_emails_theharvester(domain):
    """
    Uses theHarvester to passively collect email addresses, hosts, and IPs
    from search engines and public data sources.
    """
    print(f"[*] Running theHarvester for email/host enumeration on {domain}...")
    harvest_data = {
        "emails": [],
        "hosts": [],
        "ips": []
    }
    
    if not shutil.which("theHarvester"):
        print("[-] 'theHarvester' command not found. Skipping email harvesting module.")
        return harvest_data
    
    # Use a temp file for JSON output
    tmp_dir = tempfile.mkdtemp(prefix="ghostdorks_")
    output_base = os.path.join(tmp_dir, "harvest")
    
    try:
        result = subprocess.run(
            ["theHarvester", "-d", domain, "-b", "anubis,crtsh,dnsdumpster,duckduckgo,hackertarget,rapiddns,urlscan",
             "-l", "200", "-f", output_base],
            capture_output=True, text=True, timeout=120
        )
        
        # theHarvester saves to <output_base>.json
        json_path = output_base + ".json"
        if os.path.exists(json_path):
            with open(json_path, 'r') as f:
                data = json.load(f)
            
            harvest_data["emails"] = sorted(set(data.get("emails", [])))
            harvest_data["hosts"] = sorted(set(data.get("hosts", [])))
            harvest_data["ips"] = sorted(set(data.get("ips", [])))
            
            print(f"[+] theHarvester found: {len(harvest_data['emails'])} emails, "
                  f"{len(harvest_data['hosts'])} hosts, {len(harvest_data['ips'])} IPs")
        else:
            # Fallback: parse stdout for emails
            print("[-] theHarvester JSON output not found, parsing stdout...")
            email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
            found_emails = email_pattern.findall(result.stdout)
            harvest_data["emails"] = sorted(set(found_emails))
            if harvest_data["emails"]:
                print(f"[+] Parsed {len(harvest_data['emails'])} emails from stdout.")
            else:
                print("[-] No emails found.")
    
    except subprocess.TimeoutExpired:
        print("[-] theHarvester timed out after 120 seconds.")
    except KeyboardInterrupt:
        print("\n[!] User interrupted theHarvester (Ctrl+C). Skipping...")
    except Exception as e:
        print(f"[-] Error running theHarvester: {e}")
    finally:
        # Clean up temp files
        try:
            import shutil as sh
            sh.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass
    
    return harvest_data

def fetch_reverse_ip(ip_address):
    """
    Performs a reverse IP lookup to find other domains hosted on the same IP.
    Uses the HackerTarget API (same API already in use for subdomains).
    """
    print(f"[*] Running reverse IP lookup for {ip_address}...")
    co_hosted = []
    
    if not ip_address:
        return co_hosted
    
    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip_address}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=30)
        if response.status_code == 200:
            if "error" not in response.text.lower() and "api count" not in response.text.lower():
                lines = response.text.strip().split('\n')
                co_hosted = sorted(set([l.strip().lower() for l in lines if l.strip() and l.strip() != "No records found"]))
                if co_hosted:
                    print(f"[+] Found {len(co_hosted)} domains co-hosted on {ip_address}.")
                else:
                    print(f"[-] No co-hosted domains found.")
            else:
                print(f"[-] HackerTarget API limit reached for reverse IP lookup.")
        else:
            print(f"[-] Reverse IP lookup returned status code: {response.status_code}")
    except requests.exceptions.Timeout:
        print("[-] Reverse IP lookup timed out.")
    except KeyboardInterrupt:
        print("\n[!] User interrupted reverse IP lookup (Ctrl+C).")
    except Exception as e:
        print(f"[-] Error during reverse IP lookup: {e}")
    
    return co_hosted

def fetch_wayback_urls(domain):
    """
    Queries the Wayback Machine CDX API for highly sensitive archived files.
    """
    print(f"[*] Querying Wayback Machine for exposed files on {domain}...")
    extensions = "(env|sql|bak|db|config|pem|rsa|ini|json|log|yml|yaml|txt)"
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey&filter=original:.*\\.{extensions}$"
    
    juicy_urls = set()
    try:
        # Increased to 45 seconds
        response = requests.get(url, headers=HEADERS, timeout=45)
        if response.status_code == 200:
            lines = response.text.split('\n')
            for line in lines:
                line = line.strip()
                if line:
                    juicy_urls.add(line)
                    # Cap at 500 to prevent the HTML dashboard from crashing
                    if len(juicy_urls) >= 500:
                        print("[!] Reached maximum limit of 500 Wayback URLs. Truncating.")
                        break
            if juicy_urls:
                print(f"[+] Successfully extracted {len(juicy_urls)} archived URLs from Wayback Machine.")
        else:
            print(f"[-] Wayback Machine returned a non-200 status code: {response.status_code}")
    except requests.exceptions.Timeout:
        print("[-] Wayback Machine query timed out. Skipping.")
    except KeyboardInterrupt:
        print("\n[!] User interrupted Wayback Machine scan (Ctrl+C). Skipping this module...")
    except Exception as e:
        print(f"[-] Error querying Wayback Machine: {e}")
        
    return sorted(list(juicy_urls))

def fetch_open_ports(ip_address):
    """
    Passively checks a target IP for open ports and vulnerabilities 
    using the free Shodan InternetDB API.
    """
    print(f"[*] Querying Shodan InternetDB for ports on {ip_address}...")
    url = f"https://internetdb.shodan.io/{ip_address}"
    
    ports = []
    cves = []
    
    try:
        # We use the exact same resilient request structure
        response = requests.get(url, headers=HEADERS, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            ports = data.get('ports', [])
            cves = data.get('vulns', []) # Grabs known CVEs if Shodan has them!
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

def generate_ghost_dashboard(target):
    safe_target = html.escape(target)
    
    # 1. Passive Data Fetching (Subdomains & Wayback)
    discovered_subdomains = fetch_subdomains(target)
    discovered_wayback_urls = fetch_wayback_urls(target)
    
    # 2. Shodan Open Ports Scan
    target_ip = ""
    open_ports = []
    vulns = []
    try:
        target_ip = socket.gethostbyname(target)
        open_ports, vulns = fetch_open_ports(target_ip)
    except socket.gaierror:
        print(f"[-] Could not resolve IP address for {target}. Skipping Shodan scan.")
    
    # 3. NEW: WHOIS Intelligence
    whois_info = fetch_whois_info(target)
    
    # 4. NEW: DNS Record Map
    dns_records = fetch_dns_records(target)
    
    # 5. NEW: Email Harvesting via theHarvester
    harvest_data = fetch_emails_theharvester(target)
    
    # 6. NEW: Reverse IP Lookup
    co_hosted_domains = []
    if target_ip:
        co_hosted_domains = fetch_reverse_ip(target_ip)

    # 3. Base Google Dork Map
    dork_map = {
        "🐱 Subdomain Enum": [
            f"site:*.{target}", f"site:*.{target} -www", f"\"@{target}\" -site:www.{target} -site:{target}",
            f"intitle:\"index of\" \"parent directory\" site:{target}", f"inurl:dmarc:domain={target}",
            f"ext:txt {target} (vhost OR hostname OR nameserver)", f"filetype:env {target}",
            f"inurl:(admin | login | panel) site:*.{target}", f"site:*.{target} inurl:api",
            f"site:{target} inurl:staging", f"site:{target} inurl:dev", f"site:{target} inurl:test",
            f"site:*.{target} inurl:*.api", f"site:{target} inurl:mail", f"site:{target} inurl:ftp",
            f"site:{target} inurl:cdn", f"allintitle:\"index of/admin\"", f"allintitle:\"index of/root\"",
            f"allintitle:restricted filetype:mail", f"site:{target} inurl:vpn"
        ],
        "📁 Directory/File": [
            f"intitle:\"index of\" site:{target}", f"intitle:\"index of /backup\"", f"intitle:\"index of /admin\"",
            f"inurl:/db_backup OR inurl:/database_backup site:{target}", f"ext:sql | ext:dbf | ext:mdb | ext:ora site:{target}",
            f"filetype:log site:{target}", f"inurl:wp-config.php site:{target}", f"inurl:/.env site:{target}",
            f"intitle:\"index of\" +passwd site:{target}", f"intitle:\"index of\" +git site:{target}",
            f"intitle:\"index of\" +config site:{target}", f"inurl:sitemap.xml site:{target}", f"inurl:robots.txt site:{target}"
        ],
        "🔑 Secrets & Configs": [
            f"ext:env | ext:.env site:{target}", f"intext:\"DB_PASSWORD\" site:{target}",
            f"intext:\"AWS_ACCESS_KEY_ID\" site:{target}", f"filetype:json \"api_key\" site:{target}",
            f"inurl:.git/config site:{target}", f"intext:\"DATABASE_URL\" site:{target}",
            f"intext:\"SLACK_BOT_TOKEN\" site:{target}", f"ext:key site:{target}", f"ext:pem site:{target}",
            f"intext:\"BEGIN RSA PRIVATE\" site:{target}", f"filetype:pfx site:{target}"
        ],
        "⚠️ Admin Panels": [
            f"inurl:admin/login.php site:{target}", f"inurl:wp-login.php site:{target}",
            f"intitle:\"admin panel\" | intitle:\"control panel\" site:{target}", f"intitle:\"phpMyAdmin\" site:{target}",
            f"inurl:cpanel site:{target}", f"intitle:\"Jenkins\" site:{target}", f"intitle:\"Citrix\" site:{target}"
        ],
        "💥 Vulnerable Files": [
            f"intitle:\"phpinfo()\" site:{target}", f"inurl:/vendor/ site:{target}",
            f"intext:\"sql syntax error\" site:{target}", f"intext:\"Warning: include\" site:{target}",
            f"inurl:phpshell site:{target}", f"inurl:webshell site:{target}", f"inurl:backdoor site:{target}"
        ],
        "🔌 APIs & Swagger": [
            f"inurl:api/ | inurl:rest/ | inurl:v1/ site:{target}", f"inurl:swagger | inurl:redoc site:{target}",
            f"site:*.{target} (inurl:swagger OR inurl:api-docs)", f"inurl:graphql site:{target}",
            f"inurl:openapi.json site:{target}"
        ],
        "🚨 Error & Debug": [
            f"intext:\"Warning: mysql\" site:{target}", f"intext:\"Stack trace\" site:{target}",
            f"intext:\"Fatal error\" site:{target}", f"intext:\"syntax error\" site:{target}",
            f"intext:\"Connection refused\" site:{target}", f"intext:\"403 Forbidden\" site:{target}"
        ],
        "📄 Documents": [
            f"filetype:pdf site:{target}", f"filetype:doc | filetype:docx site:{target}",
            f"filetype:xls | filetype:xlsx site:{target}", f"intext:\"confidential\" site:{target}",
            f"intext:\"internal use only\" site:{target}", f"site:{target} \"employee handbook\" filetype:pdf"
        ],
        "🕳️ Leaks": [
            f"site:pastebin.com \"{target}\"", f"site:github.com \"{target}\" intext:\"password\"",
            f"site:*.stackexchange.com {target} password", f"site:gist.github.com {target}"
        ],
        "🔗 Takeover": [
            f"inurl:herokuapp.com site:{target}", f"inurl:*.cloudfront.net site:{target}",
            f"inurl:github.io {target}", f"inurl:s3.amazonaws.com {target}"
        ],
        "☁️ Cloud": [
            f"site:s3.amazonaws.com \"{target}\"", f"site:storage.googleapis.com {target}",
            f"site:blob.core.windows.net {target}", f"inurl:bucket site:{target}"
        ],
        "🏗️ Dev/Test": [
            f"site:{target} inurl:staging", f"site:{target} inurl:dev", f"site:{target} inurl:test",
            f"site:{target} inurl:sandbox", f"site:{target} inurl:localhost"
        ],
        "💼 Social": [
            f"site:linkedin.com/in/ \"{target}\"", f"site:linkedin.com \"{target}\" (engineer OR admin)",
            f"site:twitter.com {target}", f"\"@{target}\" site:twitter.com"
        ]
    }

    # 4. Dynamically append passive subdomains findings to the Dork Map
    if discovered_subdomains:
        sub_dorks = [f"site:{sub}" for sub in discovered_subdomains]
        new_dork_map = {"🌐 Discovered Subdomains (Passive OSINT)": sub_dorks}
        new_dork_map.update(dork_map)
        dork_map = new_dork_map

    # 5. Generate HTML Framework
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>GhostDorks - {safe_target}</title>
        <style>
            :root {{ --main-green: #00ff41; --bg-black: #0d0d0d; --card-bg: #1a1a1a; --blue: #00ccff; --wayback-yellow: #ffb800; --shodan-red: #ff3333; --whois-cyan: #00e5ff; --dns-purple: #b388ff; --harvest-orange: #ff9100; --reverse-teal: #1de9b6; }}
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
            
            .dork-list {{ display: grid; grid-template-columns: 1fr; gap: 8px; }}
            .dork-item {{ background: #111; padding: 10px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; border: 1px solid #222; transition: 0.2s; }}
            .dork-item:hover {{ border-color: #444; background: #151515; }}
            
            .dork-text {{ color: var(--blue); text-decoration: none; font-size: 14px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex-grow: 1; margin-right: 15px; }}
            .dork-text:hover {{ text-decoration: underline; color: #fff; }}
            
            .wayback-link {{ color: var(--wayback-yellow); }}
            
            .copy-btn {{ font-size: 11px; padding: 6px 12px; border: 1px solid #444; color: #888; background: #222; cursor: pointer; font-weight: bold; transition: 0.2s; }}
            .copy-btn:hover {{ color: #000; background: var(--main-green); border-color: var(--main-green); }}

            .alert {{ position: fixed; bottom: 20px; right: 20px; background: var(--main-green); color: black; padding: 10px 20px; display: none; font-weight: bold; z-index: 1000; box-shadow: 0 0 10px var(--main-green); }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>🕵️ PROJECT GHOST ENGINE</h1>
                <h3>   created by: L4ZYG33K</h3>
                <p>Target: <strong style="color: #fff;">{safe_target}</strong> {f"({target_ip})" if target_ip else ""}</p>
                <div class="stats">
                    Passive Subdomains Discovered: <strong style="color: var(--main-green);">{len(discovered_subdomains)}</strong> |
                    Wayback Juicy Files: <strong style="color: var(--wayback-yellow);">{len(discovered_wayback_urls)}</strong> |
                    Open Ports: <strong style="color: var(--shodan-red);">{len(open_ports)}</strong> |
                    CVEs: <strong style="color: var(--shodan-red);">{len(vulns)}</strong><br>
                    Emails Harvested: <strong style="color: var(--harvest-orange);">{len(harvest_data['emails'])}</strong> |
                    DNS Records: <strong style="color: var(--dns-purple);">{sum(len(v) for k, v in dns_records.items() if k in ['A','AAAA','MX','NS','TXT','SOA','CNAME'])}</strong> |
                    Co-Hosted Domains: <strong style="color: var(--reverse-teal);">{len(co_hosted_domains)}</strong>
                </div>
            </header>

            <div class="controls">
                <input type="text" class="search-box" id="searchInput" placeholder="Filter by keyword (e.g. 'sql', 'env', 'login')...">
                <button class="btn" onclick="window.print()">Export PDF</button>
            </div>

            <div id="dorkContainer">
    """

    # --- INJECT NEW MODULE SECTIONS ---

    # NEW: WHOIS Intelligence Section
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

    # NEW: DNS Record Map Section
    dns_record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    has_dns = any(dns_records.get(rt) for rt in dns_record_types)
    if has_dns:
        html_content += f"""
        <div class="category-section">
            <h2 style="color: var(--dns-purple);">🧬 DNS Record Map</h2>"""
        
        # Security notes first
        if dns_records.get("security_notes"):
            for note in dns_records["security_notes"]:
                html_content += f'<div class="security-note">{html.escape(note)}</div>'
        
        html_content += '<table class="intel-table">'
        for rt in dns_record_types:
            records = dns_records.get(rt, [])
            if records:
                records_html = "<br>".join([html.escape(r) for r in records])
                html_content += f'<tr><td style="color: var(--dns-purple);">{rt}</td><td>{records_html}</td></tr>'
        
        # SPF / DMARC summary
        if dns_records.get("spf"):
            html_content += f'<tr><td style="color: var(--main-green);">SPF</td><td>{html.escape(dns_records["spf"])}</td></tr>'
        if dns_records.get("dmarc"):
            html_content += f'<tr><td style="color: var(--main-green);">DMARC</td><td>{html.escape(dns_records["dmarc"])}</td></tr>'
        
        html_content += '</table></div>'

    # NEW: Email Harvesting Section
    if harvest_data.get("emails") or harvest_data.get("hosts"):
        html_content += f"""
        <div class="category-section">
            <h2 style="color: var(--harvest-orange);">📧 Harvested Emails & Hosts (theHarvester)</h2>
            <div style="margin-bottom: 15px;">"""
        
        if harvest_data.get("emails"):
            html_content += '<div style="margin-bottom: 10px;"><strong style="color: #888;">Emails:</strong><br>'
            for email in harvest_data["emails"]:
                safe_email = html.escape(email)
                html_content += f'<span class="email-chip">{safe_email}</span>'
            html_content += '</div>'
        
        if harvest_data.get("hosts"):
            html_content += '<div style="margin-bottom: 10px;"><strong style="color: #888;">Discovered Hosts:</strong><br>'
            for h in harvest_data["hosts"][:100]:  # Cap at 100
                safe_h = html.escape(h)
                html_content += f'<span class="host-chip">{safe_h}</span>'
            html_content += '</div>'
        
        if harvest_data.get("ips"):
            html_content += '<div><strong style="color: #888;">Associated IPs:</strong><br>'
            for ip in harvest_data["ips"][:50]:  # Cap at 50
                safe_ip = html.escape(ip)
                html_content += f'<span class="dns-badge" style="border-color: var(--harvest-orange); color: var(--harvest-orange);">{safe_ip}</span>'
            html_content += '</div>'
        
        html_content += '</div></div>'

    # NEW: Reverse IP / Co-Hosted Domains Section
    if co_hosted_domains:
        html_content += f"""
        <div class="category-section">
            <h2 style="color: var(--reverse-teal);">🗺️ Co-Hosted Domains (Reverse IP: {target_ip})</h2>
            <div class="dork-list">"""
        for co_domain in co_hosted_domains[:200]:  # Cap at 200
            safe_co = html.escape(co_domain)
            google_url = f"https://www.google.com/search?q=site:{urllib.parse.quote_plus(co_domain)}"
            html_content += f"""
                <div class="dork-item">
                    <a href="{google_url}" target="_blank" class="dork-text" style="color: var(--reverse-teal);">{safe_co}</a>
                    <button class="copy-btn" data-dork="{safe_co}" onclick="copyToClipboard(this.getAttribute('data-dork'))">COPY</button>
                </div>"""
        html_content += '</div></div>'

    # 6. Inject Shodan Intel Section (FIXED WITH CSS OVERRIDE FOR WRAPPING)
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

    # 7. Inject Wayback Machine Direct Links Section
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

    # 8. Inject Standard Google Dork Sections
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
    print(f"\n[+] Ghost Dashboard Generated: {filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate an interactive OSINT HTML dashboard with passive scanning fallback.")
    parser.add_argument("-d", "--domain", help="Target domain (e.g., example.com)", required=True)
    args = parser.parse_args()

    domain = args.domain.strip()
    if domain:
        generate_ghost_dashboard(domain)
    else:
        print("[!] Domain cannot be empty.")
