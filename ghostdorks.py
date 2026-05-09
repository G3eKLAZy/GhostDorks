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
        print("[-] WHOIS query timed out.")
    except KeyboardInterrupt:
        print("\n[!] User interrupted WHOIS query (Ctrl+C). Skipping...")
    except Exception as e:
        print(f"[-] Error running WHOIS: {e}")
        
    return whois_data


# ─────────────────────────────────────────────
# ProjectDiscovery Pipeline Modules
# ─────────────────────────────────────────────


def fetch_wayback_urls(domain):
    print(f"[*] Querying Wayback Machine for exposed files on {domain}...")
    urls = []
    # Using CDX API to find juicy files (.env, .sql, .bak, .config, .json, .zip, etc.)
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

    # Basic Regex filter for sensitive extensions
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
            result = subprocess.run(
                ["dig", "+short", rtype, domain],
                capture_output=True, text=True, timeout=10
            )
            lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            dns_data[rtype] = lines
        except Exception:
            continue
            
    # Simple Security Checks on DNS
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
    """
    Runs subfinder to passively enumerate subdomains from 40+ OSINT sources.
    Merges results with the existing subdomain list.
    Passivity: 100% passive — queries third-party APIs only.
    """
    print(f"[*] Running subfinder for passive subdomain enumeration on {domain}...")
    results = []
    if not shutil.which("subfinder"):
        print("[-] 'subfinder' not found. Skipping.")
        return results
    try:
        proc = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-all"],
            capture_output=True, text=True, timeout=120
        )
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
    """
    Validates and resolves a list of subdomains using dnsx.
    Filters dead entries and detects CNAME takeover candidates.
    Passivity: 100% passive — standard public DNS queries only.
    """
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
        proc = subprocess.run(
            ["dnsx", "-l", tmp.name, "-a", "-cname", "-resp", "-json", "-silent"],
            capture_output=True, text=True, timeout=180
        )
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
    """
    Runs naabu to fast-scan top 1000 ports on resolved hosts.
    ACTIVE — sends TCP SYN packets directly to target IPs.
    Only called when --active flag is set.
    """
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
        proc = subprocess.run(
            ["naabu", "-list", tmp.name, "-top-ports", "1000", "-rate", str(rate), "-json", "-silent"],
            capture_output=True, text=True, timeout=300
        )
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
    """
    Probes hosts for live HTTP/HTTPS services, grabbing title, status, server header, tech stack, and TLS info.
    ACTIVE — sends HTTP requests (looks like normal browser traffic).
    Only called when --active flag is set.
    """
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
            # Only send likely HTTP ports to httpx to prevent hanging on SSH/POP3
            valid_http_ports = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 8081, 9000}
            targets = list(set(f"{r['host']}:{r['port']}" for r in naabu_results if int(r['port']) in valid_http_ports))
        if not targets:
            # Fallback to standard ports if naabu found no HTTP ports
            targets = [h["host"] for h in resolved_hosts]

        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', prefix='ghostdorks_httpx_', delete=False)
        tmp.write('\n'.join(targets))
        tmp.close()
        proc = subprocess.run(
            ["httpx", "-l", tmp.name, "-status-code", "-title", "-server", "-tech-detect", "-follow-redirects", "-json", "-silent", "-threads", "50"],
            capture_output=True, text=True, timeout=300
        )
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
    """
    Crawls/spiders to discover endpoints, JS files, forms, API paths.
    passive=True uses Wayback+CommonCrawl (100% passive, default) against all resolved hosts.
    passive=False actively crawls the target (--active mode) against live HTTP hosts.
    """
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
            tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt',
                                              prefix='ghostdorks_katana_passive_', delete=False)
            tmp.write('\n'.join(targets))
            tmp.close()
            cmd = ["katana", "-list", tmp.name, "-ps", "-jsonl", "-silent"]
        else:
            targets = [h["url"] for h in (http_hosts or [])] or [f"https://{domain}"]
            tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt',
                                              prefix='ghostdorks_katana_active_', delete=False)
            tmp.write('\n'.join(targets))
            tmp.close()
            cmd = ["katana", "-list", tmp.name, "-d", "3",
                   "-jc", "-jsonl", "-silent", "-c", "20"]

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if tmp:
            try:
                os.unlink(tmp.name)
            except Exception:
                pass

        sensitive_ext = {'.env', '.sql', '.bak', '.json', '.xml', '.yaml',
                         '.yml', '.log', '.conf', '.config', '.key', '.pem'}
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
                endpoints.append({
                    "url": url,
                    "sensitive": is_sensitive,
                    "api": is_api,
                })
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
    """
    Runs nuclei vulnerability scanner against discovered HTTP hosts.
    Uses exposures/, misconfiguration/, takeovers/ templates by default.
    ACTIVE — sends crafted probes. Only call with --nuclei flag.
    """
    print(f"[*] Running nuclei vulnerability scan (rate={rate})...")
    findings = []
    if not http_hosts and not katana_endpoints:
        print("[-] No HTTP targets for nuclei. Skipping.")
        return findings
    if not shutil.which("nuclei"):
        print("[-] 'nuclei' not found. Skipping.")
        return findings

    # Build target list: prefer katana endpoints (more surface area)
    if katana_endpoints:
        targets = list(set(e["url"] for e in katana_endpoints))[:500]
    else:
        targets = [h["url"] for h in http_hosts]

    try:
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt',
                                          prefix='ghostdorks_nuclei_', delete=False)
        tmp.write('\n'.join(targets))
        tmp.close()
        proc = subprocess.run(
            ["nuclei", "-l", tmp.name,
             "-t", "exposures/", "-t", "misconfiguration/", "-t", "takeovers/",
             "-severity", "critical,high,medium,low",
             "-rate-limit", str(rate),
             "-json", "-silent", "-no-color"],
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
        print(f"[+] nuclei found {len(findings)} findings "
              f"({crit} critical, {high} high).")
    except subprocess.TimeoutExpired:
        print("[-] nuclei timed out after 600s.")
    except KeyboardInterrupt:
        print("\n[!] Interrupted nuclei (Ctrl+C).")
    except Exception as e:
        print(f"[-] nuclei error: {e}")
    return findings

def generate_ghost_dashboard(target, cfg=None):
    if cfg is None:
        cfg = {}
    active   = cfg.get("active", False)
    do_nuclei = cfg.get("nuclei", False)
    rate     = cfg.get("rate", 1000)
    safe_target = html.escape(target)

    print("\n" + "="*55)
    print("  🕵️  PROJECT GHOST ENGINE — Passive Pipeline")
    print("="*55)
    if active:
        print("  ⚠️  ACTIVE MODE enabled (naabu + httpx + katana)")
    if do_nuclei:
        print("  💀  NUCLEI enabled — vulnerability scanning active")
    print("="*55 + "\n")

    # ── Passive baseline (always runs) ────────────────────
    # 1. Subdomain enumeration
    discovered_subdomains = fetch_subdomains(target)

    # 2. Subfinder (passive, merges with above)
    sf_subs = run_subfinder(target)
    all_subdomains = sorted(set(discovered_subdomains) | set(sf_subs))
    if sf_subs:
        print(f"[+] Combined subdomain list: {len(all_subdomains)} unique entries.")
    else:
        all_subdomains = discovered_subdomains

    # 3. Dnsx — resolve & validate the merged list (always passive)
    resolved_hosts, takeover_candidates = run_dnsx(all_subdomains)

    # 4. Wayback Machine
    discovered_wayback_urls = fetch_wayback_urls(target)

    # 5. Shodan InternetDB (passive)
    target_ip = ""
    open_ports = []
    vulns = []
    try:
        target_ip = socket.gethostbyname(target)
        open_ports, vulns = fetch_open_ports(target_ip)
    except socket.gaierror:
        print(f"[-] Could not resolve IP address for {target}. Skipping Shodan scan.")

    # 6. WHOIS Intel (passive)
    whois_info = fetch_whois_info(target)

    # 7. DNS Record Map (passive)
    dns_records = fetch_dns_records(target)

    # 8. Email Harvesting (theHarvester, passive)
    harvest_data = fetch_emails_theharvester(target)

    # 9. Reverse IP Lookup (passive)
    co_hosted_domains = []
    if target_ip:
        co_hosted_domains = fetch_reverse_ip(target_ip)

    # 10. Katana passive mode — always runs (Wayback/CommonCrawl)
    katana_endpoints = run_katana(target, resolved_hosts=resolved_hosts, passive=True)

    # ── Active pipeline (--active flag required) ──────────
    naabu_results  = []
    http_hosts     = []
    nuclei_findings = []

    if active and resolved_hosts:
        # 11. Naabu port scan
        naabu_results = run_naabu(resolved_hosts, rate=rate)
        # 12. HTTPx probe
        http_hosts = run_httpx(resolved_hosts, naabu_results=naabu_results)
        # 13. Katana active crawl (overwrites passive endpoints)
        if http_hosts:
            katana_endpoints = run_katana(target, http_hosts=http_hosts, passive=False)

    # 14. Nuclei (--nuclei flag required — always needs httpx first)
    if do_nuclei:
        if not http_hosts and resolved_hosts:
            print("[*] --nuclei requires httpx; running httpx first...")
            http_hosts = run_httpx(resolved_hosts)
        nuclei_findings = run_nuclei(http_hosts, katana_endpoints=katana_endpoints, rate=150)

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
            :root {{ --main-green: #00ff41; --bg-black: #0d0d0d; --card-bg: #1a1a1a; --blue: #00ccff; --wayback-yellow: #ffb800; --shodan-red: #ff3333; --whois-cyan: #00e5ff; --dns-purple: #b388ff; --harvest-orange: #ff9100; --reverse-teal: #1de9b6; --dnsx-lime: #c6ff00; --httpx-pink: #ff4081; --katana-sky: #40c4ff; --nuclei-crit: #ff1744; --nuclei-high: #ff6d00; --nuclei-med: #ffd600; --nuclei-low: #69f0ae; }}
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
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>🕵️ PROJECT GHOST ENGINE</h1>
                <h3>   created by: L4ZYG33K</h3>
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


    # NEW: Dnsx — Resolved Hosts & Takeover Candidates
    if resolved_hosts or takeover_candidates:
        html_content += f"""
        <div class="category-section">
            <h2 style="color: var(--dnsx-lime);">&#x1F9EC; Live Resolved Hosts (dnsx) &mdash; {len(resolved_hosts)} live</h2>"""
        if takeover_candidates:
            for tc in takeover_candidates:
                safe_h = html.escape(tc['host'])
                safe_c = html.escape(', '.join(tc.get('cname', [])))
                html_content += f'<div class="security-note">&#x26A0; Takeover Candidate: <strong>{safe_h}</strong> &rarr; CNAME: {safe_c}</div>'
        if resolved_hosts:
            html_content += '<table class="intel-table" style="margin-top:10px;"><tr><td style="color:#888;width:40%">Host</td><td style="color:#888;">IPs</td></tr>'
            for rh in resolved_hosts[:150]:
                safe_h  = html.escape(rh['host'])
                safe_ip = html.escape(', '.join(rh.get('ips', [])))
                html_content += f'<tr><td style="color:var(--dnsx-lime);">{safe_h}</td><td style="color:#aaa;">{safe_ip}</td></tr>'
            html_content += '</table>'
        html_content += '</div>'

    # NEW: HTTPx — Live HTTP Services
    if http_hosts:
        html_content += f"""
        <div class="category-section">
            <h2 style="color: var(--httpx-pink);">&#x1F310; Live HTTP Services (httpx) &mdash; {len(http_hosts)} hosts</h2>
            <div style="font-size:12px;color:#555;margin-bottom:8px;">Status | URL | Server | Technologies</div>"""
        for hh in http_hosts[:200]:
            sc = hh.get("status", 0)
            sc_class = "status-2xx" if 200<=sc<300 else "status-3xx" if 300<=sc<400 else "status-4xx" if 400<=sc<500 else "status-5xx"
            safe_url   = html.escape(hh.get("url", ""))
            safe_srv   = html.escape(hh.get("server", "") or "")
            safe_title = html.escape(hh.get("title", "") or "")
            tech_html  = "".join(
                f'<span class="tech-pill">{html.escape(str(t))}</span>'
                for t in (hh.get("tech") or [])[:6]
            )
            html_content += f'<div class="httpx-row"><span class="{sc_class}">{sc}</span><a href="{safe_url}" target="_blank" style="color:var(--httpx-pink);text-decoration:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="{safe_title}">{safe_url}</a><span style="color:#666;font-size:12px;">{safe_srv}</span><span>{tech_html}</span></div>'
        html_content += '</div>'

    # NEW: Katana — Discovered Endpoints
    if katana_endpoints:
        sensitive_eps = [e for e in katana_endpoints if e.get("sensitive")]
        api_eps       = [e for e in katana_endpoints if e.get("api")]
        other_eps     = [e for e in katana_endpoints if not e.get("sensitive") and not e.get("api")]
        html_content += f"""
        <div class="category-section">
            <h2 style="color: var(--katana-sky);">&#x1F578;&#xFE0F; Crawled Endpoints (katana) &mdash; {len(katana_endpoints)} total</h2>"""
        if sensitive_eps:
            html_content += f'<div style="margin-bottom:12px;"><strong style="color:#888;">Sensitive Files ({len(sensitive_eps)}):</strong><br>'
            for e in sensitive_eps[:50]:
                su = html.escape(e["url"])
                html_content += f'<div class="dork-item" style="margin:3px 0;"><a href="{su}" target="_blank" class="dork-text" style="color:var(--shodan-red);">{su}</a><button class="copy-btn" onclick="copyToClipboard(\'{su}\')">COPY</button></div>'
            html_content += '</div>'
        if api_eps:
            html_content += f'<div style="margin-bottom:12px;"><strong style="color:#888;">API Endpoints ({len(api_eps)}):</strong><br>'
            for e in api_eps[:50]:
                su = html.escape(e["url"])
                html_content += f'<div class="dork-item" style="margin:3px 0;"><a href="{su}" target="_blank" class="dork-text" style="color:var(--katana-sky);">{su}</a><button class="copy-btn" onclick="copyToClipboard(\'{su}\')">COPY</button></div>'
            html_content += '</div>'
        if other_eps:
            html_content += f'<div><strong style="color:#888;">Other Endpoints ({len(other_eps)}):</strong><br>'
            for e in other_eps[:100]:
                su = html.escape(e["url"])
                html_content += f'<div class="dork-item" style="margin:3px 0;"><a href="{su}" target="_blank" class="dork-text">{su}</a><button class="copy-btn" onclick="copyToClipboard(\'{su}\')">COPY</button></div>'
            html_content += '</div>'
        html_content += '</div>'

    # NEW: Nuclei — Vulnerability Findings
    if nuclei_findings:
        crit_count = sum(1 for f in nuclei_findings if f["severity"] == "critical")
        high_count = sum(1 for f in nuclei_findings if f["severity"] == "high")
        html_content += f"""
        <div class="category-section">
            <h2 style="color: var(--nuclei-crit);">&#x1F480; Nuclei Findings &mdash; {len(nuclei_findings)} total ({crit_count} critical, {high_count} high)</h2>"""
        border_colors = {"critical":"var(--nuclei-crit)","high":"var(--nuclei-high)",
                         "medium":"var(--nuclei-med)","low":"var(--nuclei-low)"}
        for finding in nuclei_findings[:300]:
            sev    = finding.get("severity", "info")
            name   = html.escape(finding.get("name", ""))
            tmpl   = html.escape(finding.get("template", ""))
            furl   = html.escape(finding.get("url", ""))
            desc   = html.escape(finding.get("description", "") or "")
            refs   = finding.get("reference", []) or []
            border = border_colors.get(sev, "#444")
            ref_html = " ".join(
                f'<a href="{html.escape(r)}" target="_blank" style="color:#555;font-size:11px;">[ref]</a>'
                for r in refs[:3]
            )
            desc_html = f'<div style="color:#666;font-size:12px;margin-top:4px;">{desc}</div>' if desc else ''
            html_content += f'<div class="finding-item" style="border-left-color:{border};"><div><span class="sev-badge sev-{sev}">{sev}</span><strong style="color:#ddd;">{name}</strong><span style="color:#555;font-size:12px;margin-left:8px;">[{tmpl}]</span> {ref_html}</div><div style="margin-top:4px;"><a href="{furl}" target="_blank" style="color:{border};font-size:13px;">{furl}</a></div>{desc_html}</div>'
        html_content += '</div>'

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

    # Also save a JSON summary alongside the HTML
    json_filename = f"ghost_dorks_{target.replace('.', '_')}.json"
    summary = {
        "target": target,
        "target_ip": target_ip,
        "subdomains": all_subdomains,
        "resolved_hosts": resolved_hosts,
        "takeover_candidates": takeover_candidates,
        "wayback_urls": discovered_wayback_urls,
        "open_ports": open_ports,
        "cves": vulns,
        "emails": harvest_data.get("emails", []),
        "harvested_hosts": harvest_data.get("hosts", []),
        "co_hosted_domains": co_hosted_domains,
        "naabu_ports": naabu_results,
        "http_hosts": http_hosts,
        "katana_endpoints": katana_endpoints,
        "nuclei_findings": nuclei_findings,
    }
    with open(json_filename, "w", encoding="utf-8") as jf:
        json.dump(summary, jf, indent=2)

    print(f"\n[+] Ghost Dashboard Generated : {filename}")
    print(f"[+] JSON Summary Saved        : {json_filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PROJECT GHOST ENGINE — Passive OSINT Dashboard Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Passive only (default):
    python ghostdorks.py -d example.com

  With active scanning (naabu + httpx + katana):
    python ghostdorks.py -d example.com --active

  Full nuclear mode (active + nuclei vuln scan):
    python ghostdorks.py -d example.com --active --nuclei

  Throttle active tools:
    python ghostdorks.py -d example.com --active --rate 300
"""
    )
    parser.add_argument("-d", "--domain",
        help="Target domain (e.g., example.com)", required=True)
    parser.add_argument("--active", action="store_true",
        help="Enable active scanning: naabu (port scan) + httpx (HTTP probe) + katana (crawl). "
             "Sends packets directly to the target.")
    parser.add_argument("--nuclei", action="store_true",
        help="Enable nuclei vulnerability scanning (exposures + misconfigs + takeovers). "
             "Requires --active or will auto-run httpx first. ONLY use with permission.")
    parser.add_argument("--rate", type=int, default=1000, metavar="N",
        help="Rate limit for active tools (packets/sec for naabu, req/sec for nuclei). "
             "Default: 1000. Lower for stealth (e.g. 300).")
    args = parser.parse_args()

    domain = args.domain.strip()
    if domain:
        generate_ghost_dashboard(domain, cfg={
            "active":  args.active,
            "nuclei":  args.nuclei,
            "rate":    args.rate,
        })
    else:
        print("[!] Domain cannot be empty.")
