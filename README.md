# 🕵️ PROJECT GHOST ENGINE v2.0 (GhostRecon)

> Advanced unified OSINT & cPanel/WHM reconnaissance engine with an optional full active scanning pipeline — featuring the **Project Ghost Dork Engine**, **gf pattern matching**, **arjun parameter discovery**, and **subjack subdomain takeover scanning**.

---

## 📖 Description

Project Ghost Engine is an automated OSINT and reconnaissance tool designed for security researchers, bug bounty hunters, and penetration testers. It aggregates data from multiple passive sources **and** can optionally chain into a full active scanning pipeline using ProjectDiscovery tools installed on Kali Linux.

**v2.0 adds** a complete Project Ghost Dork Engine with DuckDuckGo integration, YAML template-based dork generation, result deduplication, pattern analysis (PII/secrets/vuln indicators), session checkpoint/resume, and stealth controls. Also integrates `gf`, `arjun`, and `subjack` for enhanced endpoint and takeover analysis.

All results are compiled into a **self-contained, color-coded, searchable HTML dashboard** plus a structured **JSON summary** — both saved automatically after every run.

---

## ✨ Feature Modules

### 🟢 Passive Mode (Always Active — No Target Contact)

| Module | Tool / Source | What It Collects |
|--------|--------------|-----------------|
| Subdomain Enumeration | crt.sh → AlienVault OTX → HackerTarget | Passive subdomains via certificate transparency & DNS |
| Subfinder | `subfinder` (40+ OSINT APIs) | Extended subdomain list merged with above |
| DNS Validation | `dnsx` | Resolves live subdomains, detects CNAME takeover candidates |
| Katana (passive) | `katana -ps` (Wayback + CommonCrawl) | Endpoints, JS files, API paths from archives |
| Wayback Machine | web.archive.org CDX API | Archived sensitive files (.env, .sql, .bak, .pem…) |
| Shodan InternetDB | internetdb.shodan.io | Open ports + known CVEs for the target IP |
| WHOIS Intelligence | `whois` | Registrar, org, dates, nameservers, DNSSEC |
| DNS Record Map | `dig` | A/AAAA/MX/NS/TXT/SOA/CNAME + SPF/DMARC analysis |
| Email Harvesting | `theHarvester` | Emails, hostnames, IPs from 7 OSINT sources |
| Reverse IP Lookup | HackerTarget API | Co-hosted domains on the same IP |
| **cPanel/WHM Detection** | `requests` + `openssl` + `dig` | Service fingerprinting on 2083/2087, version extraction, SSL analysis, geo lookup |
| **CVE-2026-41940 Assessment** | Passive regex + build database | Patch status: PATCHED / LIKELY_VULNERABLE / NO_VENDOR_PATCH / UNKNOWN |
| **Subjack** | `subjack` | Subdomain takeover fingerprinting (when `--subjack` enabled) |
| **GF Patterns** | `gf` | Pattern matching on endpoints for XSS, SQLi, SSRF, AWS keys, etc. (when `--gf` enabled) |
| **Dork Engine** | DuckDuckGo (`ddgs`) + YAML templates | 400+ categorized dork queries across 20+ categories with automated result analysis |

### 🟡 Active Mode (`--active` flag — Light traffic, looks like a browser)

| Module | Tool | What It Collects |
|--------|------|-----------------|
| Port Scanning | `naabu` | Top-1000 ports across all resolved subdomains |
| HTTP Probing | `httpx` | Live HTTP services, status codes, titles, server headers, tech stack |
| Web Crawling | `katana` (active) | Deep endpoint discovery, JS parsing, form extraction |

### 🔴 Nuclear Mode (`--nuclei` flag — Active exploitation probes)

| Module | Tool | What It Collects |
|--------|------|-----------------|
| Vulnerability Scanning | `nuclei` | Exposures, misconfigurations, subdomain takeovers — severity-ranked |

### 🎯 cPanel Active Probe (`--cpanel-probe` flag)

| Module | Method | What It Collects |
|--------|--------|-----------------|
| CVE-2026-41940 Remote Probe | `requests` → `/json-api/version?api.version=1` | Non-destructive auth test; confirms if WHM API is vulnerable to CVE-2026-41940 |
| cPanel Risk Scoring | Algorithm | CRITICAL / HIGH / MEDIUM / LOW based on service type, patch status, probe result, hardening |

### 🆕 Dork Engine (`--dork-stealth`, `--dg-categories` flags)

| Feature | Description |
|---------|-------------|
| DuckDuckGo Search | Real-time dork execution via `ddgs` library (falls back to static Google URLs if unavailable) |
| 20+ Categories | sqli, xss, lfi_rfi, redirect, ssrf, files, secrets, admin, vuln, api, errors, docs, paste_git, takeover, cloud, dev, social, cpanel_hosting, database, iot, cms, osint, subdomain_recon |
| Pattern Analysis | Auto-detects PII, secrets (AWS keys, GitHub tokens, JWTs), vulnerability indicators (SQL errors, XSS, LFI, RCE), and sensitive file types |
| Severity Ranking | Results tagged as critical / high / medium / low / info based on detected patterns |
| Checkpoint/Resume | Saves progress after each dork; resume interrupted sessions with `--dork-resume` |
| Stealth Mode | Random delays between dorks (1-3s) with `--dork-stealth` |
| Deduplication | MD5-based URL deduplication across all dork queries |

### 🆕 GF Integration (`--gf` flag)

Runs `gf` pattern matching on all katana endpoints and Wayback URLs for:
- xss, sqli, ssrf, redirect, aws-keys, s3-buckets, debug-pages
- base64, jwt, idor, lfi, rce, takeovers, upload-fields
- php-errors, git, cors

### 🆕 Arjun Integration (`--arjun` flag)

Discovers hidden HTTP parameters on live hosts using `arjun`:
- Scans up to 50 unique HTTP hosts
- Outputs discovered parameters with method and type

### 🆕 Subjack Integration (`--subjack` flag)

Scans all discovered subdomains for takeover vulnerabilities:
- Detects services: GitHub, Heroku, AWS, Azure, Fastly, Shopify, Tumblr, WordPress, and more
- Reports CONFIRMED and POTENTIAL takeover candidates

---

## 🔗 Pipeline Architecture

```
                    ┌─ crt.sh / OTX / HackerTarget ─┐
TARGET DOMAIN ──►   ├─ subfinder (40+ sources)       ├──► MERGED SUBDOMAIN LIST
                    └────────────────────────────────┘
                              │
                              ▼
                        dnsx (validate, resolve A/CNAME, detect takeovers)
                              │
                    ┌─────────┴──────────────────────────────┐
                    │ [passive]                              │ [--active]
                    ▼                                        ▼
              katana -ps                                naabu (port scan)
              Wayback CDX                                     │
              cPanel/WHM detect                          httpx (HTTP probe)
              WHOIS / DNS / Shodan                              │
              theHarvester / Reverse IP                   katana (active crawl)
              Dork Engine (ddgs)                                │
              subjack (takeovers)                        [--nuclei]
              gf (patterns)                                   ▼
              arjun (params)                         nuclei (vuln scan 💀)
                    │                                           │
                    └───────────────────────────────────────────┘
                                              │
                                              ▼
                                ┌─────────────────────────┐
                                │   HTML Dashboard         │
                                │   JSON Summary           │
                                └─────────────────────────┘
```

---

## 📊 Dashboard Sections

The generated HTML dashboard includes (in order):

1. 🎯 **Project Ghost Dork Engine Results** *(NEW in v2.0)*
   - Severity stats grid (critical/high/medium/low/info)
   - Results grouped by severity with pattern chips
   - Auto-detected patterns: PII, secrets, vulnerabilities, file types
   - Clickable URLs with dork provenance

2. 🎛️ **cPanel/WHM Reconnaissance & CVE-2026-41940 Triage**
   - Service type, port, response size/time
   - IP geolocation & ISP data
   - Patch status badge (PATCHED / LIKELY_VULNERABLE / NO_VENDOR_PATCH / UNKNOWN)
   - Probe status badge (VULNERABLE / SAFE / INCONCLUSIVE)
   - Risk level with color-coded score (CRITICAL → LOW)
   - Security headers & certificate analysis
   - Version indicators extracted from 6 passive fingerprinting methods
   - SSL certificate details
   - Response headers & body snippet

3. 🔴 **Subjack Takeover Results** *(NEW in v2.0)*
   - Confirmed and potential subdomain takeovers
   - Service identification (GitHub, AWS, Heroku, etc.)

4. 🟣 **GF Pattern Matches** *(NEW in v2.0)*
   - Pattern matches across all discovered endpoints
   - XSS, SQLi, SSRF, AWS keys, JWTs, LFI, RCE, etc.

5. 🔵 **Arjun Hidden Parameters** *(NEW in v2.0)*
   - Discovered hidden parameters per host
   - Method and parameter type indicators

6. 🔍 WHOIS Intelligence
7. 🧬 DNS Record Map (SPF/DMARC alerts)
8. 📧 Harvested Emails & Hosts
9. 🗺️ Co-Hosted Domains (Reverse IP)
10. 🧬 Live Resolved Hosts (dnsx) + Takeover Candidates
11. 🌐 Live HTTP Services (httpx)
12. 🕸️ Crawled Endpoints (katana) — Sensitive / API / Other
13. 💀 Nuclei Findings (severity-badged)
14. 🛑 Shodan Intel (ports + CVEs)
15. 🕰️ Archived Sensitive Files (Wayback)
16. 🌐 Discovered Subdomains
17. 📂 400+ Google Dork Categories

---

## ⚙️ Prerequisites

### Python
Requires **Python 3.x** and the following libraries:

```bash
pip install requests
# Optional but recommended:
pip install ddgs        # For live DuckDuckGo dork searching
pip install pyyaml      # For YAML template parsing (fallback parser included)
```

### Kali Linux Tools
The following tools are **pre-installed on Kali Linux**. Ghost Engine will automatically skip any module whose tool is not found — no errors, no crashes.

| Tool | Purpose | Install (if missing) |
|------|---------|----------------------|
| `subfinder` | Extended passive subdomain enumeration | `sudo apt install subfinder` |
| `dnsx` | DNS validation & takeover detection | `sudo apt install dnsx` |
| `naabu` | Fast port scanning (`--active`) | `sudo apt install naabu` |
| `httpx` | HTTP probing & tech fingerprinting (`--active`) | `sudo apt install httpx` |
| `katana` | Web crawling / endpoint discovery | `sudo apt install katana` |
| `nuclei` | Vulnerability scanning (`--nuclei`) | `sudo apt install nuclei` |
| `whois` | WHOIS lookups | `sudo apt install whois` |
| `dig` | DNS record enumeration | `sudo apt install dnsutils` |
| `openssl` | SSL certificate extraction (cPanel module) | `sudo apt install openssl` |
| `theHarvester` | Email & host harvesting | `sudo apt install theharvester` |
| `gf` | Pattern matching on URLs (`--gf`) | `go install github.com/tomnomnom/gf@latest` |
| `arjun` | Hidden parameter discovery (`--arjun`) | `pip install arjun` |
| `subjack` | Subdomain takeover scanning (`--subjack`) | `go install github.com/haccer/subjack@latest` |

---

## 🚀 Usage

### Passive Only (Default — Safe, no target contact)
```bash
python ghostreconv2.py -d target.com
```

### With Active Scanning (naabu + httpx + katana)
```bash
python ghostdorks_v2.py -d target.com --active
```

### Full Nuclear Mode (active + nuclei vuln scan)
```bash
python ghostdorks_v2.py -d target.com --active --nuclei
```

### cPanel/WHM Triage with Active CVE Probe
```bash
python ghostdorks_v2.py -d target.com --active --cpanel-probe
```

### Dork Engine — Specific Categories with Stealth
```bash
python ghostdorks_v2.py -d target.com --dork-stealth --dg-categories sqli,secrets,files
```

### Resume Interrupted Dork Session
```bash
python ghostdorks_v2.py -d target.com --dork-resume
```

### Enable All New Tools (gf + arjun + subjack)
```bash
python ghostdorks_v2.py -d target.com --active --gf --arjun --subjack
```

### Full Recon — Everything Enabled
```bash
python ghostdorks_v2.py -d target.com --active --nuclei --cpanel-probe --gf --arjun --subjack --dork-stealth
```

### Throttled / Stealth Rate
```bash
python ghostdorks_v2.py -d target.com --active --nuclei --rate 300
```

---

## 📋 Command Reference

```
options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Target domain (e.g., example.com)
  --active              Enable active scanning: naabu + httpx + katana.
                        Sends packets directly to target.
  --nuclei              Enable nuclei vulnerability scanning.
                        Requires --active or will auto-run httpx first.
  --cpanel-probe        Enable active CVE-2026-41940 probe against WHM
                        /json-api/version endpoint. ONLY use with explicit
                        authorization.
  --gf                  Enable gf pattern matching on katana endpoints
                        and wayback URLs.
  --arjun               Enable arjun hidden parameter discovery on live
                        HTTP hosts.
  --subjack             Enable subjack subdomain takeover scanning on all
                        discovered subdomains.
  --rate N              Rate limit for active tools. Default: 1000.
                        Lower for stealth (e.g. 300).
  --dork-stealth        Enable stealth mode for dork engine (slower with
                        random delays).
  --dg-categories CATS  Comma-separated dork categories to run. Default:
                        all. Options: sqli,xss,lfi_rfi,redirect,ssrf,files,
                        secrets,admin,vuln,api,errors,docs,paste_git,
                        takeover,cloud,dev,social,cpanel_hosting,database,
                        iot,cms,osint,subdomain_recon
  --dg-max-results N    Max results per dork query. Default: 50.
  --dork-checkpoint     Enable session checkpointing for dork engine
                        (default: on).
  --dork-resume         Resume interrupted dork session from checkpoint.
  --no-dork-checkpoint  Disable session checkpointing.
```

---

## 📁 Output Files

After each run, two files are saved in your current directory:

| File | Description |
|------|-------------|
| `ghost_dorks_<target>.html` | Full interactive dashboard — open in any browser |
| `ghost_dorks_<target>.json` | Structured JSON with all raw findings — pipe into other tools |

The JSON summary now includes:
- `dork_engine_results` — All dork findings with severity and patterns
- `dork_engine_stats` — Completion statistics
- `gf_results` — GF pattern matches per category
- `arjun_results` — Hidden parameters per host
- `subjack_results` — Takeover findings with status and service
- `cpanel_recon` — Full cPanel/WHM triage object

### Sample Terminal Output (v2.0)
```
================================================================================
GHOSTRECON v2 — Unified OSINT & cPanel/WHM Reconnaissance Engine
Created by: L4ZYG33K | Project Ghost Dork Engine
================================================================================

[*] Querying crt.sh for subdomains of example.com...
[+] Successfully extracted 42 unique subdomains from crt.sh.
[*] Running subfinder for passive subdomain enumeration on example.com...
[+] subfinder found 67 subdomains.
[+] Combined subdomain list: 89 unique entries.
[*] Running dnsx to validate 89 subdomains...
[+] dnsx resolved 54 live hosts, 2 potential takeover candidates.
[*] Checking example.com for cPanel/WHM on ports 2083/2087...
[!] WHM Detected on port 2087 (size: 12453B, time: 1.23s)
[+] IP: 192.0.2.15
[+] Geo: Dallas, US — Cloudflare, Inc.
[-] Missing security headers (X-Frame-Options, X-Content-Type-Options, HSTS, CSP)
[+] Extracted version indicators: 11.118.0.63, rev_20260428
[!] WARNING: Version 11.118.0.63 detected but no patched build string confirmed.

--- ACTIVE REMOTE PROBE (CVE-2026-41940) ---
[!!!] VULNERABLE: Remote probe returned 200 with API version data (CVE-2026-41940)

[!!!] RISK LEVEL: CRITICAL (score: 10)
      ACTION REQUIRED: Assume compromise risk. Firewall 2083/2087 immediately.

[*] DorkEngine initialized: 412 dorks across 20 categories
[*] Mode: STEALTH | Rate: 300 | Max results/dork: 50
[*] Checkpoint: .checkpoints/a3f7b2c1d8e5.pkl

[ Dork 1/412 ]  Ctrl+C -> skip  |  Double Ctrl+C -> quit
[*] Searching: site:example.com inurl:id=...
[+] Found 3 results [low:3]

[*] Querying Wayback Machine for exposed files on example.com...
[+] Successfully extracted 23 archived URLs from Wayback Machine.
[*] Querying Shodan InternetDB for ports on 192.0.2.15...
[+] Found 4 open ports and 2 vulnerabilities.
[*] Running WHOIS lookup for example.com...
[+] WHOIS data retrieved. Registrar: Example Registrar, Nameservers: 2
[*] Querying DNS records for example.com...
[+] DNS enumeration complete. 12 total records found.
[*] Running theHarvester for email/host enumeration on example.com...
[+] theHarvester found: 5 emails, 18 hosts, 3 IPs
[*] Running reverse IP lookup for 192.0.2.15...
[+] Found 7 domains co-hosted on 192.0.2.15.
[*] Running katana [passive (Wayback/CommonCrawl)] for endpoint discovery...
[+] katana discovered 138 endpoint(s).
[*] Running naabu port scan on 54 hosts (rate=300)...
[+] naabu found 12 open port(s) across all hosts.
[*] Running httpx to probe live HTTP services...
[+] httpx found 8 live HTTP endpoint(s).
[*] Running katana [active crawl] for endpoint discovery...
[+] katana discovered 45 endpoint(s).
[*] Running gf pattern matching on 183 endpoints...
[+] gf analysis complete. 47 total pattern matches across 8 patterns.
[*] Running arjun for hidden parameter discovery on 8 hosts...
[+] arjun found 15 hidden parameters across 4 hosts.
[*] Running subjack on 89 subdomains...
[+] subjack found 3 takeovers (1 confirmed, 2 potential).
[*] Running nuclei vulnerability scan (rate=150)...
[+] nuclei found 3 findings (0 critical, 1 high).

[+] DorkEngine complete: 412/412 dorks
[+] Total unique URLs: 847 | Patterns: 156

[+] Ghost Dashboard Generated : ghost_dorks_example_com.html
[+] JSON Summary Saved        : ghost_dorks_example_com.json
```

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes and authorized security auditing only**. The developers and contributors assume no liability and are not responsible for any misuse or damage caused by this program.

**Active modules (`--active`, `--nuclei`, `--cpanel-probe`, `--arjun`) send packets and requests directly to the target.** Always ensure you have **explicit, written permission** from the target owner before running any active modules.

The Dork Engine queries third-party search engines (DuckDuckGo). Use `--dork-stealth` and reasonable `--dg-max-results` values to avoid rate limiting.

---

## 👨‍💻 Credits

Created by: **L4ZYG33K**

v2.0 Dork Engine, gf, arjun, and subjack integrations by Project Ghost Dork Engine
