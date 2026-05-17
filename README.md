# 🕵️ PROJECT GHOST ENGINE v2.0-Piped (GhostDorks)

> Advanced unified OSINT & cPanel/WHM reconnaissance engine with a **fully piped active scanning pipeline** — featuring the **Project Ghost Dork Engine**, **gf pattern matching**, **arjun parameter discovery**, and **subjack subdomain takeover scanning**.
>
> **v2.0-Piped**: Dork Engine results now feed into GF, Arjun, and Nuclei via automatic fallback chains. No more zero-result dead ends when Wayback times out or naabu finds only cPanel ports.

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
| **Dork Engine** | DuckDuckGo (`ddgs`) + YAML templates | 400+ categorized dork queries across 20 categories with automated result analysis |

### 🟡 Active Mode (`--active` flag — Light traffic, looks like a browser)

| Module | Tool | What It Collects | Piped From |
|--------|------|-----------------|------------|
| Port Scanning | `naabu` | Top-1000 ports across all resolved subdomains | dnsx resolved hosts |
| HTTP Probing | `httpx` | Live HTTP services, status codes, titles, server headers, tech stack | **naabu** → resolved hosts → **dork results** |
| Web Crawling | `katana` (active) | Deep endpoint discovery, JS parsing, form extraction | **httpx hosts** + **dork results** |

### 🔴 Nuclear Mode (`--nuclei` flag — Active exploitation probes)

| Module | Tool | What It Collects | Piped From |
|--------|------|-----------------|------------|
| Vulnerability Scanning | `nuclei` | Exposures, misconfigurations, subdomain takeovers — severity-ranked | **katana** → httpx → **dork results** |

### 🎯 cPanel Active Probe (`--cpanel-probe` flag)

| Module | Method | What It Collects |
|--------|--------|-----------------|
| CVE-2026-41940 Remote Probe | `requests` → `/json-api/version?api.version=1` | Non-destructive auth test; confirms if WHM API is vulnerable to CVE-2026-41940 |
| cPanel Risk Scoring | Algorithm | CRITICAL / HIGH / MEDIUM / LOW based on service type, patch status, probe result, hardening |

### 🆕 Dork Engine (`--dork-stealth`, `--dg-categories` flags)

| Feature | Description |
|---------|-------------|
| DuckDuckGo Search | Real-time dork execution via `ddgs` library (falls back to static Google URLs if unavailable) |
| 20 Categories | sqli, xss, lfi_rfi, redirect, ssrf, files, secrets, admin, vuln, api, errors, docs, paste_git, takeover, cloud, dev, social, cpanel_hosting, database, iot, cms, osint, subdomain_recon |
| Pattern Analysis | Auto-detects PII, secrets (AWS keys, GitHub tokens, JWTs), vulnerability indicators (SQL errors, XSS, LFI, RCE), and sensitive file types |
| Severity Ranking | Results tagged as critical / high / medium / low / info based on detected patterns |
| Checkpoint/Resume | Saves progress after each dork; resume interrupted sessions with `--dork-resume` |
| Stealth Mode | Random delays between dorks (1-3s) with `--dork-stealth` |
| Deduplication | MD5-based URL deduplication across all dork queries |

### 🆕 GF Integration (`--gf` flag)

Runs `gf` pattern matching on all katana endpoints, Wayback URLs, and **dork result URLs** for:
- xss, sqli, ssrf, redirect, aws-keys, s3-buckets, debug-pages
- base64, jwt, idor, lfi, rce, takeovers, upload-fields
- php-errors, git, cors

**Pipeline behavior:** If katana returns 0 endpoints, GF automatically falls back to dork result URLs.

### 🆕 Arjun Integration (`--arjun` flag)

Discovers hidden HTTP parameters on live hosts using `arjun`:
- Scans up to 50 unique HTTP hosts
- Outputs discovered parameters with method and type

**Pipeline behavior:** If httpx returns 0 hosts, Arjun falls back to GF interesting matches (SQLi, XSS, IDOR, etc.), then to dork result URLs.

### 🆕 Subjack Integration (`--subjack` flag)

Scans all discovered subdomains for takeover vulnerabilities:
- Detects services: GitHub, Heroku, AWS, Azure, Fastly, Shopify, Tumblr, WordPress, and more
- Reports CONFIRMED and POTENTIAL takeover candidates

---

## 🔗 Pipeline Architecture

**v2.0-Piped**: Tools now feed into each other with automatic fallback chains. No more zero-result dead ends.

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
              Dork Engine (ddgs)                        naabu (port scan)
              ├─ 492 dorks, 20 categories                      │
              ├─ Pattern analysis (PII/secrets/vulns)           ▼
              ├─ Severity ranking                         httpx (HTTP probe)
              └─ Checkpoint/resume                          ├─ naabu ports
                    │                                       ├─ resolved hosts (https)
                    │                                       └─ dork result URLs [FALLBACK]
                    │                                               │
                    ├───────────────────────────────────────────────┘
                    │
                    ▼
              katana (passive + active)
              ├─ Wayback / CommonCrawl
              ├─ dork result URLs as seeds
              └─ active crawl on httpx hosts
                    │
                    ├───────────────────────────────────────────────┐
                    │                                               │
                    ▼                                               ▼
              gf (pattern matching)                          arjun (params)
              ├─ katana endpoints                            ├─ httpx hosts
              ├─ wayback URLs                                ├─ GF interesting matches
              └─ dork result URLs [FALLBACK]                 └─ dork result URLs [FALLBACK]
                    │
                    ▼
              nuclei (vulnerability scan 💀)
              ├─ katana endpoints
              ├─ httpx hosts
              └─ dork result URLs [FALLBACK]
                    │
              cPanel/WHM detect
              WHOIS / DNS / Shodan
              theHarvester / Reverse IP
              subjack (takeovers)
                    │
                    └───────────────────────────────────────────┘
                                              │
                                              ▼
                                ┌─────────────────────────┐
                                │   HTML Dashboard         │
                                │   JSON Summary           │
                                └─────────────────────────┘
```

### Fallback Chain Behavior

When a stage produces zero results, the pipeline automatically feeds upstream data forward:

| Stage | Primary Input | Fallback Input | Fallback Input |
|-------|--------------|----------------|----------------|
| **httpx** | naabu ports | resolved hosts (with `https://`) | dork result URLs |
| **katana** | http_hosts | resolved hosts | dork result URLs |
| **gf** | katana + wayback | — | dork result URLs |
| **arjun** | http_hosts | GF interesting matches | dork result URLs |
| **nuclei** | katana endpoints | http_hosts | dork result URLs |

This ensures that even if `naabu` finds only cPanel ports (`2082`, `2083`) or Wayback times out, the **222 dork results** still seed the entire active pipeline.

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

## 🔗 Pipeline Integration (v2.0-Piped)

### Why Piping Matters

In the original v2.0, each tool ran as a standalone module. If one tool returned zero results, downstream tools would skip entirely — creating "dead ends" in the reconnaissance chain. Common failure modes:

- **Wayback Machine times out** → katana passive returns 0 URLs → GF skips → Arjun skips → Nuclei skips
- **naabu finds only cPanel ports** (`2082`, `2083`) → httpx whitelist blocks them → 0 HTTP hosts → everything downstream dies
- **Dork Engine finds 222 URLs** → but they only go to the dashboard, never feed active tools

### The Solution: Upstream Fallbacks

Every active tool now accepts `dork_results` as a fallback parameter. The execution order ensures dork results are available before any active tool runs:

```python
# New execution order in generate_ghost_dashboard()
1. DorkEngine.run()              # 492 dorks → 222 URLs
2. katana(passive, dork_results) # Wayback + dork URLs as seeds
3. naabu(resolved_hosts)         # port scan
4. httpx(naabu, resolved, dorks) # probe with 3-tier fallback
5. katana(active, http_hosts, dorks) # crawl with dork fallback
6. gf(katana, wayback, dorks)    # pattern match with dork fallback
7. arjun(http_hosts, gf, dorks)  # param discovery with 3-tier fallback
8. nuclei(http_hosts, katana, dorks) # vuln scan with 3-tier fallback
```

### Fallback Chain Details

```
┌─────────────────────────────────────────────────────────────────┐
│                         HTTPX FALLBACKS                          │
├─────────────────────────────────────────────────────────────────┤
│  Tier 1: naabu_results (ports 80, 443, 8080, 8443, 2082, 2083…) │
│  Tier 2: resolved_hosts with https:// prefix                     │
│  Tier 3: dork_result URLs (extract host from URL)                │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                        KATANA FALLBACKS                          │
├─────────────────────────────────────────────────────────────────┤
│  Passive: resolved_hosts + dork URLs (top 30) as seed list       │
│  Active:  http_hosts + dork URLs (top 20) as seed list           │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                          GF FALLBACKS                            │
├─────────────────────────────────────────────────────────────────┤
│  Primary: katana_endpoints + wayback_urls                        │
│  Fallback: dork_result URLs (all HTTP/HTTPS URLs)                │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                        ARJUN FALLBACKS                           │
├─────────────────────────────────────────────────────────────────┤
│  Tier 1: http_hosts (live HTTP services from httpx)              │
│  Tier 2: GF interesting matches (sqli, xss, idor, lfi, rce…)    │
│  Tier 3: dork_result URLs (top 50 unique hosts)                  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                       NUCLEI FALLBACKS                           │
├─────────────────────────────────────────────────────────────────┤
│  Tier 1: katana_endpoints (crawled URLs)                         │
│  Tier 2: http_hosts (live services from httpx)                   │
│  Tier 3: dork_result URLs (all HTTP/HTTPS URLs, deduplicated)    │
└─────────────────────────────────────────────────────────────────┘
```

### Port Whitelist Expansion

The original `valid_http_ports` only included standard web ports (`80`, `443`, `8080`…). cPanel/WHM services run on non-standard ports that were being filtered out:

```python
# Before (caused 0 httpx results on cPanel targets)
valid_http_ports = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 8081, 9000}

# After (includes cPanel/WHM/Webmail ports)
valid_http_ports = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 8081, 9000,
                    2082, 2083, 2086, 2087, 2095, 2096, 2077, 2078, 2079}
```

This ensures `httpx` probes cPanel login pages, webmail, and WHM interfaces — not just standard web servers.

---

## ⚙️ Prerequisites

### Python Environment (Kali Linux / PEP 668)

Kali uses an **externally managed Python environment**. You must use a virtual environment to install `ddgs` and `pyyaml`.

```bash
cd ~/Desktop/myproject/ghostdorks

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies inside the venv
pip install ddgs pyyaml

# Optional: verify ddgs is working
python -c "from ddgs import DDGS; print('DDGS OK')"
```

> **Note:** Activate the venv every session: `source venv/bin/activate`

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

> **All commands assume you are inside the virtual environment:** `source venv/bin/activate`

### Passive Only (Default — Safe, no target contact)
```bash
python ghostdorks_v2.py -d target.com
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

### Full Recon — Everything Enabled (Piped Pipeline)
```bash
python ghostdorks_v2.py -d target.com --active --nuclei --cpanel-probe --gf --arjun --subjack --dork-stealth
```
> **Note:** In piped mode, Dork Engine results (222 URLs) automatically feed into GF, Arjun, and Nuclei if primary sources are empty. No more zero-result dead ends.

### Throttled / Stealth Rate
```bash
python ghostdorks_v2.py -d target.com --active --nuclei --rate 300
```

### Force Dork Results into Active Pipeline (even if naabu/httpx fail)
```bash
python ghostdorks_v2.py -d target.com --active --nuclei --gf --arjun --dork-stealth
```
> Even if the target only has cPanel ports (2083) or Wayback times out, the 222 dork URLs will seed GF, Arjun, and Nuclei.

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
                        Auto-falls back to dork results if no HTTP hosts.
  --cpanel-probe        Enable active CVE-2026-41940 probe against WHM
                        /json-api/version endpoint. ONLY use with explicit
                        authorization.
  --gf                  Enable gf pattern matching on katana endpoints,
                        wayback URLs, and dork results (fallback).
  --arjun               Enable arjun hidden parameter discovery on live
                        HTTP hosts. Falls back to GF matches, then dork URLs.
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

### Pipeline Behavior Notes

| Flag | Piped From | Fallback Chain |
|------|-----------|----------------|
| `--gf` | katana + wayback | → dork results |
| `--arjun` | httpx hosts | → GF matches → dork results |
| `--nuclei` | katana endpoints | → httpx hosts → dork results |
| `--active` | naabu → httpx → katana | dork results feed all stages |

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
- `pipeline_status` — Per-stage counters showing data flow (dorks → katana → httpx → gf → arjun → nuclei)
- `pipeline_status` — Per-stage counters showing data flow (dorks → katana → httpx → gf → arjun → nuclei)

### Sample Terminal Output (v2.0-Piped)
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

[*] DorkEngine initialized: 492 dorks across 23 categories
[*] Mode: STEALTH | Rate: 300 | Max results/dork: 50
[*] Checkpoint: .checkpoints/a3f7b2c1d8e5.pkl

[ Dork 1/492 ]  Ctrl+C -> skip  |  Double Ctrl+C -> quit
[*] Searching: site:example.com inurl:id=...
[+] Found 3 results [low:3]
... (466 dorks later) ...
[+] DorkEngine complete: 492/492 dorks
[+] Total unique URLs: 222 | Patterns: 156

[*] Running katana [passive (Wayback/CommonCrawl)] for endpoint discovery...
[*] Enriching with 30 dork result URLs as seeds...
[-] Wayback Machine query timed out.
[-] No sensitive archived files found on Wayback Machine.
[+] katana discovered 0 endpoint(s) from archives.
[+] katana discovered 18 endpoint(s) from dork URL seeds.

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

══════════════════════════════════════════════════════════════════
  PIPELINED ACTIVE RECON CHAIN
══════════════════════════════════════════════════════════════════

[*] Running naabu port scan on 54 hosts (rate=300)...
[+] naabu found 12 open port(s) across all hosts.

[*] Running httpx to probe live HTTP services...
[*] naabu found no standard HTTP ports. Falling back to resolved hosts with https:// prefix...
[+] httpx found 6 live HTTP endpoint(s) from resolved hosts.
[*] No resolved hosts to probe. Using dork engine results as httpx seeds...
[+] httpx found 4 additional endpoint(s) from dork results.
[+] httpx total: 10 live HTTP endpoint(s).

[*] Running katana [active crawl] for endpoint discovery...
[*] No http_hosts for active katana. Using dork results as seeds...
[+] katana discovered 45 endpoint(s).

[*] Running gf pattern matching on 63 URLs...
[*] No katana/wayback endpoints. Using dork results as GF input...
[+] gf analysis complete. 12 total pattern matches across 4 patterns.

[*] Running arjun for hidden parameter discovery on 10 hosts...
[*] No http_hosts for arjun. Using GF pattern matches as targets...
[+] arjun found 8 hidden parameters across 3 hosts.

[*] Running subjack on 89 subdomains...
[+] subjack found 3 takeovers (1 confirmed, 2 potential).

[*] Running nuclei vulnerability scan (rate=150)...
[*] No HTTP hosts or katana endpoints. Using dork results as nuclei targets...
[+] nuclei found 5 findings (1 critical, 2 high).

[+] Ghost Dashboard Generated : ghost_dorks_example_com.html
[+] JSON Summary Saved        : ghost_dorks_example_com.json
```

**Key differences in piped mode:**
- Dork Engine runs **first** (before katana passive)
- Wayback timeout no longer kills the pipeline — dork URLs seed katana
- httpx finds hosts via **fallback chain** even when naabu only finds cPanel ports
- GF, Arjun, and Nuclei all execute using **dork results** when primary inputs are empty
- Dashboard shows live pipeline status with per-stage counters

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes and authorized security auditing only**. The developers and contributors assume no liability and are not responsible for any misuse or damage caused by this program.

**Active modules (`--active`, `--nuclei`, `--cpanel-probe`, `--arjun`) send packets and requests directly to the target.** Always ensure you have **explicit, written permission** from the target owner before running any active modules.

The Dork Engine queries third-party search engines (DuckDuckGo). Use `--dork-stealth` and reasonable `--dg-max-results` values to avoid rate limiting.

---

## 📜 Changelog

### v2.0-Piped (Current)
- **Pipeline Integration**: Dork Engine results now feed GF, Arjun, and Nuclei via automatic fallback chains
- **Expanded Port Whitelist**: Added cPanel/WHM/Webmail ports (`2082`, `2083`, `2086`, `2087`, `2095`, `2096`, `2077-2079`) to httpx probing
- **Execution Reorder**: Dork Engine now runs before active tools so results are available for fallback
- **3-Tier Fallbacks**: Each active tool has multiple fallback inputs (e.g., httpx: naabu → resolved_hosts → dork_results)
- **Dashboard Pipeline Status**: New HTML section showing live per-stage counters and data flow documentation
- **Katana Seeding**: Both passive and active katana now use dork result URLs as seed targets

### v2.0 (Original)
- Added Project Ghost Dork Engine with DuckDuckGo integration
- Added YAML template-based dork generation (492 dorks, 23 categories)
- Added pattern analysis (PII, secrets, vulnerability indicators)
- Added session checkpoint/resume system
- Added gf, arjun, and subjack integrations
- Added cPanel/WHM detection and CVE-2026-41940 assessment

## 👨‍💻 Credits

Created by: **L4ZYG33K**

v2.0 Dork Engine, gf, arjun, and subjack integrations by Project Ghost Dork Engine

v2.0-Piped pipeline architecture and fallback chains by community contribution
