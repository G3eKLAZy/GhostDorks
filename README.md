# 🕵️ PROJECT GHOST ENGINE (GhostDorks)

> Advanced passive OSINT dashboard generator with an optional full active scanning pipeline — all in one Python script.

---

## 📖 Description

Project Ghost Engine is an automated OSINT and reconnaissance tool designed for security researchers, bug bounty hunters, and penetration testers. It aggregates data from multiple passive sources **and** can optionally chain into a full active scanning pipeline using ProjectDiscovery tools installed on Kali Linux.

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
| Google Dorks | Generated locally | 130+ categorized, clickable dork queries |

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
                    ┌─────────┴──────────┐
                    │ [passive]          │ [--active]
                    ▼                   ▼
              katana -ps           naabu (port scan)
              Wayback CDX               │
                                   httpx (HTTP probe)
                                        │
                                   katana (active crawl)
                                        │
                                   [--nuclei]
                                        ▼
                              nuclei (vuln scan 💀)
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

1. 🔍 WHOIS Intelligence
2. 🧬 DNS Record Map (SPF/DMARC alerts)
3. 📧 Harvested Emails & Hosts
4. 🗺️ Co-Hosted Domains (Reverse IP)
5. 🧬 Live Resolved Hosts (dnsx) + Takeover Candidates
6. 🌐 Live HTTP Services (httpx)
7. 🕸️ Crawled Endpoints (katana) — Sensitive / API / Other
8. 💀 Nuclei Findings (severity-badged)
9. 🛑 Shodan Intel (ports + CVEs)
10. 🕰️ Archived Sensitive Files (Wayback)
11. 🌐 Discovered Subdomains
12. 📂 130+ Google Dork Categories

---

## ⚙️ Prerequisites

### Python
Requires **Python 3.x** and the `requests` library:

```bash
pip install requests
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
| `theHarvester` | Email & host harvesting | `sudo apt install theharvester` |

---

## 🚀 Usage

### Passive Only (Default — Safe, no target contact)
```bash
python ghostdorks.py -d target.com
```

### With Active Scanning (naabu + httpx + katana)
```bash
python ghostdorks.py -d target.com --active
```

### Full Nuclear Mode (active + nuclei vuln scan)
```bash
python ghostdorks.py -d target.com --active --nuclei
```

### Throttled / Stealth Rate
```bash
python ghostdorks.py -d target.com --active --nuclei --rate 300
```

### All Options
```
options:
  -d, --domain DOMAIN   Target domain (e.g., example.com)
  --active              Enable active scanning: naabu + httpx + katana
                        Sends packets directly to target.
  --nuclei              Enable nuclei vulnerability scanning
                        (exposures + misconfigs + takeovers).
                        ONLY use with permission.
  --rate N              Rate limit for active tools (default: 1000).
                        Lower for stealth (e.g. 300).
```

---

## 📁 Output Files

After each run, two files are saved in your current directory:

| File | Description |
|------|-------------|
| `ghost_dorks_<target>.html` | Full interactive dashboard — open in any browser |
| `ghost_dorks_<target>.json` | Structured JSON with all raw findings — pipe into other tools |

### Sample Terminal Output
```
=======================================================
  🕵️  PROJECT GHOST ENGINE — Passive Pipeline
=======================================================
  ⚠️  ACTIVE MODE enabled (naabu + httpx + katana)
=======================================================

[*] Querying crt.sh for subdomains of example.com...
[+] Successfully extracted 42 unique subdomains from crt.sh.
[*] Running subfinder for passive subdomain enumeration on example.com...
[+] subfinder found 67 subdomains.
[+] Combined subdomain list: 89 unique entries.
[*] Running dnsx to validate 89 subdomains...
[+] dnsx resolved 54 live hosts, 2 potential takeover candidates.
[*] Querying Wayback Machine for exposed files on example.com...
[+] Successfully extracted 23 archived URLs from Wayback Machine.
[*] Querying Shodan InternetDB for ports on 93.184.216.34...
[+] Found 4 open ports and 2 vulnerabilities.
[*] Running WHOIS lookup for example.com...
[+] WHOIS data retrieved. Registrar: MarkMonitor Inc., Nameservers: 2
[*] Querying DNS records for example.com...
[+] DNS enumeration complete. 12 total records found.
[*] Running theHarvester for email/host enumeration on example.com...
[+] theHarvester found: 5 emails, 18 hosts, 3 IPs
[*] Running reverse IP lookup for 93.184.216.34...
[+] Found 7 domains co-hosted on 93.184.216.34.
[*] Running katana [passive (Wayback/CommonCrawl)] for endpoint discovery...
[+] katana discovered 138 endpoint(s).
[*] Running naabu port scan on 54 hosts (rate=1000)...
[+] naabu found 12 open port(s) across all hosts.
[*] Running httpx to probe live HTTP services...
[+] httpx found 8 live HTTP endpoint(s).
[*] Running katana [active crawl] for endpoint discovery...
[+] katana discovered 45 endpoint(s).

[+] Ghost Dashboard Generated : ghost_dorks_example_com.html
[+] JSON Summary Saved        : ghost_dorks_example_com.json
```

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes and authorized security auditing only**. The developers and contributors assume no liability and are not responsible for any misuse or damage caused by this program. Always ensure you have **explicit, written permission** from the target owner before running any active modules (`--active`, `--nuclei`).

---

## 👨‍💻 Credits

Created by: **L4ZYG33K**
