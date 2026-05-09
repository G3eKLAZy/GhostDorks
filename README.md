# 🕵️ PROJECT GHOST ENGINE (GhostDorks)

## 📖 Description

Project Ghost Engine is an advanced, automated OSINT (Open Source Intelligence) and reconnaissance tool designed for security researchers, bug bounty hunters, and penetration testers. It aggregates data from various passive sources and generates a highly interactive, standalone HTML dashboard tailored to a specific target domain.

The tool combines passive DNS enumeration, WHOIS intelligence, DNS record mapping, email harvesting, reverse IP analysis, archived file discovery, IP port scanning, and an extensive list of categorized Google Dorks to provide a comprehensive attack surface map — all without sending aggressive or noisy requests directly to the target infrastructure.

## ✨ Features

### 🌐 Passive Subdomain Enumeration
Implements a highly resilient triple-redundant fallback system querying **crt.sh**, **AlienVault OTX**, and **HackerTarget**.

### 🔍 WHOIS Intelligence
Extracts domain registration details including registrar, creation/expiry dates, organization, country, nameservers, and DNSSEC status using the system `whois` command.

### 🧬 DNS Record Map
Enumerates all DNS record types (A, AAAA, MX, NS, TXT, SOA, CNAME) using `dig`. Automatically analyzes **SPF** and **DMARC** policies and flags missing or misconfigured email security as vulnerabilities.

### 📧 Email & Host Harvesting
Leverages **theHarvester** to passively collect email addresses, hostnames, and IP addresses from 7 OSINT sources (Anubis, crt.sh, DNSDumpster, DuckDuckGo, HackerTarget, RapidDNS, URLScan).

### 🗺️ Reverse IP Lookup
Discovers all domains co-hosted on the same IP address, revealing shared hosting environments and expanding the attack surface.

### 🕰️ Archived Data Discovery
Interrogates the **Wayback Machine** to uncover exposed sensitive files (e.g., `.env`, `.sql`, `.bak`, `.json`, `.pem`).

### 🛑 Vulnerability & Port Scanning
Utilizes the free **Shodan InternetDB** API to map open ports and known CVEs associated with the target's resolved IP address.

### 🔗 Dynamic Google Dorks Map
Automatically generates a robust, clickable list of **130+ Google Dorks** customized for the target domain. Categories include:
- Subdomain Enum & Takeover
- Directory & File Exposure
- Secrets, Configs & Leaks
- Admin Panels
- APIs & Swagger Docs
- Cloud Storage (S3, GCP, Azure)
- Error & Debug Pages
- Documents & Social Media
- ...and more!

### 📊 Interactive HTML Dashboard
Exports all findings into a sleek, color-coded, and searchable HTML dashboard. Features include:
- **Live search filter** across all sections
- **One-click copy** to clipboard
- **Export-to-PDF** button
- **Color-coded modules** (Cyan, Purple, Orange, Teal, Yellow, Red)
- **Security alerts** for missing SPF/DMARC

## 📋 Module Overview

| Module | Source / Tool | Data Collected |
|--------|--------------|----------------|
| Subdomain Enum | crt.sh → AlienVault OTX → HackerTarget | Passive subdomains via certificate transparency & DNS |
| WHOIS Intel | `whois` | Registrar, org, dates, nameservers, DNSSEC |
| DNS Record Map | `dig` | A, AAAA, MX, NS, TXT, SOA, CNAME + SPF/DMARC analysis |
| Email Harvesting | `theHarvester` | Emails, hostnames, IPs from 7 passive sources |
| Reverse IP | HackerTarget API | Co-hosted domains on the same IP |
| Wayback Machine | web.archive.org CDX API | Archived sensitive files |
| Shodan Intel | internetdb.shodan.io | Open ports + known CVEs |
| Google Dorks | Generated locally | 130+ categorized dork queries |

## ⚙️ Prerequisites

### Python
This project requires **Python 3.x** and the `requests` library:

```bash
pip install requests
```

### Kali Linux Tools (Recommended)
For full functionality, the following tools should be installed. These come **pre-installed on Kali Linux**:

| Tool | Purpose | Install Command |
|------|---------|-----------------|
| `whois` | WHOIS domain lookups | `sudo apt install whois` |
| `dig` | DNS record enumeration | `sudo apt install dnsutils` |
| `theHarvester` | Email & host harvesting | `sudo apt install theharvester` |

> **Note:** If any tool is not found, GhostDorks will gracefully skip that module and continue with the remaining scans.

## 🚀 Usage

Run the script from the command line and specify the target domain using the `-d` or `--domain` argument:

```bash
python ghostdorks.py -d target.com
```

### Example

```bash
python ghostdorks.py -d example.com
```

Once the scan is complete, the tool will generate an HTML file named `ghost_dorks_example_com.html` in your current working directory. Simply open this file in any modern web browser to view and interact with your intelligence dashboard.

### Sample Output

```
[*] Querying crt.sh for subdomains of example.com...
[+] Successfully extracted 42 unique subdomains from crt.sh.
[*] Running WHOIS lookup for example.com...
[+] WHOIS data retrieved. Registrar: MarkMonitor Inc., Nameservers: 2
[*] Querying DNS records for example.com...
[+] DNS enumeration complete. 12 total records found.
    ⚠️ No DMARC record found — phishing risk
[*] Running theHarvester for email/host enumeration on example.com...
[+] theHarvester found: 5 emails, 18 hosts, 3 IPs
[*] Running reverse IP lookup for 93.184.216.34...
[+] Found 7 domains co-hosted on 93.184.216.34.
[*] Querying Wayback Machine for exposed files on example.com...
[+] Successfully extracted 23 archived URLs from Wayback Machine.
[*] Querying Shodan InternetDB for ports on 93.184.216.34...
[+] Found 4 open ports and 2 vulnerabilities.

[+] Ghost Dashboard Generated: ghost_dorks_example_com.html
```

## ⚠️ Disclaimer

This tool is intended for **educational purposes and authorized security auditing only**. The developers and contributors assume no liability and are not responsible for any misuse or damage caused by this program. Always ensure you have explicit, written permission from the owner before testing a target.

## 👨‍💻 Credits

Created by: **L4ZYG33K**
