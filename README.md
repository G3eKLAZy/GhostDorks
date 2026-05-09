# 🕵️ PROJECT GHOST ENGINE (GhostDorks)

## 📖 Description
**Project Ghost Engine** is an advanced, automated OSINT (Open Source Intelligence) and reconnaissance tool designed for security researchers, bug bounty hunters, and penetration testers. It aggregates data from various passive sources and generates a highly interactive, standalone HTML dashboard tailored to a specific target domain.

The tool combines passive DNS enumeration, archived file discovery, IP port scanning, and an extensive list of categorized Google Dorks to provide a comprehensive attack surface map—all without sending aggressive or noisy requests directly to the target infrastructure.

## ✨ Features
- **Passive Subdomain Enumeration**: Implements a highly resilient triple-redundant fallback system querying `crt.sh`, `AlienVault OTX`, and `HackerTarget`.
- **Archived Data Discovery**: Interrogates the Wayback Machine to uncover exposed sensitive files (e.g., `.env`, `.sql`, `.bak`, `.json`, `.pem`).
- **Vulnerability & Port Scanning**: Utilizes the free Shodan InternetDB API to map open ports and known CVEs associated with the target's resolved IP address.
- **Dynamic Google Dorks Map**: Automatically generates a robust, clickable list of Google Dorks customized for the target domain. Categories include:
  - Subdomain Enum & Takeover
  - Directory & File Exposure
  - Secrets, Configs & Leaks
  - Admin Panels
  - APIs & Swagger Docs
  - Cloud Storage (S3, GCP, Azure)
  - ...and more!
- **Interactive HTML Dashboard**: Exports all findings into a sleek, responsive, and searchable HTML dashboard. Features include a live search filter, one-click copy functionality, and an export-to-PDF button.

## ⚙️ Prerequisites
This project requires Python 3.x. Ensure you have the `requests` library installed:

```bash
pip install requests
```

## 🚀 Usage

Run the script from the command line and specify the target domain using the `-d` or `--domain` argument.

```bash
python ghostdorks.py -d target.com
```

### Example
```bash
python ghostdorks.py -d example.com
```

Once the scan is complete, the tool will generate an HTML file named `ghost_dorks_example_com.html` in your current working directory. Simply open this file in any modern web browser to view and interact with your intelligence dashboard.

## ⚠️ Disclaimer
This tool is intended for educational purposes and authorized security auditing only. The developers and contributors assume no liability and are not responsible for any misuse or damage caused by this program. Always ensure you have explicit, written permission from the owner before testing a target.

## 👨💻 Credits
Created by: **L4ZYG33K**
                          
