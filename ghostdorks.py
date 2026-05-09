import os
import urllib.parse
import html
import argparse
import requests
import socket

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
    
    # 1. Active Data Fetching (Subdomains & Wayback)
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
            :root {{ --main-green: #00ff41; --bg-black: #0d0d0d; --card-bg: #1a1a1a; --blue: #00ccff; --wayback-yellow: #ffb800; --shodan-red: #ff3333; }}
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
                    Passive Subdomains Discovered: <strong style="color: var(--main-green);">{len(discovered_subdomains)}</strong><br>
                    Juicy files discovered via Wayback Machine: <strong style="color: var(--wayback-yellow);">{len(discovered_wayback_urls)}</strong><br>
                    Open Ports (Shodan): <strong style="color: var(--shodan-red);">{len(open_ports)}</strong> | Vulnerabilities: <strong style="color: var(--shodan-red);">{len(vulns)}</strong>
                </div>
            </header>

            <div class="controls">
                <input type="text" class="search-box" id="searchInput" placeholder="Filter by keyword (e.g. 'sql', 'env', 'login')...">
                <button class="btn" onclick="window.print()">Export PDF</button>
            </div>

            <div id="dorkContainer">
    """

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