#!/usr/bin/env python3
"""
================================================================================
GHOSTRECON v2 — Unified OSINT & cPanel/WHM Reconnaissance Engine
Created by: L4ZYG33K | Project Ghost Dork Engine 
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
  • DorkEye-inspired Dork Engine (DDGS search, YAML templates, analysis)

Active Modules (--active):
  • dnsx resolution + takeover detection
  • naabu port scan
  • httpx probing (title/server/tech/TLS)
  • katana active crawl
  • nuclei vulnerability scan
  • arjun (hidden parameter discovery)
  • cPanel CVE-2026-41940 Remote Probe (WHM only)

Usage:
  python ghostreconv2.py -d example.com
  python ghostreconv2.py -d example.com --active
  python ghostreconv2.py -d example.com --active --nuclei --cpanel-probe --gf --arjun --subjack
  python ghostreconv2.py -d example.com --dork-stealth --dg-categories sqli,osint,files
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
import hashlib
import pickle
import threading
import queue
from urllib.parse import urlparse
from datetime import datetime

# ─────────────────────────────────────────────
# Optional DorkEye Dependencies
# ─────────────────────────────────────────────

try:
    from ddgs import DDGS
    DDGS_AVAILABLE = True
except ImportError:
    DDGS_AVAILABLE = False
    print("[!] ddgs not installed. Dork engine will fall back to static Google URLs.")
    print("    Install: pip install ddgs")

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

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
# DorkEye-inspired Dork Engine
# ─────────────────────────────────────────────

DORK_TEMPLATES_YAML = """
categories:
  sqli:
    name: "SQL Injection Dorks"
    description: "Dorks targeting SQL injection vulnerabilities"
    templates:
      - 'site:{target} inurl:id='
      - 'site:{target} inurl:page='
      - 'site:{target} inurl:cat='
      - 'site:{target} inurl:product='
      - 'site:{target} inurl:item='
      - 'site:{target} inurl:article='
      - 'site:{target} inurl:news='
      - 'site:{target} inurl:view='
      - 'site:{target} ext:php inurl:?'
      - 'site:{target} ext:asp inurl:?'
      - 'site:{target} ext:jsp inurl:?'
      - 'site:{target} inurl:search.php?q='
      - 'site:{target} inurl:login.php?user='
      - 'site:{target} inurl:index.php?id='
      - 'site:{target} inurl:product.php?id='
      - 'site:{target} inurl:category.php?id='
      - 'site:{target} inurl:page.php?id='
      - 'site:{target} inurl:news.php?id='
      - 'site:{target} inurl:article.php?id='
      - 'site:{target} inurl:gallery.php?id='
      - 'site:{target} inurl:event.php?id='
      - 'site:{target} inurl:train.php?id='
      - 'site:{target} inurl:buy.php?category='
      - 'site:{target} inurl:pageid='
      - 'site:{target} inurl:page_id='

  xss:
    name: "XSS Dorks"
    description: "Dorks targeting Cross-Site Scripting vulnerabilities"
    templates:
      - 'site:{target} inurl:q='
      - 'site:{target} inurl:s='
      - 'site:{target} inurl:search='
      - 'site:{target} inurl:keyword='
      - 'site:{target} inurl:query='
      - 'site:{target} inurl:tag='
      - 'site:{target} inurl:comment='
      - 'site:{target} inurl:feedback='
      - 'site:{target} inurl:name='
      - 'site:{target} inurl:message='
      - 'site:{target} inurl:body='
      - 'site:{target} inurl:post='
      - 'site:{target} inurl:reply='
      - 'site:{target} inurl:forum'
      - 'site:{target} inurl:guestbook'
      - 'site:{target} inurl:contact'
      - 'site:{target} inurl:subscribe'
      - 'site:{target} inurl:register'
      - 'site:{target} inurl:signup'
      - 'site:{target} inurl:query='

  lfi_rfi:
    name: "LFI/RFI Dorks"
    description: "Local/Remote File Inclusion dorks"
    templates:
      - 'site:{target} inurl:file='
      - 'site:{target} inurl:page='
      - 'site:{target} inurl:path='
      - 'site:{target} inurl:folder='
      - 'site:{target} inurl:directory='
      - 'site:{target} inurl:doc='
      - 'site:{target} inurl:document='
      - 'site:{target} inurl:site='
      - 'site:{target} inurl:include='
      - 'site:{target} inurl:locate='
      - 'site:{target} inurl:show='
      - 'site:{target} inurl:view='
      - 'site:{target} inurl:load='
      - 'site:{target} inurl:download='
      - 'site:{target} inurl:path=..'
      - 'site:{target} inurl:file=..'
      - 'site:{target} inurl:page=..'
      - 'site:{target} inurl:folder=..'

  redirect:
    name: "Open Redirect Dorks"
    description: "Open redirect vulnerability dorks"
    templates:
      - 'site:{target} inurl:url='
      - 'site:{target} inurl:return='
      - 'site:{target} inurl:next='
      - 'site:{target} inurl:redirect='
      - 'site:{target} inurl:redir='
      - 'site:{target} inurl:return_url='
      - 'site:{target} inurl:return_to='
      - 'site:{target} inurl:r='
      - 'site:{target} inurl:goto='
      - 'site:{target} inurl:link='
      - 'site:{target} inurl:target='
      - 'site:{target} inurl:dest='
      - 'site:{target} inurl:destination='
      - 'site:{target} inurl:forward='
      - 'site:{target} inurl:jump='
      - 'site:{target} inurl:out='
      - 'site:{target} inurl:view='

  ssrf:
    name: "SSRF Dorks"
    description: "Server-Side Request Forgery dorks"
    templates:
      - 'site:{target} inurl:proxy='
      - 'site:{target} inurl:fetch='
      - 'site:{target} inurl:request='
      - 'site:{target} inurl:curl='
      - 'site:{target} inurl:import='
      - 'site:{target} inurl:load='
      - 'site:{target} inurl:read='
      - 'site:{target} inurl:url='
      - 'site:{target} inurl:uri='
      - 'site:{target} inurl:path='
      - 'site:{target} inurl:dest='
      - 'site:{target} inurl:continue='
      - 'site:{target} inurl:window='
      - 'site:{target} inurl:next='
      - 'site:{target} inurl:callback='

  files:
    name: "Directory & File Exposure"
    description: "Exposed directories and sensitive files"
    templates:
      - 'intitle:"index of" site:{target}'
      - 'intitle:"index of /backup" site:{target}'
      - 'intitle:"index of /admin" site:{target}'
      - 'intitle:"index of /config" site:{target}'
      - 'intitle:"index of /database" site:{target}'
      - 'intitle:"index of /logs" site:{target}'
      - 'inurl:/db_backup OR inurl:/database_backup site:{target}'
      - 'ext:sql | ext:dbf | ext:mdb | ext:ora site:{target}'
      - 'filetype:log site:{target}'
      - 'inurl:wp-config.php site:{target}'
      - 'inurl:/.env site:{target}'
      - 'intitle:"index of" +passwd site:{target}'
      - 'intitle:"index of" +git site:{target}'
      - 'intitle:"index of" +config site:{target}'
      - 'inurl:sitemap.xml site:{target}'
      - 'inurl:robots.txt site:{target}'
      - 'intitle:"index of" +sql site:{target}'
      - 'intitle:"index of" +backup site:{target}'
      - 'inurl:/backup/ site:{target}'
      - 'inurl:/dump/ site:{target}'
      - 'inurl:/logs/ site:{target}'
      - 'inurl:/temp/ site:{target}'
      - 'inurl:/tmp/ site:{target}'
      - 'inurl:/old/ site:{target}'
      - 'inurl:/test/ site:{target}'
      - 'inurl:/dev/ site:{target}'
      - 'inurl:/staging/ site:{target}'
      - 'inurl:/archive/ site:{target}'
      - 'inurl:/data/ site:{target}'
      - 'inurl:/uploads/ site:{target}'
      - 'ext:bak | ext:backup | ext:old | ext:save | ext:swp site:{target}'
      - 'ext:zip | ext:tar | ext:gz | ext:rar | ext:7z site:{target}'
      - 'ext:sql | ext:dump | ext:db | ext:sqlite site:{target}'

  secrets:
    name: "Secrets & Configs"
    description: "Exposed secrets, API keys, and configuration files"
    templates:
      - 'ext:env | ext:.env site:{target}'
      - 'intext:"DB_PASSWORD" site:{target}'
      - 'intext:"AWS_ACCESS_KEY_ID" site:{target}'
      - 'filetype:json "api_key" site:{target}'
      - 'inurl:.git/config site:{target}'
      - 'intext:"DATABASE_URL" site:{target}'
      - 'intext:"SLACK_BOT_TOKEN" site:{target}'
      - 'ext:key site:{target}'
      - 'ext:pem site:{target}'
      - 'intext:"BEGIN RSA PRIVATE" site:{target}'
      - 'filetype:pfx site:{target}'
      - 'intext:"password" filetype:xml site:{target}'
      - 'intext:"secret" filetype:conf site:{target}'
      - 'intext:"token" filetype:json site:{target}'
      - 'intext:"api_secret" site:{target}'
      - 'intext:"client_secret" site:{target}'
      - 'inurl:.env.{target}'
      - 'intext:"-----BEGIN OPENSSH PRIVATE KEY-----" site:{target}'
      - 'intext:"-----BEGIN PGP PRIVATE KEY BLOCK-----" site:{target}'
      - 'intext:"-----BEGIN PRIVATE KEY-----" site:{target}'
      - 'intext:"AKIA" site:{target}'
      - 'intext:"ghp_" site:{target}'
      - 'intext:"glpat-" site:{target}'
      - 'intext:"sk-" site:{target}'
      - 'intext:"Bearer " site:{target}'
      - 'filetype:properties site:{target}'
      - 'filetype:yaml | filetype:yml site:{target}'
      - 'filetype:toml site:{target}'
      - 'filetype:ini site:{target}'
      - 'filetype:cfg site:{target}'

  admin:
    name: "Admin Panels & Auth"
    description: "Administrative interfaces and authentication portals"
    templates:
      - 'inurl:admin/login.php site:{target}'
      - 'inurl:wp-login.php site:{target}'
      - 'intitle:"admin panel" | intitle:"control panel" site:{target}'
      - 'intitle:"phpMyAdmin" site:{target}'
      - 'inurl:cpanel site:{target}'
      - 'intitle:"Jenkins" site:{target}'
      - 'intitle:"Citrix" site:{target}'
      - 'inurl:login site:{target}'
      - 'inurl:signin site:{target}'
      - 'inurl:dashboard site:{target}'
      - 'inurl:portal site:{target}'
      - 'inurl:administrator site:{target}'
      - 'intitle:"login" "password" site:{target}'
      - 'inurl:auth site:{target}'
      - 'inurl:oauth site:{target}'
      - 'inurl:saml site:{target}'
      - 'inurl:admin.php site:{target}'
      - 'inurl:admin.asp site:{target}'
      - 'inurl:admin.jsp site:{target}'
      - 'inurl:admin.html site:{target}'
      - 'inurl:admin.cgi site:{target}'
      - 'inurl:manage site:{target}'
      - 'inurl:manager site:{target}'
      - 'inurl:moderator site:{target}'
      - 'inurl:webadmin site:{target}'
      - 'inurl:control site:{target}'
      - 'inurl:panel site:{target}'
      - 'intitle:"cPanel" site:{target}'
      - 'intitle:"WebHost Manager" site:{target}'

  vuln:
    name: "Vulnerable Files & Errors"
    description: "Known vulnerable files and error disclosures"
    templates:
      - 'intitle:"phpinfo()" site:{target}'
      - 'inurl:/vendor/ site:{target}'
      - 'intext:"sql syntax error" site:{target}'
      - 'intext:"Warning: include" site:{target}'
      - 'inurl:phpshell site:{target}'
      - 'inurl:webshell site:{target}'
      - 'inurl:backdoor site:{target}'
      - 'intext:"Fatal error" site:{target}'
      - 'intext:"Stack trace" site:{target}'
      - 'intext:"syntax error" site:{target}'
      - 'intext:"Connection refused" site:{target}'
      - 'intext:"403 Forbidden" site:{target}'
      - 'intitle:"Apache2 Ubuntu Default Page" site:{target}'
      - 'intitle:"IIS Windows Server" site:{target}'
      - 'intitle:"Welcome to nginx" site:{target}'
      - 'inurl:phpmyadmin site:{target}'
      - 'inurl:adminer.php site:{target}'
      - 'inurl:elFinder site:{target}'
      - 'inurl:fckeditor site:{target}'
      - 'inurl:ckeditor site:{target}'
      - 'inurl:tinymce site:{target}'
      - 'intitle:"Swagger UI" site:{target}'
      - 'inurl:api-docs site:{target}'
      - 'inurl:swagger.json site:{target}'
      - 'inurl:graphql site:{target}'
      - 'inurl:openapi.json site:{target}'

  api:
    name: "APIs & Documentation"
    description: "API endpoints and documentation interfaces"
    templates:
      - 'inurl:api/ | inurl:rest/ | inurl:v1/ site:{target}'
      - 'inurl:swagger | inurl:redoc site:{target}'
      - 'site:*.{target} (inurl:swagger OR inurl:api-docs)'
      - 'inurl:graphql site:{target}'
      - 'inurl:openapi.json site:{target}'
      - 'inurl:api-docs site:{target}'
      - 'inurl:postman site:{target}'
      - 'intitle:"Swagger UI" site:{target}'
      - 'intext:"paths" "swagger" site:{target}'
      - 'inurl:/api/v1/ site:{target}'
      - 'inurl:/api/v2/ site:{target}'
      - 'inurl:/rest/ site:{target}'
      - 'inurl:/graphql/ site:{target}'
      - 'inurl:/soap/ site:{target}'
      - 'inurl:/wsdl site:{target}'
      - 'inurl:/odata site:{target}'
      - 'inurl:/graphql site:{target}'
      - 'inurl:/graphiql site:{target}'
      - 'inurl:/playground site:{target}'
      - 'inurl:/altair site:{target}'
      - 'filetype:wsdl site:{target}'
      - 'filetype:xsd site:{target}'

  errors:
    name: "Error & Debug Leaks"
    description: "Error messages and debug information leaks"
    templates:
      - 'intext:"Warning: mysql" site:{target}'
      - 'intext:"Stack trace" site:{target}'
      - 'intext:"Fatal error" site:{target}'
      - 'intext:"syntax error" site:{target}'
      - 'intext:"Connection refused" site:{target}'
      - 'intext:"403 Forbidden" site:{target}'
      - 'intext:"500 Internal Server Error" site:{target}'
      - 'intext:"Debug mode" site:{target}'
      - 'intext:"Traceback" site:{target}'
      - 'intext:"Exception" site:{target}'
      - 'intext:"NullPointerException" site:{target}'
      - 'intext:"django" "debug" site:{target}'
      - 'intext:"laravel" "debug" site:{target}'
      - 'intext:"symfony" "debug" site:{target}'
      - 'intext:"php error" site:{target}'
      - 'intext:"ASP.NET" "error" site:{target}'
      - 'intext:"ODBC" "error" site:{target}'
      - 'intext:"DB2" "error" site:{target}'
      - 'intext:"Oracle" "error" site:{target}'
      - 'intext:"PostgreSQL" "error" site:{target}'

  docs:
    name: "Documents & Leaks"
    description: "Exposed documents and potential data leaks"
    templates:
      - 'filetype:pdf site:{target}'
      - 'filetype:doc | filetype:docx site:{target}'
      - 'filetype:xls | filetype:xlsx site:{target}'
      - 'intext:"confidential" site:{target}'
      - 'intext:"internal use only" site:{target}'
      - 'site:{target} "employee handbook" filetype:pdf'
      - 'intext:"password" filetype:xls site:{target}'
      - 'intext:"classified" site:{target}'
      - 'intext:"proprietary" site:{target}'
      - 'intext:"NDA" site:{target}'
      - 'intext:"do not distribute" site:{target}'
      - 'filetype:ppt | filetype:pptx site:{target}'
      - 'filetype:csv site:{target}'
      - 'filetype:txt site:{target}'
      - 'filetype:rtf site:{target}'
      - 'filetype:odt site:{target}'
      - 'filetype:ods site:{target}'
      - 'intext:"budget" filetype:xls site:{target}'
      - 'intext:"invoice" filetype:pdf site:{target}'
      - 'intext:"contract" filetype:pdf site:{target}'
      - 'intext:"agreement" filetype:pdf site:{target}'

  paste_git:
    name: "Paste & Git Leaks"
    description: "Pastebin and code repository leaks"
    templates:
      - 'site:pastebin.com "{target}"'
      - 'site:github.com "{target}" intext:"password"'
      - 'site:*.stackexchange.com {target} password'
      - 'site:gist.github.com {target}'
      - 'site:github.com "{target}" "api_key"'
      - 'site:github.com "{target}" "secret"'
      - 'site:github.com "{target}" "token"'
      - 'site:gitlab.com "{target}"'
      - 'site:bitbucket.org "{target}"'
      - 'site:pastebin.com "{target}" password'
      - 'site:controlc.com "{target}"'
      - 'site:ideone.com "{target}"'
      - 'site:pastebin.com "{target}" api'
      - 'site:github.com "{target}" config'
      - 'site:github.com "{target}" credentials'
      - 'site:github.com "{target}" database'
      - 'site:github.com "{target}" backup'
      - 'site:github.com "{target}" dump'

  takeover:
    name: "Takeover & Third-Party"
    description: "Subdomain takeover and third-party service indicators"
    templates:
      - 'inurl:herokuapp.com site:{target}'
      - 'inurl:*.cloudfront.net site:{target}'
      - 'inurl:github.io {target}'
      - 'inurl:s3.amazonaws.com {target}'
      - 'inurl:azurewebsites.net site:{target}'
      - 'inurl:firebaseapp.com site:{target}'
      - 'inurl:netlify.app site:{target}'
      - 'inurl:vercel.app site:{target}'
      - 'inurl:fastly.net site:{target}'
      - 'inurl:bitbucket.io site:{target}'
      - 'inurl:repl.co site:{target}'
      - 'inurl:glitch.me site:{target}'
      - 'inurl:webflow.io site:{target}'
      - 'inurl:readme.io site:{target}'
      - 'inurl:surge.sh site:{target}'
      - 'inurl:pantheon.io site:{target}'
      - 'inurl:ghost.io site:{target}'
      - 'inurl:wordpress.com site:{target}'
      - 'inurl:tumblr.com site:{target}'
      - 'inurl:shopify.com site:{target}'

  cloud:
    name: "Cloud Storage & Buckets"
    description: "Exposed cloud storage and S3 buckets"
    templates:
      - 'site:s3.amazonaws.com "{target}"'
      - 'site:storage.googleapis.com {target}'
      - 'site:blob.core.windows.net {target}'
      - 'inurl:bucket site:{target}'
      - 'site:s3.amazonaws.com "{target}" "index of"'
      - 'site:storage.googleapis.com "{target}"'
      - 'site:amazonaws.com "{target}"'
      - 'site:cloudfront.net "{target}"'
      - 'inurl:s3.amazonaws.com inurl:{target}'
      - 'inurl:googleapis.com inurl:{target}'
      - 'intext:"bucket" "{target}" site:amazonaws.com'
      - 'site:s3.amazonaws.com "{target}" ext:log'
      - 'site:s3.amazonaws.com "{target}" ext:sql'
      - 'site:s3.amazonaws.com "{target}" ext:json'
      - 'site:s3.amazonaws.com "{target}" ext:xml'
      - 'site:s3.amazonaws.com "{target}" ext:csv'
      - 'site:s3.amazonaws.com "{target}" ext:txt'
      - 'site:s3.amazonaws.com "{target}" ext:pdf'
      - 'site:s3.amazonaws.com "{target}" ext:backup'

  dev:
    name: "Dev / Test / Staging"
    description: "Development and staging environment exposure"
    templates:
      - 'site:{target} inurl:staging'
      - 'site:{target} inurl:dev'
      - 'site:{target} inurl:test'
      - 'site:{target} inurl:sandbox'
      - 'site:{target} inurl:localhost'
      - 'site:{target} inurl:beta'
      - 'site:{target} inurl:alpha'
      - 'site:{target} inurl:qa'
      - 'site:{target} inurl:uat'
      - 'site:{target} inurl:preprod'
      - 'site:{target} inurl:preview'
      - 'site:{target} inurl:demo'
      - 'site:dev.{target}'
      - 'site:staging.{target}'
      - 'site:test.{target}'
      - 'site:beta.{target}'
      - 'site:alpha.{target}'
      - 'site:qa.{target}'
      - 'site:uat.{target}'
      - 'site:preprod.{target}'
      - 'site:{target} inurl:debug'
      - 'site:{target} inurl:console'
      - 'site:{target} inurl:phpinfo'

  social:
    name: "Social & Employee Intel"
    description: "Social media and employee intelligence gathering"
    templates:
      - 'site:linkedin.com/in/ "{target}"'
      - 'site:linkedin.com "{target}" (engineer OR admin)'
      - 'site:twitter.com {target}'
      - '"@{target}" site:twitter.com'
      - 'site:facebook.com "{target}"'
      - 'site:instagram.com "{target}"'
      - 'site:youtube.com "{target}"'
      - 'site:reddit.com "{target}"'
      - 'site:medium.com "{target}"'
      - 'site:about.me "{target}"'
      - 'site:xing.com "{target}"'
      - 'site:glassdoor.com "{target}"'
      - 'site:indeed.com "{target}"'
      - 'site:angel.co "{target}"'
      - 'site:crunchbase.com "{target}"'

  cpanel_hosting:
    name: "cPanel/WHM & Hosting"
    description: "cPanel, WHM, and hosting control panel exposure"
    templates:
      - 'inurl:cpanel site:{target}'
      - 'inurl:whm site:{target}'
      - 'inurl:webmail site:{target}'
      - 'inurl:roundcube site:{target}'
      - 'inurl:squirrelmail site:{target}'
      - 'inurl:horde site:{target}'
      - 'inurl:2083 site:{target}'
      - 'inurl:2087 site:{target}'
      - 'intitle:"cPanel" site:{target}'
      - 'intitle:"WebHost Manager" site:{target}'
      - 'inurl:2095 site:{target}'
      - 'inurl:2096 site:{target}'
      - 'inurl:2082 site:{target}'
      - 'inurl:2086 site:{target}'
      - 'inurl:cpanelsite:{target}'

  database:
    name: "Database & Backup Leaks"
    description: "Database files and backup exposure"
    templates:
      - 'ext:sql site:{target}'
      - 'ext:dump site:{target}'
      - 'ext:bak site:{target}'
      - 'ext:backup site:{target}'
      - 'ext:mdb site:{target}'
      - 'ext:sqlite site:{target}'
      - 'ext:db site:{target}'
      - 'inurl:phpmyadmin site:{target}'
      - 'inurl:adminer site:{target}'
      - 'intext:"database dump" site:{target}'
      - 'intext:"mysql dump" site:{target}'
      - 'intext:"pg_dump" site:{target}'
      - 'intext:"mongodb" "dump" site:{target}'
      - 'ext:sql.gz site:{target}'
      - 'ext:sql.zip site:{target}'
      - 'ext:sql.tar site:{target}'
      - 'ext:sql.tar.gz site:{target}'
      - 'ext:dump.gz site:{target}'
      - 'ext:dump.zip site:{target}'
      - 'ext:backup.gz site:{target}'
      - 'ext:backup.zip site:{target}'

  iot:
    name: "IoT & Network Devices"
    description: "IoT devices and network infrastructure"
    templates:
      - 'intitle:"Router" site:{target}'
      - 'intitle:"Switch" site:{target}'
      - 'intitle:"Firewall" site:{target}'
      - 'intitle:"VPN" site:{target}'
      - 'intitle:"Network Camera" site:{target}'
      - 'intitle:"Webcam" site:{target}'
      - 'inurl:axis-cgi site:{target}'
      - 'intitle:"Live View / - AXIS" site:{target}'
      - 'inurl:viewerframe?mode= site:{target}'
      - 'intitle:"DVR" site:{target}'
      - 'intitle:"NAS" site:{target}'
      - 'inurl:printer site:{target}'
      - 'intitle:"Print Server" site:{target}'
      - 'intitle:"Network Printer" site:{target}'
      - 'inurl:hp/device site:{target}'
      - 'inurl:brother/device site:{target}'
      - 'intitle:"Canon" "Network" site:{target}'

  cms:
    name: "CMS & Framework Fingerprints"
    description: "Content management system and framework identification"
    templates:
      - 'inurl:/wp-content/ site:{target}'
      - 'inurl:/wp-includes/ site:{target}'
      - 'inurl:/wp-admin/ site:{target}'
      - 'inurl:wp-config.php site:{target}'
      - 'inurl:/administrator/ site:{target}'
      - 'inurl:/components/ site:{target}'
      - 'inurl:/modules/ site:{target}'
      - 'inurl:/sites/default/ site:{target}'
      - 'inurl:/node/ site:{target}'
      - 'inurl:/misc/ site:{target}'
      - 'inurl:/skin/ site:{target}'
      - 'inurl:/app/etc/ site:{target}'
      - 'inurl:/skin/frontend/ site:{target}'
      - 'inurl:/catalog/ site:{target}'
      - 'inurl:/media/ site:{target}'
      - 'intitle:"Magento Admin" site:{target}'
      - 'intitle:"WordPress" "Installation" site:{target}'
      - 'intitle:"Joomla" "Installation" site:{target}'
      - 'intitle:"Drupal" "Installation" site:{target}'
      - 'inurl:/install.php site:{target}'
      - 'inurl:/setup.php site:{target}'
      - 'inurl:/config.php site:{target}'

  osint:
    name: "OSINT & Reconnaissance"
    description: "General open source intelligence gathering"
    templates:
      - 'site:{target} "phone number"'
      - 'site:{target} "contact us"'
      - 'site:{target} "about us"'
      - 'site:{target} "team"'
      - 'site:{target} "careers"'
      - 'site:{target} "partners"'
      - 'site:{target} "investors"'
      - 'site:{target} "press release"'
      - 'site:{target} "annual report"'
      - 'site:{target} "financial report"'
      - 'site:{target} "quarterly report"'
      - 'site:{target} "earnings call"'
      - 'site:{target} "conference call"'
      - 'site:{target} "investor relations"'
      - 'site:{target} "corporate governance"'
      - 'site:{target} "board of directors"'
      - 'site:{target} "executive team"'
      - 'site:{target} "management team"'
      - 'site:{target} "org chart"'
      - 'site:{target} "organizational structure"'

  subdomain_recon:
    name: "Subdomain Recon"
    description: "Subdomain enumeration and discovery"
    templates:
      - 'site:*.{target}'
      - 'site:*.{target} -www'
      - '"@{target}" -site:www.{target} -site:{target}'
      - 'intitle:"index of" "parent directory" site:{target}'
      - 'inurl:dmarc domain={target}'
      - 'ext:txt {target} (vhost OR hostname OR nameserver)'
      - 'filetype:env {target}'
      - 'inurl:(admin | login | panel) site:*.{target}'
      - 'site:*.{target} inurl:api'
      - 'site:{target} inurl:staging'
      - 'site:{target} inurl:dev'
      - 'site:{target} inurl:test'
      - 'site:*.{target} inurl:*.api'
      - 'site:{target} inurl:mail'
      - 'site:{target} inurl:ftp'
      - 'site:{target} inurl:cdn'
      - 'allintitle:"index of/admin"'
      - 'allintitle:"index of/root"'
      - 'allintitle:restricted filetype:mail'
      - 'site:{target} inurl:vpn'
      - 'site:*.{target} inurl:portal'
      - 'site:*.{target} inurl:secure'
      - 'site:*.{target} inurl:private'
      - 'site:*.{target} inurl:internal'
      - 'site:*.{target} inurl:corp'
      - 'site:*.{target} inurl:intranet'
"""

# ─────────────────────────────────────────────
# Project Ghost Dork Pattern Library
# ─────────────────────────────────────────────

DORK_PATTERNS = {
    "pii": {
        "email": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        "phone": re.compile(r'(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}'),
        "ssn": re.compile(r'[0-9]{3}-[0-9]{2}-[0-9]{4}'),
        "credit_card": re.compile(r'(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})'),
    },
    "secrets": {
        "aws_key": re.compile(r'AKIA[0-9A-Z]{16}'),
        "github_token": re.compile(r'ghp_[a-zA-Z0-9]{36}'),
        "gitlab_token": re.compile(r'glpat-[a-zA-Z0-9\-]{20,22}'),
        "slack_token": re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'),
        "generic_api_key": re.compile(r'(?:api[_-]?key|apikey|api_key)["\'\s]*[:=]["\'\s]*[a-zA-Z0-9]{16,64}'),
        "private_key": re.compile(r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'),
        "jwt": re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'),
    },
    "vuln_indicators": {
        "sql_error": re.compile(r'(SQL syntax.*MySQL|Warning.*mysql_|MySQLSyntaxErrorException|valid MySQL result|check the manual that corresponds to your MySQL server version|MySqlClient\.|PostgreSQL.*ERROR|Warning.*pg_|valid PostgreSQL result|Npgsql\.|Driver.* SQL[\- ]*Server|OLE DB.* SQL Server|SQLServer JDBC|ODBC SQL Server Driver|SQLServer\.Net SqlClient Data Provider|Microsoft SQL Native Client error \'[0-9a-fx]{8}\'|SQLServer JDBC|com\.jnetdirect\.jsql|macromedia\.jdbc\.sqlserver|Zend_Db_Adapter_Sqlsrv|SQLSrv_Error|mssql_query\(|odbc_exec\(|SELECT .* FROM .* WHERE .*=)', re.I),
        "xss_indicator": re.compile(r'(<script[^>]*>[\s\S]*?</script>|<iframe[^>]*>[\s\S]*?</iframe>|javascript:|on\w+\s*=)', re.I),
        "lfi_indicator": re.compile(r'(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self/environ|/windows/system32|boot\.ini|win\.ini)', re.I),
        "rce_indicator": re.compile(r'(system\(|exec\(|passthru\(|shell_exec\(|proc_open\(|popen\(|eval\(|assert\(|backtick)', re.I),
    },
    "file_types": {
        "database": re.compile(r'\.(sql|sqlite|sqlite3|mdb|accdb|dbf|ora|dmp|dump)$', re.I),
        "backup": re.compile(r'\.(bak|backup|old|orig|save|swp|swo|~)$', re.I),
        "config": re.compile(r'\.(env|config|cfg|ini|properties|yaml|yml|toml|xml|json)$', re.I),
        "archive": re.compile(r'\.(zip|tar|gz|rar|7z|bz2|xz)$', re.I),
        "key": re.compile(r'\.(pem|key|pfx|p12|crt|cer|der)$', re.I),
        "log": re.compile(r'\.(log|logs|txt)$', re.I),
    }
}

# ─────────────────────────────────────────────
# DorkEngine Class (Project Ghost Dork Engine)
# ─────────────────────────────────────────────

class SessionCheckpoint:
    """DorkEye-inspired session checkpoint/resume system."""

    def __init__(self, session_id, checkpoint_dir=".checkpoints"):
        self.session_id = session_id
        self.checkpoint_dir = checkpoint_dir
        self.path = os.path.join(checkpoint_dir, f"{session_id}.pkl")
        os.makedirs(checkpoint_dir, exist_ok=True)

    def save(self, completed_dorks, results, stats):
        try:
            data = {
                "completed_dorks": completed_dorks,
                "results": results,
                "stats": stats,
                "saved_at": datetime.now().isoformat()
            }
            with open(self.path, "wb") as f:
                pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)
            return True
        except Exception:
            return False

    def load(self):
        try:
            if os.path.exists(self.path):
                with open(self.path, "rb") as f:
                    return pickle.load(f)
        except Exception:
            pass
        return None

    def delete(self):
        try:
            if os.path.exists(self.path):
                os.unlink(self.path)
        except Exception:
            pass


class DorkEngine:
    """
    Project Ghost dork engine with:
    - YAML template-based dork generation
    - DuckDuckGo search integration
    - Result deduplication
    - Pattern analysis
    - Checkpoint/resume
    - Stealth controls
    - Thread-safe producer/consumer search
    """

    def __init__(self, domain, categories=None, stealth=False, rate_limit=1000, 
                 max_results_per_dork=50, checkpoint=True, resume=False,
                 custom_templates=None):
        self.domain = domain
        self.categories = categories or []
        self.stealth = stealth
        self.rate_limit = rate_limit
        self.max_results_per_dork = max_results_per_dork
        self.use_checkpoint = checkpoint
        self.resume = resume
        self.custom_templates = custom_templates or {}

        self.results = []  # List of dicts: {"url", "title", "dork", "category", "patterns", "severity"}
        self.completed_dorks = set()
        self.url_hashes = set()
        self.stats = {"total_dorks": 0, "completed": 0, "urls_found": 0, "patterns_found": 0}

        self._skip_current = False
        self._exit_requested = False
        self._setup_signal_handlers()

        self.templates = self._load_templates()
        self.checkpoint = self._init_checkpoint()

    def _setup_signal_handlers(self):
        import signal
        def handler(signum, frame):
            if self._skip_current:
                self._exit_requested = True
                print("\n[!] Double interrupt detected. Exiting gracefully...")
            else:
                self._skip_current = True
                print("\n[!] Interrupt received. Skipping current dork... (Press Ctrl+C again to force exit)")
        signal.signal(signal.SIGINT, handler)

    def _init_checkpoint(self):
        if not self.use_checkpoint:
            return None
        # Deterministic session ID: MD5 of first 5 dorks + total count
        all_dorks = self._generate_all_dorks()
        session_seed = "".join([d for _, d in all_dorks[:5]]) + str(len(all_dorks))
        session_id = hashlib.md5(session_seed.encode()).hexdigest()[:16]
        cp = SessionCheckpoint(session_id)

        if self.resume:
            data = cp.load()
            if data:
                print(f"[+] Checkpoint found: {data.get('saved_at', 'unknown')}")
                print(f"[+] Resuming: {len(data.get('completed_dorks', []))}/{len(all_dorks)} dorks completed")
                self.completed_dorks = set(data.get("completed_dorks", []))
                self.results = data.get("results", [])
                self.stats = data.get("stats", self.stats)
                # Rebuild url_hashes
                for r in self.results:
                    self.url_hashes.add(hashlib.md5(r["url"].encode()).hexdigest())
            else:
                print("[-] No checkpoint found. Starting fresh session.")
        return cp

    def _load_templates(self):
        """Load templates from embedded YAML or custom dict."""
        templates = {}

        # Parse embedded YAML
        if YAML_AVAILABLE:
            try:
                data = yaml.safe_load(DORK_TEMPLATES_YAML)
                if data and "categories" in data:
                    templates = data["categories"]
            except Exception as e:
                print(f"[-] YAML parse error: {e}")
        else:
            # Manual parsing fallback
            templates = self._parse_templates_fallback()

        # Merge custom templates
        templates.update(self.custom_templates)
        return templates

    def _parse_templates_fallback(self):
        """Fallback parser when PyYAML is not available."""
        templates = {}
        current_cat = None
        current_data = {"name": "", "description": "", "templates": []}

        for line in DORK_TEMPLATES_YAML.split("\n"):
            line = line.rstrip()
            if line.startswith("categories:"):
                continue
            if not line or line.strip().startswith("#"):
                continue

            indent = len(line) - len(line.lstrip())

            if indent == 2 and line.strip().endswith(":"):
                if current_cat:
                    templates[current_cat] = current_data
                current_cat = line.strip()[:-1]
                current_data = {"name": current_cat, "description": "", "templates": []}

            elif indent == 4 and current_cat:
                if line.strip().startswith("name:"):
                    current_data["name"] = line.split(":", 1)[1].strip().strip('"')
                elif line.strip().startswith("description:"):
                    current_data["description"] = line.split(":", 1)[1].strip().strip('"')
                elif line.strip().startswith("templates:"):
                    pass

            elif indent >= 6 and current_cat:
                tmpl = line.strip().lstrip("-").strip().strip('"')
                if tmpl:
                    current_data["templates"].append(tmpl)

        if current_cat:
            templates[current_cat] = current_data

        return templates

    def _generate_all_dorks(self):
        """Generate complete dork list from templates."""
        dorks = []

        if not self.categories:
            # Use all categories
            cats = list(self.templates.keys())
        else:
            cats = [c for c in self.categories if c in self.templates]

        for cat in cats:
            cat_data = self.templates.get(cat, {})
            templates = cat_data.get("templates", [])
            for tmpl in templates:
                dork = tmpl.replace("{target}", self.domain)
                dorks.append((cat, dork))

        return dorks

    def _is_duplicate(self, url):
        url_hash = hashlib.md5(url.encode()).hexdigest()
        if url_hash in self.url_hashes:
            return True
        self.url_hashes.add(url_hash)
        return False

    def _analyze_url(self, url, title=""):
        """Analyze URL for patterns (PII, secrets, vuln indicators)."""
        patterns_found = []
        severity = "info"

        text = f"{url} {title}"

        # Check PII
        for pii_type, pattern in DORK_PATTERNS["pii"].items():
            if pattern.search(text):
                patterns_found.append(f"PII:{pii_type}")
                if severity == "info":
                    severity = "low"

        # Check secrets
        for sec_type, pattern in DORK_PATTERNS["secrets"].items():
            if pattern.search(text):
                patterns_found.append(f"SECRET:{sec_type}")
                severity = "high"

        # Check vuln indicators
        for vuln_type, pattern in DORK_PATTERNS["vuln_indicators"].items():
            if pattern.search(text):
                patterns_found.append(f"VULN:{vuln_type}")
                if vuln_type in ["sql_error", "rce_indicator"]:
                    severity = "critical"
                elif severity not in ["critical"]:
                    severity = "high"

        # Check file types
        for ftype, pattern in DORK_PATTERNS["file_types"].items():
            if pattern.search(url):
                patterns_found.append(f"FILE:{ftype}")
                if ftype in ["database", "backup", "key"]:
                    if severity not in ["critical", "high"]:
                        severity = "high"

        return patterns_found, severity

    def _interruptible_sleep(self, seconds, step=0.25):
        """Sleep in small steps; return immediately if skip/exit flagged."""
        elapsed = 0.0
        while elapsed < seconds:
            if self._exit_requested or self._skip_current:
                return
            time.sleep(min(step, seconds - elapsed))
            elapsed += step

    def _search_dork_ddgs(self, dork, category):
        """Search using DuckDuckGo (DorkEye-style thread-safe producer/consumer)."""
        urls = []
        if not DDGS_AVAILABLE:
            return urls

        result_queue = queue.Queue()
        _DONE = object()

        def producer():
            try:
                with DDGS() as ddgs:
                    for r in ddgs.text(dork, max_results=self.max_results_per_dork):
                        if self._exit_requested or self._skip_current:
                            break
                        result_queue.put(r)
            except Exception:
                pass
            finally:
                result_queue.put(_DONE)

        thread = threading.Thread(target=producer, daemon=True)
        thread.start()

        while True:
            if self._exit_requested or self._skip_current:
                break
            try:
                item = result_queue.get(timeout=0.25)
                if item is _DONE:
                    break
                if isinstance(item, dict):
                    url = item.get("href", "")
                    title = item.get("title", "")
                    if url and not self._is_duplicate(url):
                        urls.append((url, title))
            except queue.Empty:
                continue

        thread.join(timeout=2)
        return urls

    def _search_dork_fallback(self, dork, category):
        """Fallback: return Google search URL (static, no actual search)."""
        encoded = urllib.parse.quote_plus(dork)
        url = f"https://www.google.com/search?q={encoded}"
        return [(url, "Google Search (ddgs not installed)")]

    def search_dork(self, dork, category):
        """Search a single dork with deduplication and analysis."""
        if DDGS_AVAILABLE:
            raw_results = self._search_dork_ddgs(dork, category)
        else:
            raw_results = self._search_dork_fallback(dork, category)

        analyzed = []
        for url, title in raw_results:
            patterns, severity = self._analyze_url(url, title)
            analyzed.append({
                "url": url,
                "title": title,
                "dork": dork,
                "category": category,
                "patterns": patterns,
                "severity": severity
            })
            self.stats["patterns_found"] += len(patterns)

        self.stats["urls_found"] += len(analyzed)
        return analyzed

    def run(self):
        """Execute full dork search with checkpoint support."""
        all_dorks = self._generate_all_dorks()
        self.stats["total_dorks"] = len(all_dorks)

        print(f"[*] DorkEngine initialized: {len(all_dorks)} dorks across {len(self.templates)} categories")
        print(f"[*] Mode: {'STEALTH' if self.stealth else 'NORMAL'} | Rate: {self.rate_limit} | Max results/dork: {self.max_results_per_dork}")
        if self.use_checkpoint:
            print(f"[*] Checkpoint: {self.checkpoint.path if self.checkpoint else 'disabled'}")

        for idx, (category, dork) in enumerate(all_dorks, 1):
            if self._exit_requested:
                print("[!] Exit requested. Saving checkpoint and stopping.")
                break

            if dork in self.completed_dorks:
                continue

            print(f"\n[ Dork {idx}/{len(all_dorks)} ]  Ctrl+C -> skip  |  Double Ctrl+C -> quit")
            print(f"[*] Searching: {dork[:100]}...")

            self._skip_current = False

            try:
                results = self.search_dork(dork, category)
                self.results.extend(results)
                self.completed_dorks.add(dork)

                if results:
                    sev_counts = {}
                    for r in results:
                        sev_counts[r["severity"]] = sev_counts.get(r["severity"], 0) + 1
                    sev_str = ", ".join([f"{k}:{v}" for k, v in sorted(sev_counts.items())])
                    print(f"[+] Found {len(results)} results [{sev_str}]")
                else:
                    print(f"[-] No results")

            except Exception as e:
                print(f"[-] Error searching dork: {e}")

            # Save checkpoint after each dork
            if self.use_checkpoint and self.checkpoint:
                self.checkpoint.save(self.completed_dorks, self.results, self.stats)

            # Stealth delay
            if self.stealth and idx < len(all_dorks):
                delay = random.uniform(1.0, 3.0)
                print(f"[*] Stealth delay: {delay:.1f}s")
                self._interruptible_sleep(delay)

            self.stats["completed"] = len(self.completed_dorks)

        # Cleanup checkpoint on normal completion
        if self.use_checkpoint and self.checkpoint and not self._exit_requested:
            self.checkpoint.delete()

        print(f"\n[+] DorkEngine complete: {self.stats['completed']}/{self.stats['total_dorks']} dorks")
        print(f"[+] Total unique URLs: {self.stats['urls_found']} | Patterns: {self.stats['patterns_found']}")
        return self.results

    def get_dork_map(self):
        """Return dork map for dashboard (category -> list of dork strings)."""
        dork_map = {}
        all_dorks = self._generate_all_dorks()
        for cat, dork in all_dorks:
            if cat not in dork_map:
                dork_map[cat] = []
            dork_map[cat].append(dork)
        return dork_map

    def get_results_by_category(self):
        """Group results by category."""
        by_cat = {}
        for r in self.results:
            cat = r["category"]
            if cat not in by_cat:
                by_cat[cat] = []
            by_cat[cat].append(r)
        return by_cat

    def get_results_by_severity(self):
        """Group results by severity."""
        by_sev = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for r in self.results:
            sev = r.get("severity", "info")
            by_sev.setdefault(sev, []).append(r)
        return by_sev


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

    # DorkEngine config
    dork_stealth = cfg.get("dork_stealth", False)
    dork_categories = cfg.get("dork_categories", None)
    dork_max_results = cfg.get("dork_max_results", 50)
    dork_checkpoint = cfg.get("dork_checkpoint", True)
    dork_resume = cfg.get("dork_resume", False)

    safe_target = html.escape(target)

    print("\n" + "="*55)
    print("  PROJECT GHOST ENGINE - Unified Recon Pipeline v5.0")
    print("  DorkEye Dork Engine | gf | arjun | subjack | cPanel Triage")
    print("="*55)
    if active:
        print("  ACTIVE MODE enabled (naabu + httpx + katana)")
    if do_nuclei:
        print("  NUCLEI enabled - vulnerability scanning active")
    if cpanel_probe:
        print("  CPANEL PROBE enabled - CVE-2026-41940 active test")
    if do_gf:
        print("  GF enabled - pattern matching on endpoints")
    if do_arjun:
        print("  ARJUN enabled - hidden parameter discovery")
    if do_subjack:
        print("  SUBJACK enabled - subdomain takeover scanning")
    if dork_stealth:
        print("  DORK STEALTH enabled - slower, quieter dorking")
    print("="*55 + "\n")

    # Passive baseline
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

    # DorkEye-inspired Dork Engine
    print("\n" + "="*55)
    print("  DORK ENGINE (DorkEye-inspired)")
    print("="*55)
    dork_engine = DorkEngine(
        domain=target,
        categories=dork_categories,
        stealth=dork_stealth,
        rate_limit=rate,
        max_results_per_dork=dork_max_results,
        checkpoint=dork_checkpoint,
        resume=dork_resume
    )
    dork_results = dork_engine.run()
    dork_map = dork_engine.get_dork_map()
    dork_by_severity = dork_engine.get_results_by_severity()

    # subjack
    subjack_results = []
    if do_subjack:
        subjack_results = run_subjack(all_subdomains)

    # cPanel/WHM Detection
    cpanel_data = detect_cpanel_services(target, active_probe=cpanel_probe)

    # Active pipeline
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

    if do_gf:
        gf_results = run_gf(katana_endpoints, discovered_wayback_urls)

    if do_arjun and http_hosts:
        arjun_results = run_arjun(http_hosts)

    if do_nuclei:
        if not http_hosts and resolved_hosts:
            print("[*] --nuclei requires httpx; running httpx first...")
            http_hosts = run_httpx(resolved_hosts)
        nuclei_findings = run_nuclei(http_hosts, katana_endpoints=katana_endpoints, rate=150)

    # Build HTML
    html_content = build_html_dashboard(
        target, safe_target, target_ip, all_subdomains, resolved_hosts, 
        takeover_candidates, discovered_wayback_urls, open_ports, vulns,
        whois_info, dns_records, harvest_data, co_hosted_domains,
        naabu_results, http_hosts, katana_endpoints, gf_results,
        arjun_results, nuclei_findings, subjack_results, cpanel_data,
        dork_results, dork_engine, dork_map
    )

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
        "dork_engine_results": dork_results,
        "dork_engine_stats": dork_engine.stats,
        "generated_at": datetime.now().isoformat()
    }
    with open(json_filename, "w", encoding="utf-8") as jf:
        json.dump(summary, jf, indent=2)

    print(f"\n[+] Ghost Dashboard Generated : {filename}")
    print(f"[+] JSON Summary Saved        : {json_filename}")


def build_html_dashboard(target, safe_target, target_ip, all_subdomains, resolved_hosts,
                         takeover_candidates, discovered_wayback_urls, open_ports, vulns,
                         whois_info, dns_records, harvest_data, co_hosted_domains,
                         naabu_results, http_hosts, katana_endpoints, gf_results,
                         arjun_results, nuclei_findings, subjack_results, cpanel_data,
                         dork_results, dork_engine, dork_map):
    """Build the complete HTML dashboard."""

    # CSS
    css = """
    :root { --main-green: #00ff41; --bg-black: #0d0d0d; --card-bg: #1a1a1a; --blue: #00ccff; --wayback-yellow: #ffb800; --shodan-red: #ff3333; --whois-cyan: #00e5ff; --dns-purple: #b388ff; --harvest-orange: #ff9100; --reverse-teal: #1de9b6; --dnsx-lime: #c6ff00; --httpx-pink: #ff4081; --katana-sky: #40c4ff; --nuclei-crit: #ff1744; --nuclei-high: #ff6d00; --nuclei-med: #ffd600; --nuclei-low: #69f0ae; --cpanel-orange: #ff6f00; --cpanel-red: #d50000; --cpanel-amber: #ffab00; --gf-purple: #e040fb; --arjun-blue: #448aff; --subjack-red: #ff5252; --dork-cyan: #00e5ff; --dork-magenta: #ff00ff; }
    body { font-family: 'Courier New', monospace; background-color: var(--bg-black); color: var(--main-green); margin: 0; padding: 20px; }
    .container { max-width: 1200px; margin: auto; }
    header { border-bottom: 2px solid var(--main-green); padding-bottom: 20px; margin-bottom: 30px; text-align: center; }
    h1 { text-shadow: 0 0 15px var(--main-green); letter-spacing: 2px; margin-bottom: 5px; }
    .stats { color: #888; font-size: 14px; margin-top: 5px; line-height: 1.6; }
    .controls { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; justify-content: center; }
    .search-box { flex-grow: 1; padding: 12px; background: #111; border: 1px solid var(--main-green); color: var(--main-green); font-size: 16px; outline: none; }
    .btn { background: transparent; border: 1px solid var(--main-green); color: var(--main-green); padding: 10px 20px; cursor: pointer; transition: 0.3s; font-family: inherit; }
    .btn:hover { background: var(--main-green); color: black; font-weight: bold; }
    .category-section { margin-bottom: 30px; border: 1px solid #333; padding: 15px; border-radius: 5px; background: #0a0a0a; }
    h2 { color: #ff003c; font-size: 20px; margin-top: 0; border-bottom: 1px solid #222; padding-bottom: 10px; }
    .intel-table { width: 100%; border-collapse: collapse; font-size: 14px; }
    .intel-table td { padding: 8px 12px; border-bottom: 1px solid #222; vertical-align: top; }
    .intel-table td:first-child { color: #888; white-space: nowrap; width: 180px; font-weight: bold; }
    .intel-table td:last-child { color: #ddd; word-break: break-all; }
    .dns-badge { display: inline-block; padding: 3px 10px; margin: 3px; border-radius: 3px; font-size: 12px; border: 1px solid #333; }
    .security-note { color: var(--shodan-red); padding: 6px 10px; margin: 4px 0; font-size: 13px; background: rgba(255,51,51,0.1); border-left: 3px solid var(--shodan-red); }
    .email-chip { display: inline-block; padding: 5px 12px; margin: 3px; border-radius: 20px; font-size: 13px; background: rgba(255,145,0,0.15); border: 1px solid var(--harvest-orange); color: var(--harvest-orange); }
    .host-chip { display: inline-block; padding: 5px 12px; margin: 3px; border-radius: 20px; font-size: 13px; background: rgba(0,229,255,0.1); border: 1px solid var(--whois-cyan); color: var(--whois-cyan); }
    .sev-badge { display: inline-block; padding: 2px 10px; border-radius: 3px; font-size: 11px; font-weight: bold; margin-right: 8px; text-transform: uppercase; }
    .sev-critical { background: var(--nuclei-crit); color: #000; }
    .sev-high { background: var(--nuclei-high); color: #000; }
    .sev-medium { background: var(--nuclei-med); color: #000; }
    .sev-low { background: var(--nuclei-low); color: #000; }
    .sev-info { background: #444; color: #fff; }
    .finding-item { padding: 10px 12px; border-left: 3px solid #333; margin: 6px 0; background: #0d0d0d; }
    .httpx-row { display: grid; grid-template-columns: 60px 1fr 120px 1fr; gap: 8px; align-items: center; padding: 8px 12px; border-bottom: 1px solid #1a1a1a; font-size: 13px; }
    .httpx-row:hover { background: #111; }
    .status-2xx { color: #69f0ae; font-weight: bold; }
    .status-3xx { color: #ffb800; font-weight: bold; }
    .status-4xx { color: #ff9100; font-weight: bold; }
    .status-5xx { color: #ff1744; font-weight: bold; }
    .tech-pill { display: inline-block; padding: 2px 8px; margin: 2px; border-radius: 10px; font-size: 11px; background: rgba(64,196,255,0.15); border: 1px solid var(--katana-sky); color: var(--katana-sky); }
    .dork-list { display: grid; grid-template-columns: 1fr; gap: 8px; }
    .dork-item { background: #111; padding: 10px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; border: 1px solid #222; transition: 0.2s; }
    .dork-item:hover { border-color: #444; background: #151515; }
    .dork-text { color: var(--blue); text-decoration: none; font-size: 14px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex-grow: 1; margin-right: 15px; }
    .dork-text:hover { text-decoration: underline; color: #fff; }
    .wayback-link { color: var(--wayback-yellow); }
    .copy-btn { font-size: 11px; padding: 6px 12px; border: 1px solid #444; color: #888; background: #222; cursor: pointer; font-weight: bold; transition: 0.2s; }
    .copy-btn:hover { color: #000; background: var(--main-green); border-color: var(--main-green); }
    .alert { position: fixed; bottom: 20px; right: 20px; background: var(--main-green); color: black; padding: 10px 20px; display: none; font-weight: bold; z-index: 1000; box-shadow: 0 0 10px var(--main-green); }
    .cpanel-banner { background: linear-gradient(90deg, rgba(255,111,0,0.1), rgba(213,0,0,0.1)); border: 1px solid var(--cpanel-orange); padding: 15px; margin-bottom: 20px; border-radius: 5px; }
    .cpanel-banner h2 { color: var(--cpanel-orange); border-bottom: 1px solid var(--cpanel-orange); }
    .risk-critical { color: var(--cpanel-red); font-weight: bold; text-shadow: 0 0 10px var(--cpanel-red); }
    .risk-high { color: var(--nuclei-high); font-weight: bold; }
    .risk-medium { color: var(--cpanel-amber); font-weight: bold; }
    .risk-low { color: var(--main-green); font-weight: bold; }
    .risk-na { color: #666; }
    .cpanel-badge { display: inline-block; padding: 4px 12px; margin: 3px; border-radius: 3px; font-size: 12px; font-weight: bold; border: 1px solid; }
    .badge-patched { border-color: var(--main-green); color: var(--main-green); background: rgba(0,255,65,0.1); }
    .badge-vulnerable { border-color: var(--cpanel-red); color: var(--cpanel-red); background: rgba(213,0,0,0.1); }
    .badge-unknown { border-color: #888; color: #888; background: rgba(136,136,136,0.1); }
    .badge-nopatch { border-color: var(--cpanel-amber); color: var(--cpanel-amber); background: rgba(255,171,0,0.1); }
    .code-block { background: #111; border: 1px solid #333; padding: 10px; font-size: 12px; color: #aaa; overflow-x: auto; white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow-y: auto; }
    .gf-banner { background: linear-gradient(90deg, rgba(224,64,251,0.1), rgba(68,138,255,0.1)); border: 1px solid var(--gf-purple); padding: 15px; margin-bottom: 20px; border-radius: 5px; }
    .gf-banner h2 { color: var(--gf-purple); border-bottom: 1px solid var(--gf-purple); }
    .gf-pattern { margin-bottom: 15px; }
    .gf-pattern-name { color: var(--gf-purple); font-weight: bold; font-size: 14px; margin-bottom: 5px; }
    .gf-match { color: #aaa; font-size: 12px; padding: 3px 0; border-bottom: 1px solid #1a1a1a; }
    .gf-match:last-child { border-bottom: none; }
    .arjun-banner { background: linear-gradient(90deg, rgba(68,138,255,0.1), rgba(0,204,255,0.1)); border: 1px solid var(--arjun-blue); padding: 15px; margin-bottom: 20px; border-radius: 5px; }
    .arjun-banner h2 { color: var(--arjun-blue); border-bottom: 1px solid var(--arjun-blue); }
    .arjun-host { margin-bottom: 12px; }
    .arjun-host-name { color: var(--arjun-blue); font-weight: bold; font-size: 14px; margin-bottom: 5px; }
    .arjun-param { display: inline-block; padding: 2px 8px; margin: 2px; border-radius: 10px; font-size: 11px; background: rgba(68,138,255,0.15); border: 1px solid var(--arjun-blue); color: var(--arjun-blue); }
    .subjack-banner { background: linear-gradient(90deg, rgba(255,82,82,0.1), rgba(255,23,68,0.1)); border: 1px solid var(--subjack-red); padding: 15px; margin-bottom: 20px; border-radius: 5px; }
    .subjack-banner h2 { color: var(--subjack-red); border-bottom: 1px solid var(--subjack-red); }
    .subjack-confirmed { color: var(--subjack-red); font-weight: bold; }
    .subjack-potential { color: var(--cpanel-amber); font-weight: bold; }
    .subjack-item { padding: 8px 12px; border-left: 3px solid #333; margin: 4px 0; background: #0d0d0d; font-size: 13px; }
    .dork-engine-banner { background: linear-gradient(90deg, rgba(0,229,255,0.1), rgba(255,0,255,0.1)); border: 1px solid var(--dork-cyan); padding: 15px; margin-bottom: 20px; border-radius: 5px; }
    .dork-engine-banner h2 { color: var(--dork-cyan); border-bottom: 1px solid var(--dork-cyan); }
    .dork-result-item { padding: 10px 12px; border-left: 3px solid #333; margin: 6px 0; background: #0d0d0d; font-size: 13px; }
    .dork-result-item:hover { background: #111; }
    .dork-sev-critical { border-left-color: var(--nuclei-crit); }
    .dork-sev-high { border-left-color: var(--nuclei-high); }
    .dork-sev-medium { border-left-color: var(--nuclei-med); }
    .dork-sev-low { border-left-color: var(--nuclei-low); }
    .dork-sev-info { border-left-color: #444; }
    .pattern-chip { display: inline-block; padding: 1px 6px; margin: 1px; border-radius: 3px; font-size: 10px; background: rgba(0,229,255,0.1); border: 1px solid var(--dork-cyan); color: var(--dork-cyan); }
    .pattern-chip.secret { background: rgba(255,0,0,0.1); border-color: #ff0000; color: #ff4444; }
    .pattern-chip.vuln { background: rgba(255,109,0,0.1); border-color: var(--nuclei-high); color: var(--nuclei-high); }
    .pattern-chip.pii { background: rgba(255,214,0,0.1); border-color: var(--nuclei-med); color: var(--nuclei-med); }
    .pattern-chip.file { background: rgba(105,240,174,0.1); border-color: var(--nuclei-low); color: var(--nuclei-low); }
    .dork-stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-bottom: 15px; }
    .dork-stat-card { background: #111; border: 1px solid #333; padding: 10px; border-radius: 4px; text-align: center; }
    .dork-stat-value { font-size: 24px; font-weight: bold; color: var(--dork-cyan); }
    .dork-stat-label { font-size: 11px; color: #666; margin-top: 4px; }
    .dork-category-section { margin-bottom: 20px; }
    .dork-category-title { color: var(--dork-magenta); font-size: 16px; font-weight: bold; margin-bottom: 8px; padding-bottom: 5px; border-bottom: 1px solid #222; }
    """

    # Header
    header_html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>GhostDorks v5.0 - {safe_target}</title>
        <style>{css}</style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>PROJECT GHOST ENGINE v2.0 </h1>
                <h3>created by: L4ZYG33K </h3>
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
                    {f' | Dork Results: <strong style="color: var(--dork-cyan);">{len(dork_results)}</strong>' if dork_results else ''}
                </div>
            </header>

            <div class="controls">
                <input type="text" class="search-box" id="searchInput" placeholder="Filter by keyword (e.g. 'sql', 'env', 'login')...">
                <button class="btn" onclick="window.print()">Export PDF</button>
            </div>

            <div id="dorkContainer">
    """

    body_html = header_html

    # Dork Engine Results Section
    if dork_results:
        crit_dorks = len(dork_by_severity.get("critical", []))
        high_dorks = len(dork_by_severity.get("high", []))
        med_dorks = len(dork_by_severity.get("medium", []))
        low_dorks = len(dork_by_severity.get("low", []))
        info_dorks = len(dork_by_severity.get("info", []))

        body_html += f"""
        <div class="category-section dork-engine-banner">
            <h2>Project Ghost Dork Engine - {len(dork_results)} results ({crit_dorks} critical, {high_dorks} high)</h2>
            <div class="dork-stats-grid">
                <div class="dork-stat-card"><div class="dork-stat-value" style="color: var(--nuclei-crit);">{crit_dorks}</div><div class="dork-stat-label">CRITICAL</div></div>
                <div class="dork-stat-card"><div class="dork-stat-value" style="color: var(--nuclei-high);">{high_dorks}</div><div class="dork-stat-label">HIGH</div></div>
                <div class="dork-stat-card"><div class="dork-stat-value" style="color: var(--nuclei-med);">{med_dorks}</div><div class="dork-stat-label">MEDIUM</div></div>
                <div class="dork-stat-card"><div class="dork-stat-value" style="color: var(--nuclei-low);">{low_dorks}</div><div class="dork-stat-label">LOW</div></div>
                <div class="dork-stat-card"><div class="dork-stat-value">{info_dorks}</div><div class="dork-stat-label">INFO</div></div>
                <div class="dork-stat-card"><div class="dork-stat-value" style="color: var(--dork-magenta);">{dork_engine.stats['total_dorks']}</div><div class="dork-stat-label">DORKS RUN</div></div>
            </div>
        """

        for sev in ["critical", "high", "medium", "low", "info"]:
            results = dork_by_severity.get(sev, [])
            if results:
                body_html += f'<div class="dork-category-section"><div class="dork-category-title">{sev.upper()} ({len(results)})</div>'
                for r in results[:100]:
                    safe_url = html.escape(r["url"])
                    safe_title = html.escape(r.get("title", ""))
                    safe_dork = html.escape(r["dork"])
                    safe_cat = html.escape(r["category"])

                    pattern_chips = ""
                    for p in r.get("patterns", []):
                        ptype = "pattern-chip"
                        if p.startswith("SECRET:"):
                            ptype += " secret"
                        elif p.startswith("VULN:"):
                            ptype += " vuln"
                        elif p.startswith("PII:"):
                            ptype += " pii"
                        elif p.startswith("FILE:"):
                            ptype += " file"
                        pattern_chips += f'<span class="{ptype}">{html.escape(p)}</span>'

                    body_html += f'<div class="dork-result-item dork-sev-{sev}">'
                    body_html += f'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:5px;">'
                    body_html += f'<span class="sev-badge sev-{sev}">{sev}</span>'
                    body_html += f'<span style="color:#555;font-size:11px;">{safe_cat}</span></div>'
                    body_html += f'<div><a href="{safe_url}" target="_blank" style="color:var(--dork-cyan);text-decoration:none;font-size:14px;">{safe_url}</a></div>'
                    if safe_title:
                        body_html += f'<div style="color:#888;font-size:12px;margin-top:3px;">{safe_title}</div>'
                    body_html += f'<div style="margin-top:5px;">{pattern_chips}</div>'
                    body_html += f'<div style="color:#444;font-size:10px;margin-top:3px;">Dork: {safe_dork[:120]}...</div>'
                    body_html += '</div>'
                body_html += '</div>'

        body_html += '</div>'

    # cPanel Section
    if cpanel_data["detected"]:
        risk_class = {"CRITICAL": "risk-critical", "HIGH": "risk-high", "MEDIUM": "risk-medium", "LOW": "risk-low", "N/A": "risk-na"}.get(cpanel_data["risk_level"], "risk-na")
        patch_badge = {"PATCHED": "badge-patched", "LIKELY_VULNERABLE": "badge-vulnerable", "NO_VENDOR_PATCH": "badge-nopatch", "UNKNOWN": "badge-unknown"}.get(cpanel_data["patch_status"], "badge-unknown")
        probe_badge = {"VULNERABLE": "badge-vulnerable", "SAFE": "badge-patched", "INCONCLUSIVE": "badge-unknown", "NOT_TESTED": "badge-unknown"}.get(cpanel_data["probe_status"], "badge-unknown")
        geo_str = ""
        if cpanel_data.get("geo_data"):
            gd = cpanel_data["geo_data"]
            geo_str = f"{gd.get('city', 'N/A')}, {gd.get('country', 'N/A')} - {gd.get('isp', 'N/A')}"
        ns_list = ", ".join(whois_info.get("name_servers", [])) or "N/A"

        body_html += f"""
        <div class="category-section cpanel-banner">
            <h2>cPanel/WHM Reconnaissance & CVE-2026-41940 Triage</h2>
            <table class="intel-table">
                <tr><td>Service</td><td><strong style="color: var(--cpanel-orange);">{html.escape(cpanel_data["service_type"])}</strong> on port {cpanel_data["port"]} ({cpanel_data["body_size"]}B, {cpanel_data["response_time"]}s)</td></tr>
                <tr><td>Target IP</td><td>{html.escape(cpanel_data["target_ip"] or "N/A")}</td></tr>
                <tr><td>Geolocation</td><td>{html.escape(geo_str)}</td></tr>
                <tr><td>Risk Level</td><td><span class="{risk_class}">{html.escape(cpanel_data["risk_level"])}</span> (score: {cpanel_data["risk_score"]})</td></tr>
                <tr><td>Patch Status</td><td><span class="cpanel-badge {patch_badge}">{html.escape(cpanel_data["patch_status"])}</span> - {html.escape(cpanel_data["patch_detail"])}</td></tr>
                <tr><td>Probe Status</td><td><span class="cpanel-badge {probe_badge}">{html.escape(cpanel_data["probe_status"])}</span> - {html.escape(cpanel_data["probe_detail"])}</td></tr>
                <tr><td>Security Headers</td><td>{"Present" if cpanel_data["security_headers"] else "Missing (X-Frame-Options, X-Content-Type-Options, HSTS, CSP)"}</td></tr>
                <tr><td>Certificate</td><td>{"Let's Encrypt" if cpanel_data["letsencrypt"] else "Other / Unknown"}</td></tr>
                <tr><td>Version Indicators</td><td>{', '.join(html.escape(v) for v in cpanel_data["versions"][:15]) or "None extracted"}</td></tr>
                <tr><td>Name Servers</td><td>{html.escape(ns_list)}</td></tr>
            </table>
        """
        if cpanel_data["ssl_info"]:
            body_html += f'<div style="margin-top: 12px;"><strong style="color: #888;">SSL Certificate Info:</strong><div class="code-block">{html.escape(cpanel_data["ssl_info"])}</div></div>'
        if cpanel_data["headers"]:
            body_html += f'<div style="margin-top: 12px;"><strong style="color: #888;">Response Headers:</strong><div class="code-block">{html.escape(cpanel_data["headers"])}</div></div>'
        if cpanel_data["body_snippet"]:
            body_html += f'<div style="margin-top: 12px;"><strong style="color: #888;">Body Snippet:</strong><div class="code-block">{html.escape(cpanel_data["body_snippet"][:1500])}</div></div>'
        body_html += '</div>'

    # subjack Section
    if subjack_results:
        confirmed = [r for r in subjack_results if r["status"] == "CONFIRMED"]
        potential = [r for r in subjack_results if r["status"] != "CONFIRMED"]
        body_html += f'<div class="category-section subjack-banner"><h2>Subjack Takeover Results - {len(subjack_results)} found ({len(confirmed)} confirmed, {len(potential)} potential)</h2><div>'
        if confirmed:
            body_html += '<div style="margin-bottom: 12px;"><strong style="color: var(--subjack-red);">CONFIRMED VULNERABLE:</strong><br>'
            for r in confirmed[:50]:
                svc = f" [{html.escape(r['service'])}]" if r["service"] else ""
                body_html += f'<div class="subjack-item"><span class="subjack-confirmed">{html.escape(r["host"])}{svc}</span><br><span style="color:#555;font-size:11px;">{html.escape(r["raw"])}</span></div>'
            body_html += '</div>'
        if potential:
            body_html += '<div><strong style="color: var(--cpanel-amber);">POTENTIAL TAKEOVERS:</strong><br>'
            for r in potential[:50]:
                svc = f" [{html.escape(r['service'])}]" if r["service"] else ""
                body_html += f'<div class="subjack-item"><span class="subjack-potential">{html.escape(r["host"])}{svc}</span><br><span style="color:#555;font-size:11px;">{html.escape(r["raw"])}</span></div>'
            body_html += '</div>'
        body_html += '</div></div>'

    # gf Section
    if gf_results:
        body_html += f'<div class="category-section gf-banner"><h2>GF Pattern Matches - {len(gf_results)} patterns, {sum(len(v) for v in gf_results.values())} total matches</h2><div>'
        for pattern, matches in gf_results.items():
            body_html += f'<div class="gf-pattern"><div class="gf-pattern-name">{html.escape(pattern.upper())} ({len(matches)} matches)</div>'
            for match in matches[:30]:
                safe_match = html.escape(match)
                body_html += f'<div class="gf-match"><a href="{safe_match}" target="_blank" style="color:#aaa;text-decoration:none;">{safe_match}</a></div>'
            body_html += '</div>'
        body_html += '</div></div>'

    # arjun Section
    if arjun_results:
        body_html += f'<div class="category-section arjun-banner"><h2>Hidden Parameters (Arjun) - {sum(len(r["params"]) for r in arjun_results)} params across {len(arjun_results)} hosts</h2><div>'
        for entry in arjun_results[:50]:
            params_html = " ".join(f'<span class="arjun-param">{html.escape(p)}</span>' for p in entry["params"])
            body_html += f'<div class="arjun-host"><div class="arjun-host-name">{html.escape(entry["url"])} <span style="color:#555;font-size:12px;">({html.escape(entry["method"])} / {html.escape(entry["type"])})</span></div>{params_html}</div>'
        body_html += '</div></div>'

    # WHOIS
    if whois_info and whois_info.get("registrar") != "N/A":
        ns_list = ", ".join(whois_info.get("name_servers", [])) or "N/A"
        body_html += f"""
        <div class="category-section">
            <h2 style="color: var(--whois-cyan);">WHOIS Intelligence</h2>
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

    # DNS
    dns_record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    has_dns = any(dns_records.get(rt) for rt in dns_record_types)
    if has_dns:
        body_html += '<div class="category-section"><h2 style="color: var(--dns-purple);">DNS Record Map</h2>'
        if dns_records.get("security_notes"):
            for note in dns_records["security_notes"]:
                body_html += f'<div class="security-note">{html.escape(note)}</div>'
        body_html += '<table class="intel-table">'
        for rt in dns_record_types:
            records = dns_records.get(rt, [])
            if records:
                records_html = "<br>".join([html.escape(r) for r in records])
                body_html += f'<tr><td style="color: var(--dns-purple);">{rt}</td><td>{records_html}</td></tr>'
        body_html += '</table></div>'

    # Emails
    if harvest_data.get("emails") or harvest_data.get("hosts"):
        body_html += '<div class="category-section"><h2 style="color: var(--harvest-orange);">Harvested Emails & Hosts (theHarvester)</h2><div style="margin-bottom: 15px;">'
        if harvest_data.get("emails"):
            body_html += '<div style="margin-bottom: 10px;"><strong style="color: #888;">Emails:</strong><br>'
            for email in harvest_data["emails"]:
                body_html += f'<span class="email-chip">{html.escape(email)}</span>'
            body_html += '</div>'
        if harvest_data.get("hosts"):
            body_html += '<div style="margin-bottom: 10px;"><strong style="color: #888;">Discovered Hosts:</strong><br>'
            for h in harvest_data["hosts"][:100]:
                body_html += f'<span class="host-chip">{html.escape(h)}</span>'
            body_html += '</div>'
        if harvest_data.get("ips"):
            body_html += '<div><strong style="color: #888;">Associated IPs:</strong><br>'
            for ip in harvest_data["ips"][:50]:
                body_html += f'<span class="dns-badge" style="border-color: var(--harvest-orange); color: var(--harvest-orange);">{html.escape(ip)}</span>'
            body_html += '</div>'
        body_html += '</div></div>'

    # Reverse IP
    if co_hosted_domains:
        body_html += f'<div class="category-section"><h2 style="color: var(--reverse-teal);">Co-Hosted Domains (Reverse IP: {target_ip})</h2><div class="dork-list">'
        for co_domain in co_hosted_domains[:200]:
            safe_co = html.escape(co_domain)
            google_url = f"https://www.google.com/search?q=site:{urllib.parse.quote_plus(co_domain)}"
            body_html += f'<div class="dork-item"><a href="{google_url}" target="_blank" class="dork-text" style="color: var(--reverse-teal);">{safe_co}</a><button class="copy-btn" data-dork="{safe_co}" onclick="copyToClipboard(this.getAttribute(\'data-dork\'))">COPY</button></div>'
        body_html += '</div></div>'

    # dnsx
    if resolved_hosts or takeover_candidates:
        body_html += f'<div class="category-section"><h2 style="color: var(--dnsx-lime);">Live Resolved Hosts (dnsx) - {len(resolved_hosts)} live</h2>'
        if takeover_candidates:
            for tc in takeover_candidates:
                safe_h = html.escape(tc['host'])
                safe_c = html.escape(', '.join(tc.get('cname', [])))
                body_html += f'<div class="security-note">Takeover Candidate: <strong>{safe_h}</strong> -> CNAME: {safe_c}</div>'
        if resolved_hosts:
            body_html += '<table class="intel-table" style="margin-top:10px;"><tr><td style="color:#888;width:40%">Host</td><td style="color:#888;">IPs</td></tr>'
            for rh in resolved_hosts[:150]:
                safe_h = html.escape(rh['host'])
                safe_ip = html.escape(', '.join(rh.get('ips', [])))
                body_html += f'<tr><td style="color:var(--dnsx-lime);">{safe_h}</td><td style="color:#aaa;">{safe_ip}</td></tr>'
            body_html += '</table>'
        body_html += '</div>'

    # httpx
    if http_hosts:
        body_html += f'<div class="category-section"><h2 style="color: var(--httpx-pink);">Live HTTP Services (httpx) - {len(http_hosts)} hosts</h2><div style="font-size:12px;color:#555;margin-bottom:8px;">Status | URL | Server | Technologies</div>'
        for hh in http_hosts[:200]:
            sc = hh.get("status", 0)
            sc_class = "status-2xx" if 200<=sc<300 else "status-3xx" if 300<=sc<400 else "status-4xx" if 400<=sc<500 else "status-5xx"
            safe_url = html.escape(hh.get("url", ""))
            safe_srv = html.escape(hh.get("server", "") or "")
            safe_title = html.escape(hh.get("title", "") or "")
            tech_html = "".join(f'<span class="tech-pill">{html.escape(str(t))}</span>' for t in (hh.get("tech") or [])[:6])
            body_html += f'<div class="httpx-row"><span class="{sc_class}">{sc}</span><a href="{safe_url}" target="_blank" style="color:var(--httpx-pink);text-decoration:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="{safe_title}">{safe_url}</a><span style="color:#666;font-size:12px;">{safe_srv}</span><span>{tech_html}</span></div>'
        body_html += '</div>'

    # Katana
    if katana_endpoints:
        sensitive_eps = [e for e in katana_endpoints if e.get("sensitive")]
        api_eps = [e for e in katana_endpoints if e.get("api")]
        other_eps = [e for e in katana_endpoints if not e.get("sensitive") and not e.get("api")]
        body_html += f'<div class="category-section"><h2 style="color: var(--katana-sky);">Crawled Endpoints (katana) - {len(katana_endpoints)} total</h2>'
        if sensitive_eps:
            body_html += f'<div style="margin-bottom:12px;"><strong style="color:#888;">Sensitive Files ({len(sensitive_eps)}):</strong><br>'
            for e in sensitive_eps[:50]:
                su = html.escape(e["url"])
                body_html += f'<div class="dork-item" style="margin:3px 0;"><a href="{su}" target="_blank" class="dork-text" style="color:var(--shodan-red);">{su}</a><button class="copy-btn" onclick="copyToClipboard(\'{su}\')">COPY</button></div>'
            body_html += '</div>'
        if api_eps:
            body_html += f'<div style="margin-bottom:12px;"><strong style="color:#888;">API Endpoints ({len(api_eps)}):</strong><br>'
            for e in api_eps[:50]:
                su = html.escape(e["url"])
                body_html += f'<div class="dork-item" style="margin:3px 0;"><a href="{su}" target="_blank" class="dork-text" style="color:var(--katana-sky);">{su}</a><button class="copy-btn" onclick="copyToClipboard(\'{su}\')">COPY</button></div>'
            body_html += '</div>'
        if other_eps:
            body_html += f'<div><strong style="color:#888;">Other Endpoints ({len(other_eps)}):</strong><br>'
            for e in other_eps[:100]:
                su = html.escape(e["url"])
                body_html += f'<div class="dork-item" style="margin:3px 0;"><a href="{su}" target="_blank" class="dork-text">{su}</a><button class="copy-btn" onclick="copyToClipboard(\'{su}\')">COPY</button></div>'
            body_html += '</div>'
        body_html += '</div>'

    # Nuclei
    if nuclei_findings:
        crit_count = sum(1 for f in nuclei_findings if f["severity"] == "critical")
        high_count = sum(1 for f in nuclei_findings if f["severity"] == "high")
        body_html += f'<div class="category-section"><h2 style="color: var(--nuclei-crit);">Nuclei Findings - {len(nuclei_findings)} total ({crit_count} critical, {high_count} high)</h2>'
        border_colors = {"critical":"var(--nuclei-crit)","high":"var(--nuclei-high)","medium":"var(--nuclei-med)","low":"var(--nuclei-low)"}
        for finding in nuclei_findings[:300]:
            sev = finding.get("severity", "info")
            name = html.escape(finding.get("name", ""))
            tmpl = html.escape(finding.get("template", ""))
            furl = html.escape(finding.get("url", ""))
            desc = html.escape(finding.get("description", "") or "")
            refs = finding.get("reference", []) or []
            border = border_colors.get(sev, "#444")
            ref_html = " ".join(f'<a href="{html.escape(r)}" target="_blank" style="color:#555;font-size:11px;">[ref]</a>' for r in refs[:3])
            desc_html = f'<div style="color:#666;font-size:12px;margin-top:4px;">{desc}</div>' if desc else ''
            body_html += f'<div class="finding-item" style="border-left-color:{border};"><div><span class="sev-badge sev-{sev}">{sev}</span><strong style="color:#ddd;">{name}</strong><span style="color:#555;font-size:12px;margin-left:8px;">[{tmpl}]</span> {ref_html}</div><div style="margin-top:4px;"><a href="{furl}" target="_blank" style="color:{border};font-size:13px;">{furl}</a></div>{desc_html}</div>'
        body_html += '</div>'

    # Shodan
    if open_ports or vulns:
        body_html += f'<div class="category-section"><h2 style="color: var(--shodan-red);">Shodan Intel (IP: {target_ip})</h2><div class="dork-list">'
        if open_ports:
            ports_str = ", ".join(map(str, open_ports))
            body_html += f'<div class="dork-item" style="display: block;"><span class="dork-text" style="color: #fff; text-decoration: none; cursor: default; white-space: normal; word-wrap: break-word; line-height: 1.5;"><strong>Open Ports:</strong> {ports_str}</span></div>'
        if vulns:
            vulns_str = ", ".join(vulns)
            body_html += f'<div class="dork-item" style="display: block;"><span class="dork-text" style="color: var(--shodan-red); text-decoration: none; cursor: default; white-space: normal; word-wrap: break-word; line-height: 1.5;"><strong>CVEs Found:</strong> {vulns_str}</span></div>'
        body_html += "</div></div>"

    # Wayback
    if discovered_wayback_urls:
        body_html += '<div class="category-section"><h2 style="color: var(--wayback-yellow);">Archived Sensitive Files (Wayback Machine)</h2><div class="dork-list">'
        for w_url in discovered_wayback_urls:
            safe_w_url = html.escape(w_url)
            body_html += f'<div class="dork-item"><a href="{safe_w_url}" target="_blank" class="dork-text wayback-link">{safe_w_url}</a><button class="copy-btn" data-dork="{safe_w_url}" onclick="copyToClipboard(this.getAttribute(\'data-dork\'))">COPY</button></div>'
        body_html += "</div></div>"

    # Generated Dorks
    for category, queries in dork_map.items():
        body_html += f'<div class="category-section"><h2>{category}</h2><div class="dork-list">'
        for q in queries:
            encoded_q = urllib.parse.quote_plus(q) 
            url = f"https://www.google.com/search?q={encoded_q}"
            safe_q = html.escape(q).replace('"', '&quot;')
            body_html += f'<div class="dork-item"><a href="{url}" target="_blank" class="dork-text">{html.escape(q)}</a><button class="copy-btn" data-dork="{safe_q}" onclick="copyToClipboard(this.getAttribute(\'data-dork\'))">COPY</button></div>'
        body_html += "</div></div>"

    # Footer with JavaScript
    footer_html = """
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

    return body_html + footer_html


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PROJECT GHOST ENGINE v5.0 - Unified OSINT & cPanel/WHM Reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Passive recon only:
    python ghostreconv2.py -d example.com

  With active scanning:
    python ghostreconv2.py -d example.com --active

  Full nuclear mode + all new modules:
    python ghostreconv2.py -d example.com --active --nuclei --cpanel-probe --gf --arjun --subjack

  Dork engine with stealth:
    python ghostreconv2.py -d example.com --dork-stealth --dg-categories sqli,secrets,files

  Resume interrupted dork session:
    python ghostreconv2.py -d example.com --dork-resume

  Stealth mode with new tools:
    python ghostreconv2.py -d example.com --gf --subjack --rate 300

  Throttle active tools:
    python ghostreconv2.py -d example.com --active --rate 300
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

    # DorkEngine arguments
    parser.add_argument("--dork-stealth", action="store_true",
        help="Enable stealth mode for dork engine (slower with random delays).")
    parser.add_argument("--dg-categories", type=str, metavar="CATS",
        help="Comma-separated dork categories to run. Default: all. Options: sqli,xss,lfi_rfi,redirect,ssrf,files,secrets,admin,vuln,api,errors,docs,paste_git,takeover,cloud,dev,social,cpanel_hosting,database,iot,cms,osint,subdomain_recon")
    parser.add_argument("--dg-max-results", type=int, default=50, metavar="N",
        help="Max results per dork query. Default: 50.")
    parser.add_argument("--dork-checkpoint", action="store_true", default=True,
        help="Enable session checkpointing for dork engine (default: on).")
    parser.add_argument("--dork-resume", action="store_true",
        help="Resume interrupted dork session from checkpoint.")
    parser.add_argument("--no-dork-checkpoint", action="store_true",
        help="Disable session checkpointing.")

    args = parser.parse_args()

    domain = args.domain.strip()
    if domain:
        dork_cats = None
        if args.dg_categories:
            dork_cats = [c.strip() for c in args.dg_categories.split(",")]

        generate_ghost_dashboard(domain, cfg={
            "active":  args.active,
            "nuclei":  args.nuclei,
            "rate":    args.rate,
            "cpanel_probe": args.cpanel_probe,
            "gf": args.gf,
            "arjun": args.arjun,
            "subjack": args.subjack,
            "dork_stealth": args.dork_stealth,
            "dork_categories": dork_cats,
            "dork_max_results": args.dg_max_results,
            "dork_checkpoint": not args.no_dork_checkpoint,
            "dork_resume": args.dork_resume,
        })
    else:
        print("[!] Domain cannot be empty.")
