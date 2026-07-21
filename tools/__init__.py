"""
CyberForge Tools Module
All security tools in one place
"""

import socket
import struct
import hashlib
import base64
import ssl
import json
import os
import sys
import time
import re
import random
import string
import urllib.request
import urllib.parse
import urllib.error
import http.client
from datetime import datetime
from collections import defaultdict

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.colors import C
from utils.helpers import (
    validate_ip, validate_domain, validate_url, 
    save_report, log_action, loading_animation,
    get_common_ports, get_subdomains, get_wordlist
)

# ============================================================
# TOOL 01: Network Scanner
# ============================================================
def network_scanner():
    print(f"\n{C.BD}{C.C}  ╔══════════════════════════════════╗")
    print(f"  ║   🔍 NETWORK SCANNER            ║")
    print(f"  ╚══════════════════════════════════╝{C.END}\n")
    
    target = input(f"  {C.W}Enter network range (e.g., 192.168.1.0/24) or IP: {C.END}").strip()
    
    if '/' in target:
        base = target.split('/')[0]
        prefix = '.'.join(base.split('.')[:3])
        print(f"\n  {C.Y}[*] Scanning network {prefix}.0/24...{C.END}\n")
        
        print(f"  {'IP Address':<18} {'Status':<12} {'Hostname':<25} {'MAC (if local)'}")
        print(f"  {'-'*18} {'-'*12} {'-'*25} {'-'*15}")
        
        found = []
        for i in range(1, 255):
            ip = f"{prefix}.{i}"
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                result = sock.connect_ex((ip, 80))
                if result == 0 or True:  # Always try to resolve
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        hostname = "—"
                    status = f"{C.G}UP{C.END}" if result == 0 else f"{C.Y}REACHABLE{C.END}"
                    print(f"  {ip:<18} {status:<20} {hostname:<25}")
                    found.append({'ip': ip, 'hostname': hostname, 'status': 'up' if result == 0 else 'reachable'})
                sock.close()
            except:
                pass
        
        print(f"\n  {C.G}[✓] Found {len(found)} hosts on the network{C.END}")
        save_report('network_scan', found)
        log_action('network_scanner', f"Scanned {target}, found {len(found)} hosts")
    else:
        if not validate_ip(target):
            print(f"  {C.R}[!] Invalid IP address{C.END}")
            return
        
        print(f"\n  {C.Y}[*] Scanning {target}...{C.END}\n")
        try:
            hostname = socket.gethostbyaddr(target)[0]
            print(f"  IP:       {target}")
            print(f"  Hostname: {hostname}")
            print(f"  Status:   {C.G}UP{C.END}")
        except:
            print(f"  IP:       {target}")
            print(f"  Hostname: Unknown")
            print(f"  Status:   {C.Y}May be filtered{C.END}")

# ============================================================
# TOOL 02: Port Scanner
# ============================================================
def port_scanner():
    print(f"\n{C.BD}{C.C}  ╔══════════════════════════════════╗")
    print(f"  ║   🌐 PORT SCANNER               ║")
    print(f"  ╚══════════════════════════════════╝{C.END}\n")
    
    target = input(f"  {C.W}Enter target IP/Domain: {C.END}").strip()
    
    try:
        ip = socket.gethostbyname(target)
    except:
        print(f"  {C.R}[!] Cannot resolve host{C.END}")
        return
    
    print(f"\n  {C.Y}[*] Scanning {target} ({ip})...{C.END}")
    print(f"  {C.Y}[*] This may take a moment...{C.END}\n")
    
    ports = get_common_ports()
    open_ports = []
    
    print(f"  {'Port':<8} {'State':<10} {'Service':<20} {'Version'}")
    print(f"  {'-'*8} {'-'*10} {'-'*20} {'-'*20}")
    
    for port, service in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()[:50]
                except:
                    banner = "—"
                print(f"  {C.G}{port:<8} OPEN{C.END}       {service:<20} {banner}")
                open_ports.append({'port': port, 'service': service, 'banner': banner})
            sock.close()
        except:
            pass
    
    if not open_ports:
        print(f"  {C.Y}[*] No open ports found (host may be behind firewall){C.END}")
    else:
        print(f"\n  {C.G}[✓] Found {len(open_ports)} open ports{C.END}")
    
    save_report('port_scan', {'target': target, 'ip': ip, 'open_ports': open_ports})
    log_action('port_scanner', f"Scanned {target}, found {len(open_ports)} open ports")

# ============================================================
# TOOL 03: WHOIS Lookup
# ============================================================
def whois_lookup():
    print(f"\n{C.BD}{C.C}  ╔══════════════════════════════════╗")
    print(f"  ║   🕵️ WHOIS LOOKUP               ║")
    print(f"  ╚══════════════════════════════════╝{C.END}\n")
    
    domain = input(f"  {C.W}Enter domain (e.g., example.com): {C.END}").strip()
    
    if not validate_domain(domain):
        print(f"  {C.R}[!] Invalid domain{C.END}")
        return
    
    print(f"\n  {C.Y}[*] Looking up WHOIS for {domain}...{C.END}\n")
    
    try:
        # Try using the whois command if available
        result = os.popen(f"whois {domain} 2>/dev/null").read()
        if result:
            # Parse key fields
            lines = result.split('\n')
            key_fields = ['Domain Name', 'Registrar', 'Creation Date', 'Expiry', 'Updated', 
                         'Name Server', 'Status', 'Registrant', 'Admin']
            
            print(f"  {C.BD}─── WHOIS Information ───{C.END}")
            for line in lines:
                for field in key_fields:
                    if field.lower() in line.lower() and ':' in line:
                        key, value = line.split(':', 1)
                        print(f"  {C.C}{key.strip()}{C.END}: {value.strip()}")
                        break
            
            # Raw output option
            print(f"\n  {C.Y}[*] Raw WHOIS data saved to reports/{C.END}")
            save_report('whois', {'domain': domain, 'raw': result[:5000]})
        else:
            print(f"  {C.Y}[*] WHOIS command not available. Using alternative...{C.END}")
            # Alternative: basic DNS info
            try:
                ip = socket.gethostbyname(domain)
                print(f"  Domain: {domain}")
                print(f"  IP:     {ip}")
                try:
                    hostname = socket.gethostbyaddr(ip)
                    print(f"  Host:   {hostname[0]}")
                except:
                    pass
            except:
                print(f"  {C.R}[!] Cannot resolve domain{C.END}")
    except Exception as e:
        print(f"  {C.R}[!] Error: {e}{C.END}")
    
    log_action('whois_lookup', f"Looked up {domain}")

# ============================================================
# TOOL 04: DNS Reconnaissance
# ============================================================
def dns_recon():
    print(f"\n{C.BD}{C.C}  ╔══════════════════════════════════╗")
    print(f"  ║   📡 DNS RECONNAISSANCE          ║")
    print(f"  ╚══════════════════════════════════╝{C.END}\n")
    
    domain = input(f"  {C.W}Enter domain: {C.END}").strip()
    if not validate_domain(domain):
        print(f"  {C.R}[!] Invalid domain{C.END}")
        return
    
    print(f"\n  {C.Y}[*] Performing DNS reconnaissance on {domain}...{C.END}\n")
    
    record_types = {
        'A': 'IPv4 Address',
        'AAAA': 'IPv6 Address',
        'MX': 'Mail Exchange',
        'NS': 'Name Server',
        'TXT': 'TXT Record',
        'CNAME': 'Canonical Name',
        'SOA': 'Start of Authority',
    }
    
    results = {}
    
    # Use dig or nslookup
    for rtype, desc in record_types.items():
        print(f"  {C.C}[{rtype}]{C.END} {desc}:")
        try:
            output = os.popen(f"dig +short {domain} {rtype} 2>/dev/null || nslookup -type={rtype} {domain} 2>/dev/null").read()
            if output.strip():
                for line in output.strip().split('\n'):
                    if line.strip() and not line.startswith('#') and not line.startswith('Server'):
                        print(f"       {C.G}{line.strip()}{C.END}")
                        results.setdefault(rtype, []).append(line.strip())
            else:
                print(f"       {C.Y}No records found{C.END}")
        except:
            print(f"       {C.Y}Lookup failed{C.END}")
        print()
    
    # Reverse DNS
    print(f"  {C.C}[Reverse DNS]{C.END}")
    try:
        ip = socket.gethostbyname(domain)
        hostname = socket.gethostbyaddr(ip)
        print(f"       {domain} → {ip} → {hostname[0]}")
    except:
        print(f"       {C.Y}Reverse lookup failed{C.END}")
    
    save_report('dns_recon', {'domain': domain, 'records': results})
    log_action('dns_recon', f"DNS recon on {domain}")

# ============================================================
# TOOL 05: Subdomain Enumerator
# ============================================================
def subdomain_enum():
    print(f"\n{C.BD}{C.C}  ╔══════════════════════════════════╗")
    print(f"  ║   🖥️ SUBDOMAIN ENUMERATOR        ║")
    print(f"  ╚══════════════════════════════════╝{C.END}\n")
    
    domain = input(f"  {C.W}Enter domain (e.g., example.com): {C.END}").strip()
    if not validate_domain(domain):
        print(f"  {C.R}[!] Invalid domain{C.END}")
        return
    
    print(f"\n  {C.Y}[*] Enumerating subdomains for {domain}...{C.END}\n")
    
    subdomains = get_subdomains()
    found = []
    
    print(f"  {'Subdomain':<40} {'IP Address':<18} {'Status'}")
    print(f"  {'-'*40} {'-'*18} {'-'*10}")
    
    for sub in subdomains:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            print(f"  {C.G}{fqdn:<40}{C.END} {ip:<18} {C.G}ACTIVE{C.END}")
            found.append({'subdomain': fqdn, 'ip': ip})
        except:
            pass  # Silent fail for speed
    
    # Also try certificate transparency
    print(f"\n  {C.Y}[*] Checking Certificate Transparency logs...{C.END}")
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={'User-Agent': 'CyberForge/2.0'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            ct_subs = set()
            for entry in data:
                name = entry.get('name_value', '')
                for n in name.split('\n'):
                    n = n.strip().lower()
                    if n.endswith(f'.{domain}') and n not in [f['subdomain'] for f in found]:
                        ct_subs.add(n)
            
            for sub in sorted(ct_subs)[:20]:
                print(f"  {C.C}{sub:<40}{C.END} {'CT Log':<18} {C.Y}FOUND{C.END}")
                found.append({'subdomain': sub, 'ip': 'CT Log'})
    except:
        print(f"  {C.Y}[*] CT lookup unavailable (network error){C.END}")
    
    print(f"\n  {C.G}[✓] Found {len(found)} subdomains{C.END}")
    save_report('subdomain_enum', {'domain': domain, 'subdomains': found})
    log_action('subdomain_enum', f"Found {len(found)} subdomains for {domain}")

# ============================================================
# TOOL 06: Hash Generator/Cracker
# ============================================================
def hash_tool():
    print(f"\n{C.BD}{C.C}  ╔══════════════════════════════════╗")
    print(f"  ║   🔐 HASH GENERATOR/CRACKER      ║")
    print(f"  ╚══════════════════════════════════╝{C.END}\n")
    
    print(f"  {C.G}[1]{C.W} Generate Hash")
    print(f"  {C.G}[2]{C.W} Crack Hash (Dictionary)")
    print(f"  {C.G}[3]{C.W} Verify Hash")
    
    choice = input(f"\n  {C.W}Choice: {C.END}").strip()
    
    if choice == '1':
        text = input(f"  Enter text to hash: ").strip()
        if not text:
            return
        
        print(f"\n  {C.BD}─── Hash Values ───{C.END}")
        print(f"  MD5:    {C.G}{hashlib.md5(text.encode()).hexdigest()}{C.END}")
        print(f"  SHA1:   {C.G}{hashlib.sha1(text.encode()).hexdigest()}{C.END}")
        print(f"  SHA256: {C.G}{hashlib.sha256(text.encode()).hexdigest()}{C.END}")
        print(f"  SHA512: {C.G}{hashlib.sha512(text.encode()).hexdigest()}{C.END}")
        print(f"  BLAKE2: {C.G}{hashlib.blake2b(text.encode()).hexdigest()}{C.END}")
        
        # Base64
        print(f"  B64:    {C.G}{base64.b64encode(text.encode()).decode()}{C.END}")
        
        save_report('hash_generate', {'text': text[:3]+'***', 'sha256': hashlib.sha256(text.encode()).hexdigest()})
    
    elif choice == '2':
        hash_val = input(f"  Enter hash to crack: ").strip()
        hash_type = input(f"  Hash type (md5/sha1/sha256): ").strip().lower()
        
        if hash_type not in ['md5', 'sha1', 'sha256']:
            print(f"  {C.R}[!] Unsupported hash type{C.END}")
            return
        
        wordlist_path = input(f"  Wordlist path (Enter for built-in): ").strip()
        
        if wordlist_path and os.path.exists(wordlist_path):
            with open(wordlist_path, 'r', errors='ignore') as f:
                words = [w.strip() for w in f.readlines()]
        else:
            words = get_wordlist()
        
        print(f"\n  {C.Y}[*] Cracking {hash_type} hash with {len(words)} words...{C.END}\n")
        
        hash_func = getattr(hashlib, hash_type)
        found = False
        
        for i, word in enumerate(words):
            if hash_func(word.encode()).hexdigest() == hash_val.lower():
                print(f"  {C.G}[✓] HASH CRACKED!{C.END}")
                print(f"  Original: {C.BD}{word}{C.END}")
                found = True
                break
            if i % 500 == 0:
                print(f"\r  Tested: {i}/{len(words)}", end='', flush=True)
        
        if not found:
            print(f"\n  {C.R}[✗] Hash not found in wordlist{C.END}")
        
        log_action('hash_crack', f"Attempted to crack {hash_type} hash, {'success' if found else 'failed'}")
    
    elif choice == '3':
        text = input(f"  Enter text: ").strip()
        hash_val = input(f"  Enter hash: ").strip()
        hash_type = input(f"  Hash type (md5/sha1/sha256): ").strip().lower()
        
        if hash_type not in ['md5', 'sha1', 'sha256']:
            print(f"  {C.R}[!] Unsupported hash type{C.END}")
            return
        
        computed = getattr(hashlib, hash_type)(text.encode()).hexdigest()
        
        if computed == hash_val.lower():
            print(f"  {C.G}[✓] MATCH! Hash verified successfully.{C.END}")
        else:
            print(f"  {C.R}[✗] NO MATCH! Hash verification failed.{C.END}")

# ============================================================
# TOOL 07: Web Technology Detector
# ============================================================
def web_tech_detect():
    print(f"\n{C.BD}{C.C}  ╔══════════════════════════════════╗")
    print(f"  ║   📊 WEB TECHNOLOGY DETECTOR      ║")
    print(f"  ╚══════════════════════════════════╝{C.END}\n")
    
    url = input(f"  {C.W}Enter URL (e.g., https://example.com): {C.END}").strip()
    if not validate_url(url):
        if not url.startswith('http'):
            url = 'https://' + url
    
    print(f"\n  {C.Y}[*] Analyzing {url}...{C.END}\n")
    
    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            headers = dict(resp.headers)
            html = resp.read().decode('utf-8', errors='ignore')
        
        # Detect technologies from headers
        print(f"  {C.BD}─── Server Information ───{C.END}")
        if 'Server' in headers:
            print(f"  Server: {C.G}{headers['Server']}{C.END}")
        if 'X-Powered-By' in headers:
            print(f"  Powered By: {C.G}{headers['X-Powered-By']}{C.END}")
        if 'X-AspNet-Version' in headers:
            print(f"  ASP.NET: {C.G}{headers['X-AspNet-Version']}{C.END}")
        
        # Detect from HTML
        print(f"\n  {C.BD}─── Detected Technologies ───{C.END}")
        
        tech_signatures = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'jQuery': ['jquery', 'jQuery'],
            'React': ['react', 'reactjs', '__NEXT_DATA__', '_app.js'],
            'Vue.js': ['vue', 'vuejs', '__vue__'],
            'Angular': ['angular', 'ng-app', 'ng-version'],
            'Bootstrap': ['bootstrap', 'Bootstrap'],
            'Tailwind CSS': ['tailwind', 'tailwindcss'],
            'Laravel': ['laravel', 'laravel_session'],
            'Django': ['csrfmiddlewaretoken', 'django'],
            'Cloudflare': ['cf-ray', 'cloudflare'],
            'Google Analytics': ['google-analytics', 'gtag', 'ga('],
            'reCAPTCHA': ['recaptcha', 'grecaptcha'],
            'PHP': ['.php', 'PHPSESSID'],
            'Node.js': ['x-powered-by: Express', 'x-powered-by: Next'],
            'Shopify': ['shopify', 'Shopify'],
            'Wix': ['wix', 'wixpress'],
        }
        
        detected = []
        for tech, sigs in tech_signatures.items():
            for sig in sigs:
                if sig.lower() in html.lower() or sig.lower() in str(headers).lower():
                    detected.append(tech)
                    break
        
        for tech in detected:
            print(f"  {C.G}✓{C.END} {tech}")
        
        if not detected:
            print(f"  {C.Y}No common technologies detected{C.END}")
        
        # Security headers
        print(f"\n  {C.BD}─── Security Headers ───{C.END}")
        sec_headers = {
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-Frame-Options': 'Clickjacking Protection',
            'X-XSS-Protection': 'XSS Filter',
            'X-Content-Type-Options': 'MIME Sniffing Protection',
            'Referrer-Policy': 'Referrer Policy',
            'Permissions-Policy': 'Permissions Policy',
        }
        
        for header, desc in sec_headers.items():
            if header in headers:
                print(f"  {C.G}✓{C.END} {desc}: {headers[header][:50]}")
            else:
                print(f"  {C.R}✗{C.END} {desc}: {C.R}Missing{C.END}")
        
        save_report('web_tech', {'url': url, 'detected': detected, 'headers': headers})
        log_action('web_tech_detect', f"Analyzed {url}, found {len(detected)} technologies")
    
    except Exception as e:
        print(f"  {C.R}[!] Error: {e}{C.END}")

# ============================================================
# TOOL 08: Firewall Tester
# ============================================================
def firewall_tester():
    print(f"\n{C.BD}{C.C}  ╔══════════════════════════════════╗")
    print(f"  ║   🔥 FIREWALL TESTER             ║")
    print(f"  ╚══════════════════════════════════╝{C.END}\n")
    
    target = input(f"  {C.W}Enter target IP/Domain: {C.END}").strip()
    
    try:
        ip = socket.gethostbyname(target)
    except:
        print(f"  {C.R}[!] Cannot resolve host{C.END}")
        return
    
    print(f"\n  {C.Y}[*] Testing firewall on {target} ({ip})...{C.END}\n")
    
    # Test common ports
    test_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 
                  1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200]
    
    open_ports = []
    filtered_ports = []
    closed_ports = []
    
    for port in test_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
                print(f"  {C.G}Port {port:>5}: OPEN{C.END}")
            elif result == 111:
                closed_ports.append(port)
            else:
                filtered_ports.append(port)
                print(f"  {C.Y}Port {port:>5}: FILTERED{C.END}")
            sock.close()
        except socket.timeout:
            filtered_ports.append(port)
            print(f"  {C.Y}Port {port:>5}: FILTERED (timeout){C.END}")
        except:
            closed_ports.append(port)
    
    # Analysis
    print(f"\n  {C.BD}─── Firewall Analysis ───{C.END}")
    print(f"  Open ports:     {C.G}{len(open_ports)}{C.END}")
    print(f"  Filtered ports: {C.Y}{len(filtered_ports)}{C.END}")
    print(f"  Closed ports:   {C.R}{len(closed_ports)}{C.END}")
    
    if filtered_ports > len(test_ports) // 2:
        print(f"\n  {C.G}[✓] Strong firewall detected — most ports are filtered{C.END}")
    elif filtered_ports == 0 and open_ports > 5:
        print(f"\n  {C.R}[!] Weak/No firewall — many ports open, none filtered{C.END}")
    else:
        print(f"\n  {C.Y}[*] Moderate firewall — some filtering in place{C.END}")
    
    # ICMP test
    print(f"\n  {C.BD}─── ICMP Test ───{C.END}")
    ping_result = os.popen(f"ping -c 1 -W 2 {ip} 2>/dev/null").read()
    if 'ttl=' in ping_result.lower() or 'time=' in ping_result.lower():
        ttl = re.search(r'ttl=(\d+)', ping_result, re.IGNORECASE)
        if ttl:
            ttl_val = int(ttl.group(1))
            if ttl_val <= 64:
                os_guess = "Linux/Unix"
            elif ttl_val <= 128:
                os_guess = "Windows"
            else:
                os_guess = "Network Device"
            print(f"  {C.G}Host responds to ICMP{C.END} (TTL: {ttl_val}, Likely OS: {os_guess})")
    else:
        print(f"  {C.Y}ICMP blocked — firewall may be dropping pings{C.END}")
    
    save_report('firewall_test', {'target': target, 'open': open_ports, 'filtered': filtered_ports})
    log_action('firewall_tester', f"Tested {target}")

# ============================================================
# TOOL 09: WiFi Scanner
# ============================================================
def wifi_scanner():
    print(f"\n{C.BD}{C.C}  ╔══════════════════════════════════╗")
    print(f"  ║   📡 WIFI SCANNER                ║")
    print(f"  ╚══════════════════════════════════╝{C.END}\n")
    
    print(f"  {C.Y}[*] Scanning for WiFi networks...{C.END}\n")
    
    if os.name == 'nt':
        output = os.popen("netsh wlan show networks mode=bssid").read()
    else:
        output = os.popen("iwlist scan 2>/dev/null || nmcli -t -f SSID,SIGNAL,SECURITY dev wifi list 2>/dev/null").read()
    
    if output.strip():
        print(output)
    else:
        print(f"  {C.Y}[*] Direct scan unavailable. Showing nmcli results...{C.END}")
        output = os.popen("nmcli dev wifi list 2>/dev/null").read()
        if output.strip():
            print(output)
        else:
            print(f"  {C.R}[!] WiFi scanning requires root/admin privileges{C.END}")
            print(f"  {C.Y}[*] Try: sudo python3 cyberforge.py -t wifi_scanner{C.END}")

# ============================================================
# TOOL 10: Password Strength Checker
# ============================================================
def pass_checker():
    print(f"\n{C.BD}{C.C}  ╔══════════════════════════════════╗")
    print(f"  ║   🔑 PASSWORD STRENGTH CHECKER   ║")
    print(f"  ╚══════════════════════════════════╝{C.END}\n")
    
    password = input(f"  {C.W}Enter password to check: {C.END}").strip()
    if not password:
        return
    
    score = 0
    feedback = []
    
    # Length
    if len(password) >= 12:
        score += 25
        feedback.append(f"  {C.G}✓{C.END} Length ≥ 12 characters")
    elif len(password) >= 8:
        score += 15
        feedback.append(f"  {C.Y}~{C.END} Length ≥ 8 characters (aim for 12+)")
    else:
        feedback.append(f"  {C.R}✗{C.END} Too short (minimum 8 characters)")
    
    # Uppercase
    if re.search(r'[A-Z]', password):
        score += 15
        feedback.append(f"  {C.G}✓{C.END} Contains uppercase letters")
    else:
        feedback.append(f"  {C.R}✗{C.END} No uppercase letters")
    
    # Lowercase
    if re.search(r'[a-z]', password):
        score += 15
        feedback.append(f"  {C.G}✓{C.END} Contains lowercase letters")
    else:
        feedback.append(f"  {C.R}✗{C.END} No lowercase letters")
    
    # Numbers
    if re.search(r'\d', password):
        score += 15
        feedback.append(f"  {C.G}✓{C.END} Contains numbers")
    else:
        feedback.append(f"  {C.R}✗{C.END} No numbers")
    
    # Special characters
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};\'"\\|,.<>/?`~]', password):
        score += 20
        feedback.append(f"  {C.G}✓{C.END} Contains special characters")
    else:
        feedback.append(f"  {C.R}✗{C.END} No special characters")
    
    # Common passwords check
    common = ['password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 
              'master', 'dragon', 'login', 'admin', 'welcome', 'letmein']
    if password.lower() in common:
        score = 0
        feedback.append(f"  {C.R}✗{C.END} This is a commonly used password!")
    
    # Entropy calculation
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'\d', password): charset += 10
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};\'"\\|,.<>/?`~]', password): charset += 32
    entropy = len(password) * (charset ** 0.5) if charset else 0
    
    # Crack time estimation
    if charset > 0:
        combinations = charset ** len(password)
        attempts_per_sec = 10_000_000_000  # 10B/s for modern GPU
        seconds = combinations / attempts_per_sec
        if seconds < 1:
            crack_time = "Instant"
        elif seconds < 60:
            crack_time = f"{seconds:.0f} seconds"
        elif seconds < 3600:
            crack_time = f"{seconds/60:.0f} minutes"
        elif seconds < 86400:
            crack_time = f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            crack_time = f"{seconds/86400:.0f} days"
        elif seconds < 31536000 * 1000:
            crack_time = f"{seconds/31536000:.0f} years"
        else:
            crack_time = f"{seconds/31536000:.0e} years"
    else:
        crack_time = "N/A"
    
    # Strength bar
    if score >= 80:
        strength = f"{C.G}STRONG{C.END}"
        bar_color = C.G
    elif score >= 50:
        strength = f"{C.Y}MEDIUM{C.END}"
        bar_color = C.Y
    else:
        strength = f"{C.R}WEAK{C.END}"
        bar_color = C.R
    
    print(f"\n  {C.BD}─── Password Analysis ───{C.END}")
    print(f"  Strength: {strength} ({score}/100)")
    print(f"  {'█' * (score // 5)}{'░' * (20 - score // 5)}")
    print(f"  Entropy:  {entropy:.1f}")
    print(f"  Crack time (GPU): {bar_color}{crack_time}{C.END}")
    print(f"  SHA256: {C.C}{hashlib.sha256(password.encode()).hexdigest()[:32]}...{C.END}")
    
    print(f"\n  {C.BD}─── Feedback ───{C.END}")
    for f in feedback:
        print(f)
    
    log_action('pass_checker', f"Checked password strength: {score}/100")

# ============================================================
# TOOL 11: Email Header Analyzer
# ============================================================
def email_analyzer():
    print(f"\n{C.BD}{C.C}  ╔══════════════════════════════════╗")
    print(f"  ║   📧 EMAIL HEADER ANALYZER       ║")
    print(f"  ╚══════════════════════════════════╝{C.END}\n")
    
    print(f"  {C.Y}Paste email headers (Ctrl+D when done):{C.END}\n")
    
    lines = []
    try:
        while True:
            line = input()
            lines.append(line)
    except EOFError:
        pass
    except KeyboardInterrupt:
        pass
    
    headers = '\n'.join(lines)
    if not headers.strip():
        print(f"  {C.R}[!] No headers provided{C.END}")
        return
    
    print(f"\n  {C.BD}─── Header Analysis ───{C.END}")
    
    # Parse key headers
    important = ['From', 'To', 'Subject', 'Date', 'Received', 'DKIM-Signature', 
                 'SPF', 'Authentication-Results', 'X-Spam-Score', 'Return-Path',
                 'X-Mailer', 'Message-ID']
    
    for line in headers.split('\n'):
        for key in important:
            if line.lower().startswith(key.lower() + ':'):
                print(f"  {C.C}{key}:{C.END} {line.split(':', 1)[1].strip()[:80]}")
                break
    
    # Check for suspicious indicators
    print(f"\n  {C.BD}─── Security Check ───{C.END}")
    
    if 'spf=pass' in headers.lower() or 'dkim=pass' in headers.lower():
        print(f"  {C.G}✓{C.END} SPF/DKIM authentication passed")
    elif 'spf=fail' in headers.lower() or 'dkim=fail' in headers.lower():
        print(f"  {C.R}✗{C.END} SPF/DKIM authentication FAILED — likely spoofed!")
    else:
        print(f"  {C.Y}~{C.END} No SPF/DKIM records found")
    
    # Extract IPs from Received headers
    ips = re.findall(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', headers)
    if ips:
        print(f"\n  {C.BD}─── Source IPs ───{C.END}")
        for ip in set(ips):
            print(f"  • {ip}")

# ============================================================
# TOOL 12: URL Expander & Checker
# ============================================================
def url_checker():
    print(f"\n{C.BD}{C.C}  ╔══════════════════════════════════╗")
    print(f"  ║   🔗 URL EXPANDER & CHECKER      ║")
    print(f"  ╚══════════════════════════════════╝{C.END}\n")
    
    url = input(f"  {C.W}Enter URL: {C.END}").strip()
    if not url:
        return
    
    if not url.startswith('http'):
        url = 'http://' + url
    
    print(f"\n  {C.Y}[*] Analyzing URL...{C.END}\n")
    
    # Expand short URLs
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        req.get_method = lambda: 'HEAD'
        with urllib.request.urlopen(req, timeout=10) as resp:
            final_url = resp.url
            if final_url != url:
                print(f"  {C.Y}[*] Short URL expanded:{C.END}")
                print(f"  Original: {url}")
                print(f"  Final:    {C.G}{final_url}{C.END}")
            else:
                print(f"  URL: {final_url}")
    except urllib.error.HTTPError as e:
        print(f"  {C.R}HTTP Error: {e.code} {e.reason}{C.END}")
    except Exception as e:
        print(f"  {C.R}Error: {e}{C.END}")
    
    # Parse URL components
    parsed = urllib.parse.urlparse(url if '://' in url else 'http://' + url)
    print(f"\n  {C.BD}─── URL Components ───{C.END}")
    print(f"  Scheme:   {parsed.scheme}")
    print(f"  Domain:   {parsed.netloc}")
    print(f"  Path:     {parsed.path or '/'}")
    print(f"  Query:    {parsed.query or 'None'}")
    print(f"  Fragment: {parsed.fragment or 'None'}")
    
    # Check for suspicious patterns
    print(f"\n  {C.BD}─── Security Check ───{C.END}")
    suspicious = False
    
    if parsed.scheme != 'https':
        print(f"  {C.R}✗{C.END} Not using HTTPS")
        suspicious = True
    
    # IP-based URL
    if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc):
        print(f"  {C.R}✗{C.END} IP-based URL (potential phishing)")
        suspicious = True
    
    # Suspicious TLD
    sus_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
    if any(parsed.netloc.endswith(t) for t in sus_tlds):
        print(f"  {C.R}✗{C.END} Suspicious TLD detected")
        suspicious = True
    
    # Long URL
    if len(url) > 100:
        print(f"  {C.Y}~{C.END} Very long URL (possible obfuscation)")
    
    # @ in URL
    if '@' in url:
        print(f"  {C.R}✗{C.END} URL contains '@' (URL spoofing technique)")
        suspicious = True
    
    if not suspicious:
        print(f"  {C.G}✓{C.END} No obvious suspicious patterns detected")

# ============================================================
# TOOL 13: Tor Checker
# ============================================================
def tor_checker():
    print(f"\n{C.BD}{C.C}  ╔══════════════════════════════════╗")
    print(f"  ║   🧅 TOR CHECKER                 ║")
    print(f"  ╚══════════════════════════════════╝{C.END}\n")
    
    print(f"  {C.G}[1]{C.W} Check if I'm using Tor")
    print(f"  {C.G}[2]{C.W} Check if IP is a Tor exit node")
    print(f"  {C.G}[3]{C.W} Check Tor relay status")
    
    choice = input(f"\n  {C.W}Choice: {C.END}").strip()
    
    if choice == '1':
        print(f"\n  {C.Y}[*] Checking Tor status...{C.END}\n")
        try:
            req = urllib.request.Request('https://check.torproject.org/', 
                                         headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as resp:
                html = resp.read().decode()
                if 'Congratulations' in html:
                    print(f"  {C.G}[✓] You ARE using Tor! 🧅{C.END}")
                elif 'Sorry' in html:
                    print(f"  {C.R}[✗] You are NOT using Tor{C.END}")
                else:
                    # Alternative check
                    try:
                        req2 = urllib.request.Request('https://check.torproject.org/api/ip',
                                                       headers={'User-Agent': 'CyberForge'})
                        with urllib.request.urlopen(req2, timeout=10) as resp2:
                            data = json.loads(resp2.read())
                            if data.get('IsTor'):
                                print(f"  {C.G}[✓] You ARE using Tor!{C.END}")
                            else:
                                print(f"  {C.R}[✗] You are NOT using Tor{C.END}")
                            print(f"  IP: {data.get('IP', 'Unknown')}")
                    except:
                        print(f"  {C.Y}[*] Could not determine Tor status{C.END}")
        except Exception as e:
            print(f"  {C.R}[!] Error: {e}{C.END}")
    
    elif choice == '2':
        ip = input(f"  Enter IP to check: ").strip()
        if not validate_ip(ip):
            print(f"  {C.R}[!] Invalid IP{C.END}")
            return
        try:
            req = urllib.request.Request(f'https://check.torproject.org/torbulkexitlist',
                                         headers={'User-Agent': 'CyberForge'})
            with urllib.request.urlopen(req, timeout=15) as resp:
                exits = resp.read().decode().strip().split('\n')
                if ip in exits:
                    print(f"  {C.R}[!]{C.END} {ip} is a {C.R}Tor exit node{C.END}")
                else:
                    print(f"  {C.G}[✓]{C.END} {ip} is {C.G}NOT{C.END} a Tor exit node")
        except Exception as e:
            print(f"  {C.R}[!] Error: {e}{C.END}")

# ============================================================
# TOOL 14: IP Geolocation
# ============================================================
def ip_geolocation():
    print(f"\n{C.BD}{C.C}  ╔══════════════════════════════════╗")
    print(f"  ║   📋 IP GEOLOCATION              ║")
    print(f"  ╚══════════════════════════════════╝{C.END}\n")
    
    ip = input(f"  {C.W}Enter IP address (or 'me' for your IP): {C.END}").strip()
    
    if ip.lower() == 'me' or ip == '':
        try:
            req = urllib.request.Request('https://api.ipify.org?format=json',
                                         headers={'User-Agent': 'CyberForge'})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                ip = data['ip']
                print(f"  Your public IP: {C.G}{ip}{C.END}")
        except:
            print(f"  {C.R}[!] Could not determine your IP{C.END}")
            return
    elif not validate_ip(ip):
        print(f"  {C.R}[!] Invalid IP address{C.END}")
        return
    
    print(f"\n  {C.Y}[*] Looking up {ip}...{C.END}\n")
    
    try:
        req = urllib.request.Request(f'http://ip-api.com/json/{ip}',
                                     headers={'User-Agent': 'CyberForge'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            
            if data.get('status') == 'success':
                print(f"  {C.BD}─── Geolocation Info ───{C.END}")
                print(f"  IP:          {C.G}{data.get('query')}{C.END}")
                print(f"  Country:     {data.get('country')} ({data.get('countryCode')})")
                print(f"  Region:      {data.get('regionName')}")
                print(f"  City:        {data.get('city')}")
                print(f"  Zip:         {data.get('zip')}")
                print(f"  Lat/Lon:     {data.get('lat')}, {data.get('lon')}")
                print(f"  Timezone:    {data.get('timezone')}")
                print(f"  ISP:         {data.get('isp')}")
                print(f"  Org:         {data.get('org')}")
                print(f"  AS:          {data.get('as')}")
                
                save_report('ip_geo', data)
            else:
                print(f"  {C.R}[!] Lookup failed: {data.get('message', 'Unknown error')}{C.END}")
    except Exception as e:
        print(f"  {C.R}[!] Error: {e}{C.END}")

# ============================================================
# TOOL 15: Cipher Tools
# ============================================================
def cipher_tools():
    print(f"\n{C.BD}{C.C}  ╔══════════════════════════════════╗")
    print(f"  ║   🧩 CIPHER TOOLS                ║")
    print(f"  ╚══════════════════════════════════╝{C.END}\n")
    
    print(f"  {C.G}[1]{C.W} Caesar Cipher")
    print(f"  {C.G}[2]{C.W} ROT13")
    print(f"  {C.G}[3]{C.W} Base64 Encode/Decode")
    print(f"  {C.G}[4]{C.W} Vigenère Cipher")
    print(f"  {C.G}[5]{C.W} XOR Cipher")
    print(f"  {C.G}[6]{C.W} Atbash Cipher")
    print(f"  {C.G}[7]{C.W} Binary/Hex/ASCII Converter")
    
    choice = input(f"\n  {C.W}Choice: {C.END}").strip()
    
    if choice == '1':
        # Caesar Cipher
        text = input(f"  Enter text: ").strip()
        shift = input(f"  Enter shift (1-25): ").strip()
        mode = input(f"  Encrypt (e) or Decrypt (d)? ").strip().lower()
        
        try:
            shift = int(shift) % 26
            if mode == 'd':
                shift = -shift
            
            result = ''
            for c in text:
                if c.isalpha():
                    base = ord('A') if c.isupper() else ord('a')
                    result += chr((ord(c) - base + shift) % 26 + base)
                else:
                    result += c
            
            print(f"\n  Result: {C.G}{result}{C.END}")
        
        except ValueError:
            print(f"  {C.R}[!] Invalid shift value{C.END}")
    
    elif choice == '2':
        # ROT13
        text = input(f"  Enter text: ").strip()
        result = text.translate(str.maketrans(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))
        print(f"\n  Result: {C.G}{result}{C.END}")
    
    elif choice == '3':
        # Base64
        text = input(f"  Enter text: ").strip()
        mode = input(f"  Encode (e) or Decode (d)? ").strip()
        
        try:
            if mode == 'e':
                result = base64.b64encode(text.encode()).decode()
            else:
                result = base64.b64decode(text.encode()).decode()
            print(f"\n  Result: {C.G}{result}{C.END}")
        except:
            print(f"  {C.R}[!] Invalid input{C.END}")
    
    elif choice == '4':
        # Vigenère
        text = input(f"  Enter text: ").strip()
        key = input(f"  Enter key: ").strip().upper()
        mode = input(f"  Encrypt (e) or Decrypt (d)? ").strip()
        
        result = ''
        key_idx = 0
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                shift = ord(key[key_idx % len(key)]) - ord('A')
                if mode == 'd':
                    shift = -shift
                result += chr((ord(c) - base + shift) % 26 + base)
                key_idx += 1
            else:
                result += c
        
        print(f"\n  Result: {C.G}{result}{C.END}")
    
    elif choice == '5':
        # XOR
        text = input(f"  Enter text: ").strip()
        key = input(f"  Enter key: ").strip()
        
        result = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))
        print(f"\n  Result: {C.G}{result}{C.END}")
        print(f"  Hex:    {C.C}{result.encode().hex()}{C.END}")
    
    elif choice == '6':
        # Atbash
        text = input(f"  Enter text: ").strip()
        result = ''
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                result += chr(ord('Z') - (ord(c) - base)) if c.isupper() else chr(ord('z') - (ord(c) - base))
            else:
                result += c
        print(f"\n  Result: {C.G}{result}{C.END}")
    
    elif choice == '7':
        # Binary/Hex/ASCII Converter
        text = input(f"  Enter text: ").strip()
        print(f"\n  ASCII:  {C.C}{', '.join(str(ord(c)) for c in text)}{C.END}")
        print(f"  Hex:    {C.C}{text.encode().hex()}{C.END}")
        print(f"  Binary: {C.C}{' '.join(format(ord(c), '08b') for c in text)}{C.END}")
        print(f"  Octal:  {C.C}{' '.join(format(ord(c), '03o') for c in text)}{C.END}")

# ============================================================
# TOOL 16: SQL Injection Tester
# ============================================================
def sqli_tester():
    print(f"\n{C.BD}{C.C}  ╔══════════════════════════════════╗")
    print(f"  ║   💉 SQL INJECTION TESTER         ║")
    print(f"  ╚══════════════════════════════════╝{C.END}\n")
    
    url = input(f"  {C.W}Enter URL with parameter (e.g., https://site.com/page?id=1): {C.END}").strip()
    
    if not url:
        print(f"  {C.R}[!] URL required{C.END}")
        return
    
    print(f"\n  {C.Y}[*] Testing SQL injection on {url}...{C.END}\n")
    print(f"  {C.R}[!] Only test on authorized targets!{C.END}\n")
    
    payloads = [
        "'", "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
        "1' OR '1'='1", "1' OR '1'='1'--", "1' OR '1'='1'/*",
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
        "1; DROP TABLE users--", "' OR 1=1#", "admin'--",
        "1' AND '1'='1", "1' AND '1'='2",
        "' AND SUBSTRING(@@version,1,1)='5",
        "1' WAITFOR DELAY '0:0:5'--",
    ]
    
    error_patterns = [
        'sql syntax', 'mysql', 'warning', 'error in your sql',
        'unclosed quotation', 'sqlcommand', 'postgresql',
        'ORA-', 'Microsoft OLE DB', 'ODBC', 'SQL Server',
        'syntax error', 'query failed', 'sqlstate',
        'mysqli_', 'mysql_fetch', 'pg_query',
        'sqlite_', 'sql error', 'invalid query',
    ]
    
    vuln = False
    
    for payload in payloads:
        test_url = url + urllib.parse.quote(payload)
        try:
            req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as resp:
                html = resp.read().decode('utf-8', errors='ignore').lower()
                
                for pattern in error_patterns:
                    if pattern.lower() in html:
                        print(f"  {C.R}[!]{C.END} Potential SQLi with: {C.Y}{payload}{C.END}")
                        print(f"       Error pattern: {C.R}{pattern}{C.END}")
                        vuln = True
                        break
        except urllib.error.HTTPError as e:
            if e.code in [500, 403]:
                print(f"  {C.Y}~{C.END} HTTP {e.code} with: {payload}")
        except:
            pass
    
    if not vuln:
        print(f"  {C.G}[✓] No obvious SQL injection vulnerabilities detected{C.END}")
    else:
        print(f"\n  {C.R}[!] VULNERABLE! SQL injection may be possible!{C.END}")
        print(f"  {C.Y}[*] Further manual testing recommended{C.END}")
    
    save_report('sqli_test', {'url': url, 'vulnerable': vuln})
    log_action('sqli_tester', f"Tested {url}, vulnerable: {vuln}")

# ============================================================
# TOOL 17: Web Crawler
# ============================================================
def web_crawler():
    print(f"\n{C.BD}{C.C}  ╔══════════════════════════════════╗")
    print(f"  ║   🕷️ WEB CRAWLER                  ║")
    print(f"  ╚══════════════════════════════════╝{C.END}\n")
    
    url = input(f"  {C.W}Enter URL to crawl: {C.END}").strip()
    depth = input(f"  {C.W}Max depth (1-3): {C.END}").strip() or '1'
    
    if not url:
        return
    
    try:
        depth = int(depth)
    except:
        depth = 1
    
    visited = set()
    links = set()
    emails = set()
    phones = set()
    
    def crawl(target_url, current_depth):
        if current_depth > depth or target_url in visited:
            return
        visited.add(target_url)
        
        try:
            req = urllib.request.Request(target_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as resp:
                html = resp.read().decode('utf-8', errors='ignore')
        except:
            return
        
        # Find links
        found_links = re.findall(r'href=["\'](https?://[^"\'>]+)', html, re.IGNORECASE)
        for link in found_links:
            links.add(link)
        
        # Find emails
        found_emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html)
        emails.update(found_emails)
        
        # Find phone numbers
        found_phones = re.findall(r'(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}', html)
        phones.update(found_phones)
        
        print(f"  {C.G}[✓]{C.END} Crawled: {target_url[:60]}... (depth {current_depth})")
        
        # Crawl found links
        if current_depth < depth:
            for link in list(found_links)[:5]:  # Limit per depth
                if link not in visited:
                    crawl(link, current_depth + 1)
    
    print(f"\n  {C.Y}[*] Crawling {url} (depth: {depth})...{C.END}\n")
    crawl(url, 1)
    
    print(f"\n  {C.BD}─── Results ───{C.END}")
    print(f"  Pages crawled: {len(visited)}")
    print(f"  Links found:   {C.C}{len(links)}{C.END}")
    print(f"  Emails found:  {C.G}{len(emails)}{C.END}")
    print(f"  Phones found:  {C.Y}{len(phones)}{C.END}")
    
    if emails:
        print(f"\n  {C.BD}─── Emails ───{C.END}")
        for email in emails:
            print(f"  📧 {email}")
    
    if links:
        print(f"\n  {C.BD}─── Top Links ───{C.END}")
        for link in sorted(links)[:20]:
            print(f"  🔗 {link[:80]}")
    
    save_report('web_crawl', {'url': url, 'links': list(links), 'emails': list(emails)})
    log_action('web_crawler', f"Crawled {url}, found {len(links)} links, {len(emails)} emails")

# ============================================================
# TOOL 18: SSL/TLS Analyzer
# ============================================================
def ssl_analyzer():
    print(f"\n{C.BD}{C.C}  ╔══════════════════════════════════╗")
    print(f"  ║   📦 SSL/TLS ANALYZER            ║")
    print(f"  ╚══════════════════════════════════╝{C.END}\n")
    
    domain = input(f"  {C.W}Enter domain: {C.END}").strip()
    if not domain:
        return
    
    domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
    
    print(f"\n  {C.Y}[*] Analyzing SSL/TLS for {domain}...{C.END}\n")
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()
        
        print(f"  {C.BD}─── Certificate Info ───{C.END}")
        
        # Subject
        subject = dict(x[0] for x in cert.get('subject', []))
        print(f"  Organization: {subject.get('organizationName', 'N/A')}")
        print(f"  Common Name:  {subject.get('commonName', 'N/A')}")
        print(f"  Country:      {subject.get('countryName', 'N/A')}")
        
        # Issuer
        issuer = dict(x[0] for x in cert.get('issuer', []))
        print(f"  Issuer:       {issuer.get('organizationName', 'N/A')}")
        print(f"  Issuer CN:    {issuer.get('commonName', 'N/A')}")
        
        # Validity
        not_before = cert.get('notBefore', 'N/A')
        not_after = cert.get('notAfter', 'N/A')
        print(f"  Valid From:   {not_before}")
        print(f"  Valid Until:  {not_after}")
        
        # Check expiry
        if 'notAfter' in cert:
            try:
                expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry - datetime.now()).days
                if days_left < 0:
                    print(f"  Status:       {C.R}EXPIRED ({abs(days_left)} days ago){C.END}")
                elif days_left < 30:
                    print(f"  Status:       {C.Y}Expiring soon ({days_left} days left){C.END}")
                else:
                    print(f"  Status:       {C.G}Valid ({days_left} days remaining){C.END}")
            except:
                pass
        
        # SAN
        san = cert.get('subjectAltName', [])
        if san:
            print(f"\n  {C.BD}─── Subject Alternative Names ───{C.END}")
            for type_, value in san[:10]:
                print(f"  {type_}: {C.C}{value}{C.END}")
        
        # Protocol & Cipher
        print(f"\n  {C.BD}─── Connection Security ───{C.END}")
        print(f"  Protocol:     {C.G}{protocol}{C.END}")
        print(f"  Cipher:       {C.G}{cipher[0]}{C.END}")
        print(f"  Key Size:     {cipher[2]} bits")
        
        # Security assessment
        print(f"\n  {C.BD}─── Security Assessment ───{C.END}")
        if protocol in ['TLSv1.2', 'TLSv1.3']:
            print(f"  {C.G}✓{C.END} Modern TLS protocol")
        elif protocol in ['TLSv1.1', 'TLSv1.0']:
            print(f"  {C.R}✗{C.END} Outdated TLS protocol! Upgrade recommended")
        
        if cipher[2] >= 256:
            print(f"  {C.G}✓{C.END} Strong cipher key size")
        elif cipher[2] >= 128:
            print(f"  {C.Y}~{C.END} Adequate cipher key size")
        else:
            print(f"  {C.R}✗{C.END} Weak cipher key size")
        
        save_report('ssl_analyze', {'domain': domain, 'protocol': protocol, 'cipher': cipher[0]})
        
    except ssl.SSLError as e:
        print(f"  {C.R}[!] SSL Error: {e}{C.END}")
    except Exception as e:
        print(f"  {C.R}[!] Error: {e}{C.END}")
    
    log_action('ssl_analyzer', f"Analyzed SSL for {domain}")
