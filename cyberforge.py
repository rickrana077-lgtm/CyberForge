#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║     ██████╗██╗   ██╗██████╗ ███████╗██████╗             ║
║    ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗            ║
║    ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝            ║
║    ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗            ║
║    ╚██████╗   ██║   ██████╔╝███████╗██║  ██║            ║
║     ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝            ║
║                                                          ║
║          CyberForge - Advanced Security Toolkit           ║
║                    v2.0.0                                ║
║                                                          ║
║    [!] For Educational & Authorized Testing Only         ║
║    [!] Unauthorized use is illegal                       ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
"""

import os
import sys
import time
import json
import argparse
from datetime import datetime

# Colors
class C:
    R = '\033[91m'    # Red
    G = '\033[92m'    # Green
    Y = '\033[93m'    # Yellow
    B = '\033[94m'    # Blue
    M = '\033[95m'    # Magenta
    C = '\033[96m'    # Cyan
    W = '\033[97m'    # White
    BD = '\033[1m'    # Bold
    END = '\033[0m'   # Reset

def banner():
    os.system('clear' if os.name != 'nt' else 'cls')
    print(f"""{C.C}
╔══════════════════════════════════════════════════════════╗
║     ██████╗██╗   ██╗██████╗ ███████╗██████╗             ║
║    ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗            ║
║    ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝            ║
║    ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗            ║
║    ╚██████╗   ██║   ██████╔╝███████╗██║  ██║            ║
║     ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝            ║
║          {C.W}CyberForge - Advanced Security Toolkit{C.C}           ║
║                    {C.G}v2.0.0{C.C}                          ║
╚══════════════════════════════════════════════════════════╝{C.END}
""")

def menu():
    print(f"""{C.BD}{C.C}  ┌─────────────────────────────────────────────┐
  │              🔐 MAIN MENU                   │
  └─────────────────────────────────────────────┘{C.END}

  {C.G}[01]{C.W} 🔍 Network Scanner          {C.G}[10]{C.W} 🔑 Password Strength Checker
  {C.G}[02]{C.W} 🌐 Port Scanner             {C.G}[11]{C.W} 📧 Email Header Analyzer
  {C.G}[03]{C.W} 🕵️ WHOIS Lookup            {C.G}[12]{C.W} 🔗 URL Expander & Checker
  {C.G}[04]{C.W} 📡 DNS Reconnaissance       {C.G}[13]{C.W} 🧅 Tor Checker
  {C.G}[05]{C.W} 🖥️ Subdomain Enumerator     {C.G}[14]{C.W} 📋 IP Geolocation
  {C.G}[06]{C.W} 🔐 Hash Generator/Cracker   {C.G}[15]{C.W} 🧩 Cipher Tools
  {C.G}[07]{C.W} 📊 Web Technology Detector  {C.G}[16]{C.W} 💉 SQL Injection Tester
  {C.G}[08]{C.W} 🔥 Firewall Tester          {C.G}[17]{C.W} 🕷️ Web Crawler
  {C.G}[09]{C.W} 📡 WiFi Scanner             {C.G}[18]{C.W} 📦 SSL/TLS Analyzer

  {C.Y}[00]{C.W} Exit
""")

def get_choice():
    try:
        choice = input(f"\n{C.BD}{C.C}[CyberForge]{C.W} > ").strip()
        return choice
    except (KeyboardInterrupt, EOFError):
        print(f"\n{C.Y}[*] Exiting CyberForge...{C.END}")
        sys.exit(0)

def main():
    banner()
    
    parser = argparse.ArgumentParser(description='CyberForge - Advanced Security Toolkit')
    parser.add_argument('-t', '--tool', help='Run specific tool directly')
    parser.add_argument('-l', '--list', action='store_true', help='List all tools')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode')
    args = parser.parse_args()
    
    if args.list:
        print(f"{C.C}Available Tools:{C.END}")
        print("  01. network_scanner   - Network Scanner")
        print("  02. port_scanner      - Port Scanner")
        print("  03. whois_lookup      - WHOIS Lookup")
        print("  04. dns_recon         - DNS Reconnaissance")
        print("  05. subdomain_enum    - Subdomain Enumerator")
        print("  06. hash_tool         - Hash Generator/Cracker")
        print("  07. web_tech_detect   - Web Technology Detector")
        print("  08. firewall_tester   - Firewall Tester")
        print("  09. wifi_scanner      - WiFi Scanner")
        print("  10. pass_checker      - Password Strength Checker")
        print("  11. email_analyzer    - Email Header Analyzer")
        print("  12. url_checker       - URL Expander & Checker")
        print("  13. tor_checker       - Tor Checker")
        print("  14. ip_geolocation    - IP Geolocation")
        print("  15. cipher_tools      - Cipher Tools")
        print("  16. sqli_tester       - SQL Injection Tester")
        print("  17. web_crawler       - Web Crawler")
        print("  18. ssl_analyzer      - SSL/TLS Analyzer")
        return

    if args.tool:
        run_tool(args.tool)
        return

    while True:
        menu()
        choice = get_choice()
        
        actions = {
            '01': 'network_scanner', '1': 'network_scanner',
            '02': 'port_scanner', '2': 'port_scanner',
            '03': 'whois_lookup', '3': 'whois_lookup',
            '04': 'dns_recon', '4': 'dns_recon',
            '05': 'subdomain_enum', '5': 'subdomain_enum',
            '06': 'hash_tool', '6': 'hash_tool',
            '07': 'web_tech_detect', '7': 'web_tech_detect',
            '08': 'firewall_tester', '8': 'firewall_tester',
            '09': 'wifi_scanner', '9': 'wifi_scanner',
            '10': 'pass_checker',
            '11': 'email_analyzer',
            '12': 'url_checker',
            '13': 'tor_checker',
            '14': 'ip_geolocation',
            '15': 'cipher_tools',
            '16': 'sqli_tester',
            '17': 'web_crawler',
            '18': 'ssl_analyzer',
            '00': 'exit', '0': 'exit',
        }
        
        tool = actions.get(choice)
        if tool == 'exit':
            print(f"\n{C.G}[✓] Thank you for using CyberForge. Stay safe! 🔐{C.END}")
            break
        elif tool:
            run_tool(tool)
        else:
            print(f"{C.R}[!] Invalid choice. Try again.{C.END}")
            time.sleep(1)
        
        banner()

def run_tool(tool_name):
    """Run a specific tool by name"""
    try:
        tool_map = {
            'network_scanner': 'tools.network_scanner',
            'port_scanner': 'tools.port_scanner',
            'whois_lookup': 'tools.whois_lookup',
            'dns_recon': 'tools.dns_recon',
            'subdomain_enum': 'tools.subdomain_enum',
            'hash_tool': 'tools.hash_tool',
            'web_tech_detect': 'tools.web_tech_detect',
            'firewall_tester': 'tools.firewall_tester',
            'wifi_scanner': 'tools.wifi_scanner',
            'pass_checker': 'tools.pass_checker',
            'email_analyzer': 'tools.email_analyzer',
            'url_checker': 'tools.url_checker',
            'tor_checker': 'tools.tor_checker',
            'ip_geolocation': 'tools.ip_geolocation',
            'cipher_tools': 'tools.cipher_tools',
            'sqli_tester': 'tools.sqli_tester',
            'web_crawler': 'tools.web_crawler',
            'ssl_analyzer': 'tools.ssl_analyzer',
        }
        
        module_name = tool_map.get(tool_name)
        if not module_name:
            print(f"{C.R}[!] Tool '{tool_name}' not found.{C.END}")
            return
            
        # Import and run
        parts = module_name.split('.')
        module = __import__(parts[0])
        func = getattr(module, parts[1])
        func()
        
    except Exception as e:
        print(f"{C.R}[!] Error running tool: {e}{C.END}")
    
    input(f"\n{C.Y}[*] Press Enter to continue...{C.END}")

if __name__ == '__main__':
    main()
