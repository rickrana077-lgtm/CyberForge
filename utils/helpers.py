"""
CyberForge Helper Utilities
Common functions used across tools
"""

import os
import re
import json
import socket
import time
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.colors import C

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'reports')
LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')

def validate_ip(ip):
    """Validate IPv4 address"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    return False

def validate_domain(domain):
    """Validate domain name"""
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def validate_url(url):
    """Validate URL"""
    pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    return bool(re.match(pattern, url))

def save_report(tool_name, data):
    """Save scan results to JSON report"""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{tool_name}_{timestamp}.json"
    filepath = os.path.join(REPORTS_DIR, filename)
    
    report = {
        'tool': tool_name,
        'timestamp': datetime.now().isoformat(),
        'data': data
    }
    
    try:
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        return filepath
    except Exception as e:
        return None

def log_action(tool_name, action):
    """Log an action to the log file"""
    os.makedirs(LOGS_DIR, exist_ok=True)
    log_file = os.path.join(LOGS_DIR, f"cyberforge_{datetime.now().strftime('%Y%m%d')}.log")
    
    try:
        with open(log_file, 'a') as f:
            f.write(f"[{datetime.now().isoformat()}] [{tool_name}] {action}\n")
    except:
        pass

def loading_animation(message="Loading", duration=3):
    """Display a loading animation"""
    frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    end_time = time.time() + duration
    i = 0
    while time.time() < end_time:
        sys.stdout.write(f'\r  {C.C}{frames[i % len(frames)]}{C.END} {message}...')
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    sys.stdout.write('\r' + ' ' * (len(message) + 20) + '\r')
    sys.stdout.flush()

def get_common_ports():
    """Return list of common ports with services"""
    return [
        (21, 'FTP'), (22, 'SSH'), (23, 'Telnet'), (25, 'SMTP'),
        (53, 'DNS'), (80, 'HTTP'), (110, 'POP3'), (111, 'RPCBind'),
        (135, 'MSRPC'), (139, 'NetBIOS'), (143, 'IMAP'), (443, 'HTTPS'),
        (445, 'SMB'), (993, 'IMAPS'), (995, 'POP3S'), (1433, 'MSSQL'),
        (1521, 'Oracle'), (3306, 'MySQL'), (3389, 'RDP'), (5432, 'PostgreSQL'),
        (5900, 'VNC'), (6379, 'Redis'), (6443, 'K8s API'), (8080, 'HTTP-Alt'),
        (8443, 'HTTPS-Alt'), (8888, 'HTTP-Alt'), (9090, 'Prometheus'),
        (9200, 'Elasticsearch'), (9443, 'WSO2'), (27017, 'MongoDB'),
    ]

def get_subdomains():
    """Return common subdomain list"""
    return [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
        'dns', 'dns1', 'dns2', 'mx', 'mx1', 'mx2', 'api', 'api1', 'api2',
        'dev', 'staging', 'test', 'beta', 'alpha', 'demo', 'sandbox', 'uat',
        'admin', 'portal', 'dashboard', 'panel', 'cpanel', 'webmin', 'plesk',
        'blog', 'forum', 'wiki', 'docs', 'help', 'support', 'kb', 'knowledge',
        'shop', 'store', 'app', 'mobile', 'm', 'cdn', 'static', 'assets', 'media',
        'img', 'images', 'videos', 'files', 'download', 'uploads', 'content',
        'vpn', 'remote', 'gateway', 'proxy', 'firewall', 'router', 'switch',
        'git', 'github', 'gitlab', 'ci', 'jenkins', 'build', 'deploy', 'release',
        'db', 'database', 'mysql', 'postgres', 'mongo', 'redis', 'elastic', 'cache',
        'auth', 'login', 'sso', 'oauth', 'ldap', 'ad', 'directory',
        'monitor', 'grafana', 'kibana', 'prometheus', 'alert', 'status', 'health',
        'backup', 'archive', 'log', 'logs', 'analytics', 'tracking', 'stats',
        'intranet', 'internal', 'private', 'secure', 'ssl', 'cert',
        'news', 'press', 'media', 'events', 'careers', 'jobs', 'hr',
        'office', 'sharepoint', 'teams', 'onedrive', 'outlook', 'exchange',
        'cloud', 'aws', 'azure', 'gcp', 's3', 'storage', 'bucket',
    ]

def get_wordlist():
    """Return built-in wordlist for hash cracking"""
    common_passwords = [
        'password', '123456', '12345678', '1234', '12345', '123456789', '1234567890',
        'qwerty', 'abc123', 'password1', 'password123', 'admin', 'admin123', 'root',
        'letmein', 'welcome', 'monkey', 'dragon', 'master', 'login', 'princess',
        'football', 'shadow', 'sunshine', 'trustno1', 'iloveyou', 'batman', 'access',
        'hello', 'charlie', 'donald', 'michael', 'passwd', 'pass', 'test', 'test123',
        'guest', 'secret', 'server', 'computer', 'internet', 'service', 'oracle',
        'changeme', 'default', 'system', 'manager', 'mysql', 'postgres', 'redis',
        'supersecret', 'P@ssw0rd', 'P@ss1234', 'Passw0rd', 'Qwerty123', 'Admin123',
        'hunter2', 'baseball', 'soccer', 'hockey', 'basketball', 'jordan', 'harley',
        'ranger', 'thomas', 'robert', 'pepper', 'killer', 'george', 'asshole',
        'fuckyou', 'jessica', 'joshua', 'maverick', 'cookie', 'nicole', 'sparky',
    ]
    return common_passwords

def format_bytes(size):
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}PB"

def print_table(headers, rows, colors=None):
    """Print a formatted table"""
    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(cell)))
    
    # Print header
    header_line = '  '.join(h.ljust(w) for h, w in zip(headers, widths))
    print(f"  {C.BD}{header_line}{C.END}")
    print(f"  {'─' * len(header_line)}")
    
    # Print rows
    for row in rows:
        line = '  '.join(str(cell).ljust(w) for cell, w in zip(row, widths))
        print(f"  {line}")
