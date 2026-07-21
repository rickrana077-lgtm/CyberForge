# 🔐 CyberForge — Advanced Security Toolkit

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0.0-cyan?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20Mac-orange?style=for-the-badge" />
</p>

```
    ██████╗██╗   ██╗██████╗ ███████╗██████╗
   ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
   ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝
   ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗
   ╚██████╗   ██║   ██████╔╝███████╗██║  ██║
    ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝
         CyberForge - Advanced Security Toolkit v2.0
```

## 🛡️ About

CyberForge is a comprehensive, Python-based cybersecurity toolkit designed for **penetration testing, security auditing, and network reconnaissance**. It provides 18+ powerful security tools in a single, easy-to-use interface.

> ⚠️ **Disclaimer**: This tool is for **educational and authorized testing purposes only**. Unauthorized use against systems you do not own or have permission to test is **illegal**. The developers assume no liability for misuse.

---

## ✨ Features

### 🔍 Reconnaissance
| # | Tool | Description |
|---|------|-------------|
| 01 | **Network Scanner** | Discover hosts on a network |
| 02 | **Port Scanner** | Identify open ports & services |
| 03 | **WHOIS Lookup** | Domain registration information |
| 04 | **DNS Recon** | DNS record enumeration |
| 05 | **Subdomain Enum** | Find subdomains + Certificate Transparency |
| 14 | **IP Geolocation** | Geo-locate any IP address |

### 🔐 Cryptography
| # | Tool | Description |
|---|------|-------------|
| 06 | **Hash Tool** | Generate, crack & verify hashes (MD5/SHA1/SHA256/BLAKE2) |
| 10 | **Password Checker** | Strength analysis with crack time estimation |
| 15 | **Cipher Tools** | Caesar, ROT13, Base64, Vigenère, XOR, Atbash, Binary/Hex |

### 🌐 Web Security
| # | Tool | Description |
|---|------|-------------|
| 07 | **Web Tech Detector** | Detect technologies & security headers |
| 12 | **URL Checker** | Expand short URLs & detect phishing |
| 16 | **SQLi Tester** | Test for SQL injection vulnerabilities |
| 17 | **Web Crawler** | Crawl websites, extract emails & links |
| 18 | **SSL Analyzer** | Analyze SSL/TLS certificates & cipher strength |

### 🛡️ Network Security
| # | Tool | Description |
|---|------|-------------|
| 08 | **Firewall Tester** | Test firewall rules & OS fingerprinting |
| 09 | **WiFi Scanner** | Scan nearby WiFi networks |
| 13 | **Tor Checker** | Check Tor status & exit nodes |
| 11 | **Email Analyzer** | Analyze email headers for spoofing |

---

## 🚀 Installation

### Quick Install
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/CyberForge.git
cd CyberForge

# No external dependencies required! Uses Python standard library only
python3 cyberforge.py
```

### One-Liner
```bash
git clone https://github.com/YOUR_USERNAME/CyberForge.git && cd CyberForge && python3 cyberforge.py
```

### Direct Tool Execution
```bash
# Run a specific tool directly
python3 cyberforge.py -t port_scanner

# List all available tools
python3 cyberforge.py -l
```

---

## 📖 Usage

### Interactive Menu
```bash
python3 cyberforge.py
```

### Command Line
```bash
# Port scan a target
python3 cyberforge.py -t port_scanner

# DNS reconnaissance
python3 cyberforge.py -t dns_recon

# Check password strength
python3 cyberforge.py -t pass_checker
```

### Import as Module
```python
from tools import port_scanner, hash_tool, pass_checker

# Use individual tools in your scripts
port_scanner()
hash_tool()
pass_checker()
```

---

## 📁 Project Structure

```
CyberForge/
├── cyberforge.py          # Main entry point
├── tools/
│   ├── __init__.py        # All 18 security tools
│   └── ...
├── utils/
│   ├── __init__.py
│   ├── colors.py          # Terminal color definitions
│   └── helpers.py         # Utility functions
├── wordlists/             # Custom wordlists (add your own)
├── reports/               # Auto-generated scan reports (JSON)
├── logs/                  # Activity logs
├── requirements.txt       # (Minimal - stdlib only)
└── README.md              # This file
```

---

## 🔧 Requirements

- **Python 3.8+**
- **No external dependencies** — uses only Python standard library
- Some tools work better with:
  - `whois` command (for WHOIS lookups)
  - `dig` command (for DNS reconnaissance)
  - Root/admin privileges (for WiFi scanning)

### Optional System Packages
```bash
# Debian/Ubuntu
sudo apt install whois dnsutils nmap

# macOS (via Homebrew)
brew install whois bind nmap

# Arch Linux
sudo pacman -S whois bind nmap
```

---

## 📊 Reports

All scan results are automatically saved to the `reports/` directory as JSON files with timestamps:

```
reports/
├── port_scan_20260721_103045.json
├── dns_recon_20260721_103200.json
├── ssl_analyze_20260721_103500.json
└── ...
```

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/new-tool`)
3. Commit your changes (`git commit -m 'Add new security tool'`)
4. Push to the branch (`git push origin feature/new-tool`)
5. Open a Pull Request

### Adding a New Tool

1. Add your tool function to `tools/__init__.py`
2. Follow the existing naming convention
3. Add it to the menu in `cyberforge.py`
4. Update this README

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## ⚖️ Legal

- This tool is provided for **educational and authorized security testing only**
- Always obtain **written permission** before testing any system
- The developers are **not responsible** for any misuse or damage
- Unauthorized access to computer systems is **illegal** in most jurisdictions

---

## 🌟 Star History

If you find CyberForge useful, please consider giving it a ⭐ star!

<p align="center">
  <strong>Built with 🔐 by CyberForge Team</strong>
</p>
