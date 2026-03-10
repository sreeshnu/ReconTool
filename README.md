# 🔍 ReconTool — Full Reconnaissance & Vulnerability Scanner

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Ubuntu-green?style=flat-square&logo=linux)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

> A comprehensive, beginner-friendly reconnaissance and vulnerability assessment tool that gathers **maximum information** about a target and generates a **clean PDF/HTML report** with plain-English explanations.

---

## ✨ Features

### 🌐 Network Intelligence
- Port scanning (common ports or full 1-1024 range)
- Service & version detection via banner grabbing
- Host alive detection (ICMP ping)
- Risk scoring per open port (Critical / High / Medium / Low)
- OS fingerprinting hints

### 🔎 DNS Intelligence
- Full DNS record enumeration (A, MX, NS, TXT, CNAME, SOA)
- WHOIS information lookup
- Subdomain enumeration (50+ common subdomains)
- DNS Zone Transfer vulnerability check
- Reverse DNS lookup

### 🌍 Web Application Intelligence
- HTTP/HTTPS header analysis
- Security headers audit (HSTS, CSP, X-Frame-Options, etc.)
- Technology stack detection
- SSL/TLS certificate analysis (expiry, version, cipher)
- robots.txt analysis for sensitive paths

### 🕵️ OSINT Intelligence
- IP Geolocation (City, Country, Organization, Timezone)
- ASN (Autonomous System Number) lookup
- Exposed admin panel detection (50+ paths)
- Sensitive file exposure check (.env, .git, config files)
- Email pattern generation
- Shodan/Censys reference links

### 📄 Reporting
- Beautiful **HTML report** (opens in any browser)
- **PDF report** (requires wkhtmltopdf or Chromium)
- Optional **JSON export** for further analysis
- Color-coded severity levels
- Plain English explanations for every finding
- Actionable recommendations

---

## 🚀 Installation

### Requirements
- Python 3.8+
- Kali Linux / Ubuntu (recommended)
- `dig`, `whois` (usually pre-installed on Kali)

### Clone & Run
```bash
# Clone the repository
git clone https://github.com/yourusername/recontool.git
cd recontool

# (Optional) Install PDF support
sudo apt install wkhtmltopdf

# Run a scan
python3 main.py -t example.com
```

---

## 📖 Usage

```bash
# Full scan with PDF report
python3 main.py -t example.com

# Scan an IP address
python3 main.py -t 192.168.1.1

# Extended port scan (1-1024)
python3 main.py -t example.com --ports extended

# Skip specific modules
python3 main.py -t example.com --no-osint
python3 main.py -t example.com --no-dns --no-web

# Save JSON output too
python3 main.py -t example.com --json

# Custom output directory
python3 main.py -t example.com --output-dir /home/user/scans
```

### All Options
```
-t, --target       Target IP or domain (required)
--ports            common (default) or extended (1-1024)
--no-network       Skip port scanning
--no-dns           Skip DNS recon
--no-web           Skip web recon
--no-osint         Skip OSINT
--json             Save raw JSON results
--output-dir       Report output directory
```

---

## 📊 Sample Report

The tool generates a professional HTML/PDF report including:

- 🔴 **Critical** findings (immediate action required)
- 🟠 **High** severity issues
- 🟡 **Medium** severity issues  
- 🟢 **Low** severity / informational findings
- Plain English explanation for every finding
- Specific fix recommendations

---

## 🗂️ Project Structure

```
recontool/
├── main.py                    # Main entry point
├── modules/
│   ├── network_scan.py        # Port scanning & service detection
│   ├── dns_recon.py           # DNS enumeration & WHOIS
│   ├── web_recon.py           # Web headers, SSL, tech detection
│   ├── osint.py               # Geolocation, admin panels, OSINT
│   └── report_generator.py   # HTML & PDF report generation
├── reports/                   # Generated reports saved here
└── README.md
```

---

## ⚙️ How It Works

1. **Network Module** — Uses Python's `socket` library with multi-threading for fast port scanning
2. **DNS Module** — Uses `dig` and `whois` system commands via subprocess
3. **Web Module** — Uses Python's `urllib` for HTTP requests and SSL analysis
4. **OSINT Module** — Uses free geolocation APIs and custom path checking
5. **Report Generator** — Builds a full HTML report, converts to PDF via wkhtmltopdf

---

## ⚖️ Legal Disclaimer

> **This tool is for authorized security testing only.**
> Scanning systems, networks, or web applications **without explicit written permission** is illegal under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent laws in most countries.
> 
> **Always obtain proper authorization before scanning any target.**
> The developer assumes no liability for misuse of this tool.

---

## 🛠️ Tested On

- Kali Linux 2023+
- Ubuntu 20.04 / 22.04
- Python 3.8, 3.10, 3.12

---

## 🤝 Contributing

Pull requests are welcome! Feel free to:
- Add new scanning modules
- Improve detection signatures
- Enhance the report design
- Add new OSINT sources

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built with 🐍 Python | Made for the cybersecurity community*
