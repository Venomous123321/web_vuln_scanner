# 🔍 Advanced Web Application Vulnerability Scanner

**Author:** Sudipta  
**Version:** 1.0  
**Language:** Python 3  
**Status:** ✅ Fully Functional | 🎯 GitHub-Ready

---

## 🧠 Overview

This is a **comprehensive, real-time web vulnerability scanner** built for professionals, ethical hackers, CTF players, and researchers. It performs automated analysis of web applications to detect a wide range of vulnerabilities, following OWASP Top 10 standards and beyond.

It supports:
- Multiple scan modes
- Advanced AI-style fix recommendations
- Proof-of-Concept (PoC) generation
- Visual intelligence capture
- HTML, TXT, JSON, CSV reporting
- CLI interface with full control

---

## 🚀 Features

| Category                  | Capabilities                                                                 |
|---------------------------|------------------------------------------------------------------------------|
| 🔎 Scanner Modes          | Quick Scan, Deep AI Scan, Custom Level Scan, CTF Flag Finder                 |
| 🧪 Vulnerabilities        | XSS, SQLi, CSRF, LFI, RCE, SSRF, File Upload, Cookie Poisoning, etc.         |
| 🔐 Security Headers       | Checks for missing X-Frame-Options, CSP, etc.                                |
| 🛡️ WAF/CDN Detection      | Detects Cloudflare, Akamai, and more                                         |
| 🧬 Advanced Intelligence  | WHOIS, DNS enumeration, ASN, GeoIP, Subdomains, Port scan, Banner grabbing   |
| 🎯 Exploit Generator      | Generates PoCs in HTML, Python, Bash, and cURL                               |
| 🧠 AI Fix Recommender     | Explains each finding and gives a fix                                        |
| 📊 Reporting              | HTML, JSON, TXT, CSV with severity mapping                                   |
| 🌐 Visual Engine          | DOM snapshots, console logs, screenshots                                     |
| 🔧 Configurable CLI       | Headless, proxy, multi-tab, config file support                              |
---

## 🛠️ Installation

### 🔗 Prerequisites

- Python 3.8+
- Google Chrome or Firefox (for visual engine)
- Linux or Windows

### 📦 Dependencies

Install the required modules:

```bash
git clone https://github.com/Venomous123321/web_vuln_scanner.git
```
🔘 Create  environment for requirements
```bash
sudo apt update
```
```bash
sudo apt install python3 python3-venv python3-pip -y
```
```bash
python3 -m venv venv
```
```bash
source venv/bin/activate
```
⏩ Then
```bash
cd web_vuln_scan
```
```bash
pip install -r requirements.txt
```
```bash
python web_vuln_scan.py
```



🔘 Quick CLI Scan
```bash
python web_vuln_scan.py -u https://target.com -m quick --save --html
```
🧠 Deep AI Scan
```bash
python web_vuln_scan.py -u https://target.com -m deep --save --html
```
🎯 Custom Scan (Levels)
```bash
python web_vuln_scan.py -u https://target.com -m custom
```
🏁 CTF Flag Mode
```bash
python web_vuln_scan.py -u https://target.com -m ctf
```
