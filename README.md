# V-XENT: Intelligence Advanced Reconnaissance Framework [SECURE ED.]

![Version](https://img.shields.io/badge/version-1.1.0--secure-purple.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)

**V-XENT** is a professional-grade OSINT reconnaissance engine designed for red teams and security researchers. This secure edition has been hardened for production use in enterprise environments and client audits.

---

## 🚀 Key Features

*   **Multi-Source Intelligence**: Automated infrastructure discovery via Shodan and reputation analysis via VirusTotal API v3.
*   **Advanced Correlation Engine**: Intelligent cross-matching to identify high-risk assets and critical threats.
*   **Production Hardened Reporting**: Secure HTML reports (Jinja2 + Bleach) and JSON outputs with **HMAC-SHA256 integrity signatures**.
*   **Strict Input Validation**: Protects against injection attacks via deep target sanitization (IP, Domain, CIDR).
*   **Enterprise Docker Stack**: Multi-stage build, non-root users, and read-only filesystem for maximum security.
*   **Batch Scanning**: Support for processing multiple targets from file lists.

---

## ⚠️ SECURITY & BEST PRACTICES

**This framework follows an "Impenetrable by Design" philosophy. To maintain maximum security:**

1.  **API Key Management**: 
    - **NEVER** commit your `.env` file. It is ignored by default in `.gitignore`.
    - In production, use **Environment Variables** (e.g., `SHODAN_API_KEY`) or **Docker Secrets**.
2.  **Report Integrity**: 
    - Every JSON report includes an `integrity_hash`. You can verify this using the `IntegrityManager.verify_report()` utility to ensure data hasn't been tampered with.
3.  **Deployment**: 
    - Run V-XENT within its **Hardened Docker Container**. It runs as a non-privileged user and has a read-only root filesystem.
4.  **Audit Logs**: 
    - Use the `--json-log` flag to export structured data directly to your SIEM/SOAR platforms.

---

## 🛠️ Installation

### 1. Prerequisites
- Docker & Docker Compose **(Recommended)**
- OR Python 3.10+ and system dependencies (libpangocairo, libharfbuzz).

### 2. Setup (Docker)
```bash
cp .env.example .env
# Edit .env with your keys
docker compose build
```

### 3. Setup (Native)
```bash
pip install -r requirements.txt
cp .env.example .env
```

---

## 🖥️ Usage

### Scan a Single Target
```bash
# Docker
docker compose run v-xent --target 8.8.8.8 --shodan --virustotal

# Native
python3 main.py --target google.com --shodan --virustotal
```

### Batch Scanning (Multiple Targets)
Create a file `targets.txt` with one target per line:
```bash
python3 main.py --file targets.txt --shodan --virustotal
```

### SIEM Integration (JSON Logs)
```bash
python3 main.py --target 8.8.8.8 --shodan --virustotal --json-log
```

---

## 📂 Project Structure

```text
v-xent/
├── config/             # Hardened config management
├── scanners/           # Shodan & VT modules
├── intel_gathering/    # Advanced Correlator
├── utils/              # Validator, Crypto (HMAC), Reporter (Jinja2), Logger
├── templates/          # Secure HTML report templates
├── output/             # Persistent signed reports
└── main.py             # Secure Entry Point
```

---

## ⚖️ Ethics & Disclaimer

V-XENT is intended for ethical security research and authorized penetration testing only. K-VØID Labs is not responsible for misuse. Use responsibly.

---

*"Intelligence is the first line of defense."* - **V-XENT Framework [SECURE]**
