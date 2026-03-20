# V-XENT: Intelligence Advanced Reconnaissance Framework

![Version](https://img.shields.io/badge/version-1.0.0-purple.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)

**V-XENT** (Virtual-X Intelligence Intelligence Intelligence-Enterprise-Network-Threat-Scanner) is a high-performance OSINT reconnaissance engine designed for red teams and security researchers. It automates the target discovery and profiling phase by correlating intelligence from multiple elite sources.

---

## 🚀 Key Features

*   **Shodan Intelligence**: Automated infrastructure discovery, port mapping, and service profiling.
*   **VirusTotal Integration**: Real-time domain and IP reputation analysis using VT API v3.
*   **Advanced Correlation Engine**: Intelligent matching across sources to identify high-risk assets and critical threats.
*   **Professional Reporting**: Generates high-impact, "cyberpunk-styled" HTML reports and structured JSON for automated workflows.
*   **Rate-Limit Management**: Built-in delays to respect API quotas (Shodan 1.1s, VT 15s).

---

## 🛠️ Installation

### 1. Prerequisites
- Python 3.10 or higher.
- API keys for Shodan and VirusTotal.

### 2. Setup
Clone the repository and enter the project directory:

```bash
git clone https://github.com/your-username/V-XENT-Intelligence-Advanced-Reconnaissance-.git
cd V-XENT-Intelligence-Advanced-Reconnaissance-/v-xent
```

Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

Install dependencies:
```bash
pip install -r requirements.txt
```

---

## 🔐 Configuration

Copy the example environment file and add your API keys:

```bash
cp .env.example .env
```

Edit the `.env` file:
```env
SHODAN_API_KEY=your_shodan_key_here
VT_API_KEY=your_virustotal_key_here
DEBUG=True
```

---

## 🖥️ Usage

Run the framework using the `main.py` entry point.

### Scan a Domain
```bash
python3 main.py --target google.com --shodan --virustotal
```

### Scan a Specific IP
```bash
python3 main.py --target 8.8.8.8 --shodan --virustotal
```

### Full Options
```bash
python3 main.py --help
```

---

## 📂 Project Structure

```text
v-xent/
├── config/             # Framework configuration logic
├── scanners/           # Scanner modules (Shodan, VirusTotal)
├── intel_gathering/    # Intelligence correlation engine
├── utils/              # Logging and reporting utilities
├── output/             # Generated reports (JSON, HTML)
├── main.py             # Main entry point
└── requirements.txt    # Project dependencies
```

---

## 🧪 Technologies Used

- **Python 3.10+**: Core logic.
- **Shodan Library**: Infrastructure search.
- **Requests**: VT API v3 interaction.
- **Colorama**: Stylized terminal output.
- **Custom HTML/CSS**: Professional reporting system.

---

## ⚖️ Ethics & Disclaimer

V-XENT is intended for ethical security research and authorized penetration testing only. The developers are not responsible for misuse or any damage caused by this tool. Use responsibly.

---

*"Intelligence is the first line of defense."* - **K-VØID Labs**
