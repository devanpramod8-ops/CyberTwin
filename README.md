# 🛡️ CyberTwin v1.6
### Cybersecurity Analysis & Threat Detection Toolkit

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-black?logo=flask)
![HTML5](https://img.shields.io/badge/HTML5-Frontend-orange?logo=html5)
![CSS3](https://img.shields.io/badge/CSS3-Styling-blue?logo=css)
![JavaScript](https://img.shields.io/badge/JavaScript-Interactive-yellow?logo=javascript)
![Version](https://img.shields.io/badge/Version-1.6-green)
![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen)

---

## 📌 About CyberTwin

**CyberTwin** is a Python-based cybersecurity analysis toolkit designed to help users identify potentially suspicious files, URLs, and messages.

Built using **Python, Flask, HTML, CSS, and JavaScript**, CyberTwin provides an interactive security dashboard with rule-based threat analysis and easy-to-understand security reports.

The project focuses on making basic cybersecurity analysis accessible to students, beginners, and security enthusiasts.

> **Mission:** Simplifying cybersecurity analysis through an accessible and user-friendly security platform.

---

## 🚀 Key Features

### 📁 1. File Security Analyzer

Analyze uploaded files for potential security concerns.

**Capabilities:**
- SHA-256 file hash generation
- File extension analysis
- File signature (magic-byte) inspection
- File type mismatch detection
- Suspicious extension warnings
- Security findings and analysis reports

### 🌐 2. URL Security Analyzer

Inspect website links for suspicious characteristics.

**Capabilities:**
- URL structure analysis
- HTTP and HTTPS identification
- IP-based URL detection
- Suspicious keyword detection
- Potential phishing indicators
- Security warnings and reports

### 💬 3. Message Security Analyzer

Identify potentially suspicious content in text messages.

**Capabilities:**
- Phishing-related keyword detection
- Urgency and threatening language analysis
- OTP and sensitive information request detection
- Suspicious link identification
- Rule-based social engineering indicators
- Security analysis reports

---

## 🖥️ Security Dashboard

CyberTwin features a modern, dark-themed cybersecurity dashboard designed for a simple and interactive user experience.

**Dashboard highlights:**
- Clean sidebar navigation
- Dedicated security analysis modules
- Interactive scan interface
- Scan statistics
- Dynamic security reports
- Responsive visual design

### 📸 Dashboard Preview

*Dashboard screenshots will be added in a future update.*

---

## 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| Python | Backend development |
| Flask | Web application framework |
| HTML5 | User interface structure |
| CSS3 | Dashboard styling |
| JavaScript | Frontend interactions |
| hashlib | SHA-256 hash generation |
| Git | Version control |
| GitHub | Source code hosting |

---

## 📂 Project Structure

```text
CyberTwin/
│
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── templates/
│   └── index.html
│
├── static/
│   ├── css/
│   │   └── style.css
│   │
│   └── images/
│       └── logo.png
│
└── venv/                # Local virtual environment (not tracked)
```

---

## ⚙️ Installation and Setup

### Prerequisites

Before running CyberTwin, make sure you have:

- Python 3 installed
- pip package manager
- Git
- A modern web browser

### Step 1: Clone the Repository

```bash
git clone https://github.com/devanpramod8-ops/CyberTwin.git
```

### Step 2: Navigate to the Project

```bash
cd CyberTwin
```

### Step 3: Create a Virtual Environment

```bash
python -m venv venv
```

### Step 4: Activate the Virtual Environment

**Windows PowerShell:**

```powershell
.\venv\Scripts\Activate.ps1
```

**Linux/macOS:**

```bash
source venv/bin/activate
```

### Step 5: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 6: Run CyberTwin

```bash
python app.py
```

### Step 7: Open the Dashboard

Visit:

**http://127.0.0.1:5000**

CyberTwin should now be running locally.

---

## 🔍 How CyberTwin Works

CyberTwin uses a rule-based analysis approach to inspect user-submitted inputs.

**File Analysis**

1. User uploads a file.
2. CyberTwin inspects its extension and file signature.
3. A SHA-256 hash is generated.
4. Potential security warnings are identified.
5. Results are displayed in the dashboard.

**URL Analysis**

1. User submits a URL.
2. CyberTwin examines its structure.
3. Suspicious indicators are checked.
4. Findings are displayed in a security report.

**Message Analysis**

1. User submits message text.
2. CyberTwin checks for suspicious language and keywords.
3. Potential phishing and social engineering indicators are identified.
4. Results are displayed in the dashboard.

---

## 🔐 Security and Privacy

CyberTwin is designed primarily for educational cybersecurity analysis.

- Uses rule-based security checks.
- Generates SHA-256 hashes for file identification.
- Provides security findings without requiring external AI services.
- Supports local execution using Flask.

**Important:** CyberTwin does not provide comprehensive malware detection, sandbox execution, antivirus protection, or guaranteed phishing identification. A clean result does not mean a file, URL, or message is safe.

---

## 🗺️ Future Roadmap

Potential improvements for future versions include:

- [ ] Advanced phishing detection
- [ ] Improved file analysis techniques
- [ ] VirusTotal API integration
- [ ] Threat intelligence integration
- [ ] Downloadable PDF security reports
- [ ] Improved dashboard analytics
- [ ] Scan history management
- [ ] Advanced URL reputation analysis
- [ ] Additional security modules

---

## 🎯 Project Objectives

CyberTwin was developed to:

- Improve practical cybersecurity development skills.
- Explore common phishing and suspicious content indicators.
- Build experience with Python and Flask.
- Understand file inspection and hashing techniques.
- Create an accessible security analysis dashboard.
- Develop a foundation for more advanced security tools.

---

## 👨‍💻 Developer

**Devan Pramod**

Cybersecurity Enthusiast | Ethical Hacking | Python Developer

Interested in cybersecurity research, penetration testing, vulnerability assessment, and security tool development.

**GitHub:** [@devanpramod8-ops](https://github.com/devanpramod8-ops)

**Project Repository:** [CyberTwin](https://github.com/devanpramod8-ops/CyberTwin)

---

## ⚠️ Disclaimer

CyberTwin is developed for **educational, research, and defensive cybersecurity purposes**.

Its findings are based on basic static and rule-based analysis. They should not be treated as definitive proof that content is malicious or safe.

Always use appropriate professional security tools and procedures when investigating real-world threats.

---

## ⭐ Support the Project

If you find CyberTwin interesting or useful, consider giving the repository a **star ⭐** on GitHub.

Your support encourages continued learning and development.

---

**CyberTwin v1.6 — Analyze. Detect. Stay Aware.**

*Developed by Devan Pramod*
