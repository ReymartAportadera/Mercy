# TrustFile - File Security Platform

## Project Overview

**TrustFile** is a file security platform that scans and protects files before access. The system analyzes uploaded files for malicious content using heuristic analysis, VirusTotal API integration, and AI-powered threat classification before allowing users to access or download them.

## Project Purpose

The goal of TrustFile is to detect, analyze, and remove malicious software before files are accessed. TrustFile protects users by scanning potentially harmful files, assessing their threat level, and providing one-click deletion or quarantine options before any damage can occur.

## Key Features

| Feature | Description |
|---------|-------------|
| **Pre-Access Scanning** | Files are scanned and analyzed before user access |
| **Heuristic Analysis** | Detects suspicious patterns, code execution, and malware behaviors |
| **VirusTotal Integration** | Uses 70+ antivirus engines for accurate known malware detection |
| **AI-Powered Analysis** | NVIDIA NIM (Llama 3.1) provides intelligent threat explanations |
| **Malware Classification** | Identifies ransomware, trojans, keyloggers, worms, and spyware |
| **Risk Scoring** | 0-100% threat level |
| **One-Click Removal** | Delete or quarantine infected files immediately |
| **Interactive Dashboard** | File upload and scan management interface |
| **Exportable Reports** | PDF, HTML, JSON formats for documentation |

## Technology Stack

| Layer | Technology |
|-------|------------|
| **Backend** | Python 3.8+, Flask, SQLAlchemy |
| **Database** | MySQL |
| **Security APIs** | VirusTotal API, NVIDIA NIM AI |
| **Frontend** | HTML5, CSS3, JavaScript, Chart.js |

## Project Structure



##  Project Structure

trustfile/
├── app.py                 # Main Flask application
├── file_monitor.py        # Real-time file system monitor
├── requirements.txt       # Python dependencies
├── api/
│   ├── malware_api.py     # VirusTotal integration
│   └── ai_analysis.py     # NVIDIA NIM AI integration
├── static/
│   ├── dashboard.css      # Stylesheets
│   ├── theme.css          
│   ├── theme.js           # Theme manager
│   ├── home.css
│   ├── login.css
│   ├── report.css
│   ├── scan.css
│   ├── setting.css
│   ├── upload.css
    ├──history.css 
    └── uploads/           # User uploaded files
├── templates/
│   ├── dashboard.html     # Main dashboard
│   ├── scan.html          # Scan interface
│   ├── reports.html       # Reports page
│   ├── settings.html      # User settings
│   ├── history.html       # Scan history
│   ├── home.html          # Landing page
│   ├── login.html         # Login page
│   ├── signup.html        # Registration page
│   └── uploadfiles.html   # File upload page
└── models/                # Database models



## Dependencies

### Core Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| Flask | 2.0+ | Web framework for building the application |
| Flask-SQLAlchemy | 2.5+ | ORM for database operations |
| Flask-Login | 0.5+ | User session management and authentication |
| Flask-WTF | 1.0+ | Form handling and CSRF protection |
| WTForms | 3.0+ | Form validation and rendering |
| mysql-connector-python | 8.0+ | MySQL database connector |
| Werkzeug | 2.0+ | WSGI utilities and password hashing |

### Security & Analysis Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| requests | 2.25+ | HTTP requests for VirusTotal API |
| openai | 1.0+ | NVIDIA NIM AI integration |
| watchdog | 2.1+ | Real-time file system monitoring |

### Frontend Dependencies (CDN)

| Library | Version | Purpose |
|---------|---------|---------|
| Font Awesome | 6.5.0 | Icons and visual elements |
| Chart.js | 4.4.0 | Data visualization for reports |

### requirements.txt

Create a `requirements.txt` file with the following content:

```txt
Flask>=2.0.0
Flask-SQLAlchemy>=2.5.0
Flask-Login>=0.5.0
Flask-WTF>=1.0.0
WTForms>=3.0.0
mysql-connector-python>=8.0.0
Werkzeug>=2.0.0
requests>=2.25.0
openai>=1.0.0
watchdog>=2.1.0


