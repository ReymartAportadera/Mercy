# TrustFile - File Security Platform

## Project Overview

**TrustFile** is a file security platform that scans and protects files before access. The system analyzes uploaded files for malicious content using heuristic analysis, VirusTotal API integration, and AI-powered threat classification before allowing users to access or download them.

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Pre-Access Scanning** | Files are scanned and analyzed before user access |
| **Heuristic Analysis** | Detects suspicious patterns, code execution, and malware behaviors |
| **VirusTotal Integration** | Uses 70+ antivirus engines for accurate known malware detection |
| **AI-Powered Analysis** | NVIDIA NIM (Llama 3.1) provides intelligent threat explanations |
| **Malware Classification** | Identifies ransomware, trojans, keyloggers, worms, and spyware |
| **Risk Scoring** | 0-100% threat level assessment |
| **Auto-Quarantine & Recycle Bin** | Automatically moves malicious files to the Recycle Bin |
| **Interactive Dashboard** | File upload and scan management interface |
| **Real-time Threat Monitoring** | Watches designated folders for immediate threat detection |

---

## Technology Stack

| Layer | Technology |
|-------|------------|
| **Backend** | Python 3.8+, Flask |
| **Database** | Firebase Realtime Database (Google Cloud) |
| **Security APIs** | VirusTotal API, NVIDIA NIM AI |
| **Frontend** | HTML5, CSS3, JavaScript, Chart.js |

---

## Installation & Setup

To run this project on a new device, follow these steps:

### 1. Set Up the Environment File
Create a `.env` file in the root of the project. You can copy the template from `.env.example`:

```bash
cp .env.example .env
```

Open the `.env` file and configure the variables:

*   `FIREBASE_DB_URL`: The URL to your Firebase Realtime Database.
*   `FIREBASE_SERVICE_ACCOUNT`: The absolute path to your downloaded Firebase private key JSON file (e.g., `D:/Flask website/serviceAccountKey.json`).
*   `VIRUSTOTAL_API_KEY`: Your VirusTotal API Key for scanning files.
*   `UPLOAD_FOLDER`: Absolute path to the folder where scanned uploads are stored.

### 2. Get Firebase Private Credentials
1. Go to the [Firebase Console](https://console.firebase.google.com/).
2. Open your project.
3. Click the Gear Icon ⚙️ (**Project Settings**) -> **Service accounts**.
4. Click **Generate new private key** and download the `.json` file.
5. Place the downloaded `.json` file inside your project directory and set its path in the `.env` file under `FIREBASE_SERVICE_ACCOUNT`.

### 3. Install Python Dependencies
Activate your virtual environment and install the required modules:

```bash
pip install -r requirements.txt
```

### 4. Run the Application
Start the Flask application:

```bash
python app_firebase.py
```


