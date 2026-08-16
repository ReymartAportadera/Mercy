# TrustFile — Architecture, Workflow & Agile SDLC Diagrams

Comprehensive technical specification for the **TrustFile Malware Analysis & Security Monitoring System**.

---

## 1. System Architecture Diagram

```mermaid
graph TB
    subgraph Presentation_Layer["1. Presentation Layer (Client Tier)"]
        UI_Home["Home Landing & Auth Views (home.html, login.html, signup.html)"]
        UI_Dash["Interactive Dashboard (dashboard.html — Folder Groups, Threat Meters)"]
        UI_Upload["Upload & Batch Queue Engine (uploadfiles.html — Folder Mode, Drag & Drop)"]
        UI_Scan["Scan Result Inspection View (scan.html — Spectrum Meter, IOCs, AI Card)"]
        UI_Guest["Guest Quick Scanner (guest_scan.html — Zero Auth Required)"]
        UI_Crypto["Web Crypto API Client-Side SHA-256 (Instant Pre-Hashing for >4.5MB Files)"]
    end

    subgraph Application_Layer["2. Application & API Routing Layer (WSGI / Serverless)"]
        Flask_Core["Flask Core Web Application (app_firebase.py / api/index.py)"]
        CSRF_Limiter["Security Middleware (Flask-WTF CSRF & Rate Limiting)"]
        Auth_Mgr["Session & User Manager (Flask-Login & PBKDF2 Password Hasher)"]
        Monitor_Svc["Real-Time Directory Watcher (file_monitor.py — Watchdog Observer)"]
        API_Endpoints["RESTful API Gateway (/api/upload_single_file, /api/scan_hash, /api/guest_upload, /api/auto_scan)"]
    end

    subgraph Scanning_Core["3. Multi-Engine Threat Detection Core"]
        subgraph Engine_1["Engine 1: Local Static Heuristics"]
            H_Clean["Preprocessor & Sanitizer (strip_comments_and_docstrings)"]
            H_B64["Payload Inspector (is_executable_or_malicious_payload)"]
            H_Entropy["Shannon Entropy Calculator (0.0–8.0 Byte Distribution)"]
            H_AST["Pattern & AST Analyzer (Obfuscated Loaders, Persistence, PE Magic)"]
        end

        subgraph Engine_2["Engine 2: VirusTotal Global Consensus"]
            VT_Cache["Firebase VT Cache Layer (Instant <100ms Cache Hits)"]
            VT_Hash["VirusTotal v3 REST API (70+ Global AV Engines)"]
            VT_Override["Global Consensus Rule (0/20+ Clean -> Cap at 40% Medium)"]
        end

        subgraph Engine_3["Engine 3: Contextual AI Intelligence"]
            Gemini_AI["Google Gemini 2.0 Flash API (Contextual Threat Synthesis)"]
            AI_Local["Rule-Based Fallback Engine (analyze_file_ai_local)"]
        end
    end

    subgraph Data_Layer["4. Data & Persistence Layer"]
        Firebase_RTDB[("Firebase Realtime Database (Users, File Records, vt_cache, Settings)")]
        Local_FS[("File Storage Subsystem (uploads/<uid>/ & /tmp/uploads/)")]
        SMTP_Relay["Gmail SMTP Notification Relay (Password Reset OTPs & Threat Alerts)"]
    end

    UI_Upload --> UI_Crypto
    UI_Crypto --> API_Endpoints
    UI_Guest --> API_Endpoints
    UI_Dash --> Flask_Core
    UI_Home --> Auth_Mgr
    Flask_Core --> CSRF_Limiter
    CSRF_Limiter --> API_Endpoints
    API_Endpoints --> H_Clean
    H_Clean --> H_B64 --> H_Entropy --> H_AST
    H_AST --> VT_Cache
    VT_Cache -.->|Cache Miss| VT_Hash
    VT_Hash --> VT_Override
    VT_Override --> Gemini_AI
    Gemini_AI -.->|Fallback| AI_Local
    API_Endpoints --> Firebase_RTDB
    API_Endpoints --> Local_FS
    Auth_Mgr --> SMTP_Relay
    Monitor_Svc --> API_Endpoints
```

---

## 2. System Workflow Diagram

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Guest
    participant UI as Frontend (uploadfiles.html / guest_scan.html)
    participant API as Flask API Gateway (app_firebase.py)
    participant E1 as Engine 1: Static Heuristics
    participant E2 as Engine 2: VirusTotal Engine
    participant E3 as Engine 3: Gemini AI Engine
    participant DB as Firebase Realtime Database

    User->>UI: Select File(s) / Folder (or Drag & Drop)
    alt File Size > 4.5 MB on Cloud (Vercel)
        UI->>UI: Compute SHA-256 via Web Crypto API (Client-Side)
        UI->>API: POST /api/scan_hash {hash, filename, size}
    else Standard File Upload (<= 4.5 MB or Local)
        UI->>API: POST /api/upload_single_file (FormData: bytes, folder)
    end

    API->>E1: Execute _run_full_heuristic_scan(filename, bytes, hash)
    activate E1
    E1->>E1: Strip Comments & Docstrings (#, /* */, """)
    E1->>E1: Inspect Base64 Payloads (Suppress harmless text)
    E1->>E1: Calculate Shannon Entropy & AST Patterns
    E1-->>API: Return scan_res (Heuristic Score: 0–100)
    deactivate E1

    API->>E2: Execute smart_virustotal_scan(path, file_hash)
    activate E2
    E2->>DB: Check vt_cache/{file_hash}
    alt Cache Hit (<100ms)
        DB-->>E2: Return Cached VT Results (0/76 clean)
    else Cache Miss
        E2->>E2: Query VirusTotal v3 REST API (Hash Lookup / Upload)
        E2->>DB: Save result to vt_cache/{file_hash}
    end
    E2-->>API: Return vt_result (Positives, Engine Count)
    deactivate E2

    alt VirusTotal 0 Detections & Engine Count >= 20
        API->>API: Apply Global Consensus Hard Override Rule (Cap at <= 40% Medium)
    end

    API->>E3: Execute analyze_file_ai(entropy, patterns, imports, risk_score)
    activate E3
    E3->>E3: Contextual synthesis via Gemini 2.0 Flash (or Local Rule Fallback)
    E3-->>API: Return ai_analysis (Verdict, Summary Text, Recommendation)
    deactivate E3

    API->>API: Determine Threat Level (Benign, Low, Medium, High, Critical)
    API->>API: Generate Plain-English Explanation
    API->>DB: Save File Record (fb.save_uploaded_file)
    API-->>UI: Return JSON {success: true, file_id, risk_score, threat_level}
    UI->>UI: Render /scan/<file_id> (Spectrum Gauge, IOCs, AI Card)
    UI-->>User: Display Final Threat Report
```

---

## 3. Agile Methodology & SDLC Model Diagram

```mermaid
graph LR
    subgraph Backlog_Phase["1. Backlog & Requirements"]
        PB["Product Backlog<br/>(Security Features, False-Positive Rules)"]
        SP["Sprint Planning<br/>(Task Prioritization, Risk Assessment)"]
    end

    subgraph Sprint_Execution["2. Sprint Execution (1–2 Weeks)"]
        Code["Feature Development<br/>(Static AST Engine, VT Logic, Flask APIs)"]
        Pair["Pair Programming & AI Assistance<br/>(Antigravity Agentic Pair Coding)"]
        UnitTest["Local Unit & Parity Testing<br/>(test_enhancements.py, test_guest_parity.py)"]
    end

    subgraph CI_CD["3. Continuous Integration & Deployment"]
        GitPush["Git Commit & Branch Sync<br/>(origin/main)"]
        VercelBuild["Vercel Cloud Build<br/>(Python 3.12, uv, Serverless Bundling)"]
        ProdDeploy["Production Staging & Release<br/>(trustfile-tau-alpha.vercel.app)"]
    end

    subgraph Review_Feedback["4. Review & Retrospective"]
        SecAudit["Security & Accuracy Audit<br/>(False Positive Verification, Parity Check)"]
        SprintReview["Sprint Review & Demo<br/>(User Acceptance & Dashboard Validation)"]
        Retro["Sprint Retrospective<br/>(Engine Rule Refinement & Continuous Learning)"]
    end

    PB --> SP
    SP --> Code
    Code --> Pair
    Pair --> UnitTest
    UnitTest --> GitPush
    GitPush --> VercelBuild
    VercelBuild --> ProdDeploy
    ProdDeploy --> SecAudit
    SecAudit --> SprintReview
    SprintReview --> Retro
    Retro -->|Continuous Feedback Loop| PB
```
