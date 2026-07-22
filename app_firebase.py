import os
try:
    from send2trash import send2trash as _send_to_trash
except ImportError:
    _send_to_trash = None  # fallback to permanent delete if not available
import sys
import types
import hashlib
import json
import logging
import math
import re
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from threading import Semaphore

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import firebase_utils as fb

from flask_wtf.csrf import CSRFProtect

# ── Scan Dependencies ────────────────────────────────────────────────────────
from api.malware_api import check_hash_api, smart_virustotal_scan
from api.ai_analysis import analyze_file_ai
from api.advanced_heuristics import run_advanced_heuristics

MEDIA_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".tiff", ".ico",
    ".mp4", ".avi", ".mov", ".mkv", ".flv", ".wmv", ".webm", ".3gp", ".m4v",
    ".mp3", ".wav", ".ogg", ".flac", ".aac", ".m4a"
}
BINARY_EXTENSIONS = {
    ".zip", ".tar", ".gz", ".exe", ".dll", ".bin", ".dat", ".pdf", ".doc",
    ".docx", ".xls", ".xlsx"
} | MEDIA_EXTENSIONS
ALL_SCAN_TYPES = ["heuristic", "virustotal", "ai_analysis"]

# ── In-memory byte cache (LRU, max 50 entries to prevent memory bloat) ───────
_BYTE_CACHE_MAX = 50
_BYTE_CACHE: OrderedDict = OrderedDict()

def _cache_bytes(file_id, data):
    if file_id in _BYTE_CACHE:
        _BYTE_CACHE.move_to_end(file_id)
    _BYTE_CACHE[file_id] = data
    while len(_BYTE_CACHE) > _BYTE_CACHE_MAX:
        _BYTE_CACHE.popitem(last=False)  # evict oldest

def _pop_bytes(file_id):
    return _BYTE_CACHE.pop(file_id, None)

def is_binary_file(file_path):
    return os.path.splitext(file_path)[1].lower() in BINARY_EXTENSIONS

scan_semaphore = Semaphore(10)  # max 10 concurrent scans

def safe_file_path(p: str) -> str:
    return os.path.normpath(os.path.abspath(p))

def safe_open(file_path: str, mode: str = "rb", **kw):
    p = safe_file_path(file_path)
    if not os.path.exists(p):
        raise FileNotFoundError(f"File not found: {p!r}")
    if not os.path.isfile(p):
        raise ValueError(f"Not a file: {p!r}")
    return open(p, mode, **kw)

def _compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in counts if c), 2)

def calculate_entropy(file_path: str) -> float:
    CHUNK = 65536
    counts = [0] * 256
    total  = 0
    try:
        with safe_open(file_path, "rb") as f:
            while True:
                chunk = f.read(CHUNK)
                if not chunk:
                    break
                for b in chunk:
                    counts[b] += 1
                total += len(chunk)
        if total == 0:
            return 0.0
        return round(
            -sum((c / total) * math.log2(c / total) for c in counts if c > 0), 2
        )
    except OSError as exc:
        logger.warning("entropy calc failed for %s: %s", file_path, exc)
        return 0.0

def get_file_type_entropy_threshold(file_path: str) -> float:
    ext = os.path.splitext(file_path)[1].lower()
    if ext in {".py", ".js", ".vbs", ".ps1", ".bat", ".txt", ".html", ".css"}:
        return 5.8
    if ext in {".exe", ".dll", ".bin", ".dat"}:
        return 7.0
    if ext in MEDIA_EXTENSIONS or ext in {".zip", ".tar", ".gz", ".7z", ".rar", ".docx", ".xlsx", ".pptx"}:
        return 7.95
    return 6.5

def _in_memory_heuristics(text: str) -> list:
    findings = []
    if re.search(r"requests\.(post|get).*?(webhook|pastebin|ngrok|token|password|cookie)", text, re.I):
        findings.append("Data Exfiltration")
    if re.search(r"base64.*(decode|b64decode).*eval\s*\(", text, re.I):
        findings.append("Obfuscated Execution")
    if re.search(r"socket\.socket.*connect.*subprocess", text, re.I):
        findings.append("Reverse Shell")
    if re.search(r"(winreg|HKEY_|schtasks|Startup)", text, re.I):
        findings.append("Persistence Mechanism")
    return findings

def determine_threat_level(risk_score: int, detection_details: list) -> tuple[str, str]:
    joined = " ".join(detection_details).lower()
    if "reverse shell" in joined:
        level = "Critical"
    elif "data exfiltration" in joined:
        level = "High"
    elif risk_score >= 70:
        level = "Critical"
    elif risk_score >= 50:
        level = "High"
    elif risk_score >= 30:
        level = "Medium"
    elif risk_score > 0:
        level = "Low"
    else:
        level = "Safe"
    status = "Threat" if level in {"Critical", "High", "Medium"} else "Safe"
    return level, status

def generate_explanation(file_dict: dict) -> str:
    reasons = []
    if file_dict.get("pattern_result") and file_dict.get("pattern_result") != "Clean":
        reasons.append(f"it exhibits {file_dict.get('pattern_result').lower()} behavior")
    if file_dict.get("signature_status") and file_dict.get("signature_status") != "None":
        reasons.append(f"it performs suspicious actions such as {file_dict.get('signature_status').lower()}")
    if file_dict.get("risky_imports") and file_dict.get("risky_imports") != "None":
        reasons.append(f"it uses risky modules like {file_dict.get('risky_imports')}")
    if file_dict.get("entropy") and file_dict.get("entropy") > 7.5:
        reasons.append("it has high entropy, which may indicate obfuscation")

    risk = file_dict.get("risk_score", 0) or 0
    if risk >= 70:
        intro, level = "This file is very dangerous", "a critical threat"
    elif risk >= 50:
        intro, level = "This file is potentially harmful", "a high-risk threat"
    elif risk >= 30:
        intro, level = "This file shows suspicious behavior", "moderately suspicious"
    else:
        intro, level = "This file appears mostly safe", "low-risk"

    if reasons:
        return f"{intro} ({level}) because " + ", ".join(reasons) + "."
    if risk < 30:
        return f"{intro}. No significant suspicious behavior detected."
    return f"This file is classified as {level} but no specific suspicious behavior was detected."

def _persist_advanced_to_file(file_dict: dict, adv: dict) -> None:
    if not adv:
        return
    file_dict["advanced_heuristics"] = adv
    file_dict["detected_type"] = adv.get("detected_type", "")
    file_dict["confidence"] = adv.get("confidence", 0)
    file_dict["iocs"] = adv.get("iocs", [])

def _apply_scan_result_to_file(file_dict: dict, result: dict) -> None:
    file_dict["hash"] = result.get("hash", "")
    file_dict["entropy"] = result.get("entropy", 0)
    file_dict["pattern_result"] = (
        result.get("pattern_result")
        or ", ".join(result.get("suspicious_functions", [])[:3])
        or "No suspicious patterns"
    )
    file_dict["signature_status"] = (
        result.get("signature_status")
        or ", ".join(result.get("heuristics", [])[:3])
        or "No signatures detected"
    )
    file_dict["risky_imports"] = (
        result.get("risky_imports_str")
        or ", ".join(result.get("risky_imports", []))
        or "None"
    )
    _persist_advanced_to_file(file_dict, result.get("advanced", {}))

def _run_full_heuristic_scan(
    filename: str,
    file_bytes: bytes,
    file_hash: str,
) -> dict:
    ext        = os.path.splitext(filename)[1].lower()
    is_binary  = ext in BINARY_EXTENSIONS
    dangerous_exts = {".exe", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".py"}
    file_type_risk = ext in dangerous_exts

    entropy    = _compute_entropy(file_bytes)
    heuristics: list = []
    suspicious: list = []
    risky_imports: list = []

    if not is_binary:
        text = file_bytes.decode("utf-8", errors="ignore")
        heuristics = _in_memory_heuristics(text)
        text_lower = text.lower()

        string_patterns = {
            "Code Execution":  r"\b(eval|exec)\s*\(",
            "System Command":  r"\b(os\.system|cmd\.exe|powershell)\b",
            "Process Spawn":   r"\b(subprocess\.(Popen|call|run)|start)\b",
            "Infinite Loop":   r"(:\w+.*goto\s+\w+)|(while\s+true)",
            "Network":         r"\b(requests\.(get|post)|socket|http|ftp)\b",
            "Encoding":        r"\b(base64|b64decode|hex|encode|decode)\b",
            "Script Engine":   r"\b(wscript|cscript|powershell)\b",
            "File Access":     r"\b(open|write|delete|remove|mkdir)\b",
            "Batch Abuse":     r"\b(start|taskkill|shutdown|del)\b",
        }
        for label, pattern in string_patterns.items():
            if re.findall(pattern, text_lower):
                suspicious.append(f"{label} detected")

        dangerous_mods = {"os", "sys", "subprocess", "socket", "requests"}
        for imp in dangerous_mods:
            if re.search(rf"\bimport {imp}\b|\bfrom {imp} import", text):
                risky_imports.append(imp)

    threshold  = get_file_type_entropy_threshold("x" + ext)
    risk_score = 0

    if entropy > threshold + 1.5:
        risk_score += 30
        heuristics.append(f"Very high entropy ({entropy}) for this file type")
    elif entropy > threshold + 0.8:
        risk_score += 20
        heuristics.append(f"High entropy ({entropy}) — possible obfuscation")
    elif entropy > threshold:
        risk_score += 10

    HEURISTIC_SCORES = {"Exfiltration": 25, "Reverse Shell": 30,
                        "Persistence": 20,  "Obfuscated":    15}
    for h in heuristics:
        risk_score += next((v for k, v in HEURISTIC_SCORES.items() if k in h), 10)

    SIG_SCORES = {"Code Execution": 15, "Process Spawn": 15, "System Command": 12,
                  "Batch Abuse": 12,    "Network": 8,         "Encoding": 8,
                  "Script Engine": 10,  "File Access": 5}
    for sig in suspicious:
        risk_score += next((v for k, v in SIG_SCORES.items() if k in sig), 5)

    IMPORT_SCORES = {"subprocess": 15, "socket": 15, "os": 10, "sys": 10, "requests": 8}
    for imp in risky_imports:
        risk_score += IMPORT_SCORES.get(imp, 5)

    if file_type_risk:
        risk_score += 10

    total = len(heuristics) + len(suspicious) + len(risky_imports)
    risk_score += 15 if total >= 5 else (8 if total >= 3 else (3 if total >= 1 else 0))
    risk_score  = min(risk_score, 100)
    if suspicious and risk_score < 30:
        risk_score = 30
    if risky_imports and risk_score < 20:
        risk_score = 20

    # ── Advanced heuristics (always, on bytes) ────────────────────────────────
    adv: dict = {}
    try:
        adv = run_advanced_heuristics(filename, file_bytes)
        risk_score = max(risk_score, adv.get("score", 0))
        adv_detections = adv.get("detections", [])
        heuristics = list(dict.fromkeys(heuristics + adv_detections))
    except Exception as exc:
        logger.warning("Advanced heuristics failed in _run_full_heuristic_scan: %s", exc)

    pattern_str = ", ".join(suspicious[:3]) or "No suspicious patterns"
    imports_str = ", ".join(risky_imports)  or "None"
    sig_str     = ", ".join(heuristics[:3]) or "No signatures detected"

    return {
        "hash":                 file_hash,
        "entropy":              entropy,
        "heuristics":           heuristics,
        "suspicious_functions": suspicious,
        "risky_imports":        risky_imports,
        "risk_score":           min(risk_score, 100),
        "pattern_result":       pattern_str,
        "signature_status":     sig_str,
        "risky_imports_str":    imports_str,
        "all_detections":       heuristics + suspicious,
        "advanced":             adv,
    }


# ── Logging (single configuration — avoids duplicate handlers) ───────────────
logger = logging.getLogger(__name__)

# ── Logging setup (single basicConfig for the whole app) ─────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)

# ── App setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__)

# Initialize CSRF protection (adds csrf_token() globally)
csrf = CSRFProtect(app)

_secret = os.environ.get("TRUSTFILE_SECRET_KEY", "")
if not _secret:
    logger.critical(
        "TRUSTFILE_SECRET_KEY is not set in .env — "
        "sessions are INSECURE. Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )
    _secret = "insecure-default-replace-me"
app.config["SECRET_KEY"] = _secret

# Max upload size: 32 MB (protects against resource exhaustion)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024

_upload_base = os.environ.get("UPLOAD_FOLDER", os.path.join(os.path.dirname(__file__), "uploads"))
app.config["UPLOAD_FOLDER"] = _upload_base
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# ── Custom Jinja2 filters ─────────────────────────────────────────────────────
@app.template_filter("format_dt")
def format_dt(value, fmt="%Y-%m-%d %H:%M:%S"):
    """Format an ISO datetime string or datetime object for display."""
    if not value:
        return "—"
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    try:
        return value.strftime(fmt)
    except Exception:
        return str(value)

# Rate limiting (optional) ───────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=[], storage_uri="memory://")

# ── Login manager ───────────────────────────────────────────────────────────────
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ── In-memory byte cache (LRU) — defined at module top, re-referenced here ───

# ── User class (Firebase‑backed) ────────────────────────────────────────────────
class User(UserMixin):
    def __init__(self, uid: str, username: str, email: str, password_hash: str):
        self.uid = uid
        self.username = username
        self.email = email
        self.password_hash = password_hash

    def get_id(self):
        return self.uid

    @property
    def is_active(self):
        return True

# Load user callback
@login_manager.user_loader
def load_user(user_id):
    try:
        data = fb.get_user(user_id)
    except Exception as e:
        logger.warning("Failed to load user %s: %s", user_id, e)
        return None
    if data:
        return User(uid=data["uid"], username=data["username"], email=data["email"], password_hash=data["password"])
    return None

# ── Auth routes ────────────────────────────────────────────────────────────────
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        if not (username and email and password):
            flash("Please fill out all fields.")
            return redirect(url_for("signup"))
        if fb.get_user_by_email(email):
            flash("Email already in use.")
            return redirect(url_for("signup"))
        password_hash = generate_password_hash(password, method="pbkdf2:sha256")
        uid = fb.save_user({"username": username, "email": email, "password": password_hash})
        flash("Account created! Please log in.")
        return redirect(url_for("login"))
    return render_template("signup.html")
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        user_rec = fb.get_user_by_email(email)
        if user_rec and check_password_hash(user_rec["password"], password):
            user = User(uid=user_rec["uid"], username=user_rec["username"], email=user_rec["email"], password_hash=user_rec["password"])
            login_user(user)
            return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/forgot_password", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if not email or not new_password or not confirm_password:
            flash("Please fill in all required fields.")
            return redirect(url_for("forgot_password"))

        if new_password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for("forgot_password"))

        user_rec = fb.get_user_by_email(email)
        if not user_rec:
            flash("No account registered with that email address.")
            return redirect(url_for("forgot_password"))

        password_hash = generate_password_hash(new_password, method="pbkdf2:sha256")
        user_rec["password"] = password_hash
        fb.save_user(user_rec)

        flash("Your password has been successfully reset! Please log in.")
        return redirect(url_for("login"))

    return render_template("forgot_password.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

def get_or_create_user_settings(uid: str) -> dict:
    settings = fb.get_user_settings(uid) or {}
    dirty = False
    defaults = {
        "auto_scan_enabled": True,
        "auto_scan_mode": "single",
        "scan_types": ["heuristic"],
        "notify_on_threat": True,
        "theme": "dark",
        "auto_quarantine": True,
        "alert_sound": True,
        "notify_safe": False,
    }
    for k, v in defaults.items():
        if k not in settings:
            if k == "scan_types" and "default_scan_types" in settings:
                val = settings["default_scan_types"]
                settings["scan_types"] = [val] if isinstance(val, str) else val
            else:
                settings[k] = v
            dirty = True
    if dirty:
        fb.save_user_settings(uid, settings)
    return settings

# ── Dashboard ────────────────────────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    all_files = fb.list_user_files(current_user.uid)
    settings  = get_or_create_user_settings(current_user.uid)

    # Show all scanned files — only hide Pending (not yet scanned)
    files = [f for f in all_files if f.get("status") != "Pending"]

    counters = dict(total_scans=len(files), safe_files=0, low_threat=0,
                    medium_threat=0, high_threat=0, critical_threat=0)

    for f in files:
        risk = f.get("risk_score", 0) or 0
        if risk >= 70:
            f["threat_level"] = "Critical"
            counters["critical_threat"] += 1
        elif risk >= 50:
            f["threat_level"] = "High"
            counters["high_threat"] += 1
        elif risk >= 30:
            f["threat_level"] = "Medium"
            counters["medium_threat"] += 1
        elif risk > 0:
            f["threat_level"] = "Low"
            counters["low_threat"] += 1
        else:
            f["threat_level"] = "Safe"
            counters["safe_files"] += 1
        try:
            size = os.path.getsize(f["filepath"])
            f["size"] = f"{round(size / 1024, 2)} KB"
        except Exception:
            f["size"] = f.get("size", "N/A")
        f["explanation"] = f.get("explanation", "")
        f["threat_ratio"] = risk

    return render_template("dashboard.html", files=files, settings=settings, **counters)


# ── Upload ───────────────────────────────────────────────────────────────────
@app.route("/upload", methods=["GET", "POST"])
@login_required
def uploadfiles():
    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            flash("No file selected.")
            return redirect(request.url)
        filename = secure_filename(f.filename)
        if not filename:
            flash("Filename is invalid. Please rename the file and try again.")
            return redirect(request.url)
        # Extension check (reuse ALLOWED_EXTENSIONS from original if needed)
        ext = os.path.splitext(filename)[1].lower()
        allowed = {".txt", ".py", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".exe", ".dll", ".bin", ".dat", ".html", ".css", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".tar", ".gz", ".7z", ".rar"} | MEDIA_EXTENSIONS
        if ext not in allowed:
            flash(f"File type '{ext}' is not permitted.")
            return redirect(request.url)
        file_bytes = f.read()
        if not file_bytes:
            flash("The uploaded file is empty.")
            return redirect(request.url)
        file_hash = hashlib.sha256(file_bytes).hexdigest()

        # ── Duplicate detection: check if user already uploaded this exact file ──
        existing_files = fb.list_user_files(current_user.uid)
        for existing in existing_files:
            same_hash = (existing.get("hash") and existing.get("hash") == file_hash)
            same_name = (existing.get("filename") == filename)
            
            if same_hash or same_name:
                if existing.get("status") == "Pending":
                    flash(f"⚠️ '{filename}' has already been uploaded and is pending scan.", "warning")
                else:
                    flash(f"⚠️ '{filename}' has already been uploaded and scanned. Duplicate blocked.", "warning")
                return redirect(url_for("dashboard"))

        # Save file to disk
        user_folder = os.path.join(app.config["UPLOAD_FOLDER"], str(current_user.uid))
        os.makedirs(user_folder, exist_ok=True)
        path = os.path.abspath(os.path.join(user_folder, filename))
        if len(path) > 255:
            filename = uuid.uuid4().hex + ext
            path = os.path.abspath(os.path.join(user_folder, filename))
        with open(path, "wb") as out:
            out.write(file_bytes)
        # Store relative path so records are portable across machines
        relative_path = os.path.join(str(current_user.uid), filename)
        # Record metadata in Firebase
        file_record = {
            "id": str(uuid.uuid4()),
            "filename": filename,
            "filepath": path,
            "relative_path": relative_path,
            "upload_time": datetime.now(timezone.utc).isoformat(),
            "status": "Pending",
            "hash": file_hash,
            "user_id": current_user.uid,
            "user_email": getattr(current_user, "email", ""),
            "username": getattr(current_user, "username", getattr(current_user, "email", "").split("@")[0]),
            "size": f"{round(len(file_bytes) / 1024, 2)} KB",
        }
        fb.save_uploaded_file(file_record)
        _cache_bytes(file_record["id"], file_bytes)
        flash("File uploaded successfully.")

        # Check settings for auto scan preference
        settings = get_or_create_user_settings(current_user.uid)
        auto_scan_param = "true" if settings.get("auto_scan_enabled", True) else "false"
        return redirect(url_for("scan_page", file_id=file_record["id"], auto_scan=auto_scan_param))
    return render_template("uploadfiles.html")

# ── Delete single detection (X button) ───────────────────────────────────────
@app.route("/api/delete_detection_record", methods=["POST"])
@login_required
def delete_detection_record_api():
    detection_id = request.form.get("detection_id")
    if not detection_id:
        return jsonify({"error": "Missing detection_id"}), 400

    if detection_id.startswith("local_"):
        # This is a local system monitor detection stored in TrustFile_Detections.json
        detections_file = os.path.join(os.path.expanduser("~"), "Desktop", "TrustFile_Detections.json")
        if os.path.exists(detections_file):
            try:
                with open(detections_file, "r", encoding="utf-8") as f:
                    detections = json.load(f)

                # First find the target filepath
                target_filepath = None
                for entry in detections:
                    if isinstance(entry, dict):
                        path_str = entry.get("file_path", "") or entry.get("filepath", "") or ""
                        time_str = entry.get("timestamp", "") or ""
                        h = hashlib.sha256(f"{path_str}{time_str}".encode("utf-8")).hexdigest()
                        if f"local_{h}" == detection_id:
                            target_filepath = path_str
                            break

                if target_filepath:
                    _trash_file(target_filepath)
                    
                    # Remove all duplicate entries sharing the same filepath
                    updated_detections = []
                    for entry in detections:
                        if isinstance(entry, dict):
                            path_str = entry.get("file_path", "") or entry.get("filepath", "") or ""
                            if path_str != target_filepath:
                                updated_detections.append(entry)

                    with open(detections_file, "w", encoding="utf-8") as f:
                        json.dump(updated_detections, f, indent=2)
                    return jsonify({"status": "deleted", "message": "File moved to Recycle Bin"})
            except Exception as e:
                logger.error("Error deleting local detection: %s", e)
                return jsonify({"error": str(e)}), 500
        return jsonify({"error": "Local detection file not found"}), 404

    # Otherwise it's a standard Firebase record
    record = fb.get_uploaded_file(detection_id)
    if record and record.get("user_id") == current_user.uid:
        target_hash = record.get("hash")
        target_path = record.get("filepath")

        # Trash the physical file
        _trash_file(target_path)

        # Remove all duplicate database records matching hash or path
        user_files = fb.list_user_files(current_user.uid)
        for f in user_files:
            same_hash = (target_hash and f.get("hash") == target_hash)
            same_path = (target_path and f.get("filepath") == target_path)
            if same_hash or same_path or f.get("id") == detection_id:
                fb.delete_uploaded_file(f["id"])

    return jsonify({"status": "deleted", "message": "File moved to Recycle Bin"})

# ── Scan page ─────────────────────────────────────────────────────────────────
@app.route("/scan/<file_id>", methods=["GET", "POST"], endpoint="scan_page")
@login_required
def scan(file_id):
    file_meta = fb.get_uploaded_file(str(file_id))
    if not file_meta or file_meta.get("user_id") != current_user.uid:
        flash("File not found.")
        return redirect(url_for("dashboard"))

    already_scanned = file_meta.get("status") != "Pending"
    auto_scan = request.args.get("auto_scan", "false")

    if request.method == "POST":
        if already_scanned:
            flash("This file has already been scanned.", "warning")
            return redirect(url_for("dashboard"))

        # ── Run the full scan inline (HTTP redirects are always GET, so we
        #    cannot redirect to /multiple_scan and expect its POST branch to run)
        if not scan_semaphore.acquire(blocking=False):
            flash("System is busy. Please try again in a moment.", "warning")
            return redirect(url_for("dashboard"))

        try:
            file_exists   = os.path.isfile(file_meta.get("filepath", ""))
            cached_bytes  = _pop_bytes(file_meta["id"])
            file_hash     = file_meta.get("hash", "")
            file_bytes    = None

            if file_exists:
                try:
                    with safe_open(file_meta["filepath"], "rb") as fh:
                        file_bytes = fh.read()
                    file_hash = hashlib.sha256(file_bytes).hexdigest()
                except Exception as exc:
                    logger.error("Cannot read uploaded file: %s", exc)
                    file_exists = False

            if not file_exists:
                file_bytes = cached_bytes
                if file_bytes:
                    file_hash = hashlib.sha256(file_bytes).hexdigest()
                    logger.info("scan: using cached bytes for %s", file_meta.get("filename"))
                else:
                    logger.warning("scan: no bytes available for %s", file_meta.get("filename"))

            offline_cache = None
            results: dict = {}

            # Heuristic
            if file_bytes:
                offline_cache = _run_full_heuristic_scan(
                    file_meta.get("filename"), file_bytes, file_hash
                )
            else:
                offline_cache = {
                    "hash": file_hash, "entropy": file_meta.get("entropy", 0.0),
                    "heuristics": ["File bytes unavailable for deep scan"],
                    "suspicious_functions": [], "risky_imports": [],
                    "risk_score": max(file_meta.get("risk_score", 0), 85),
                    "pattern_result": "Bytes unavailable",
                    "signature_status": "File deleted by antivirus",
                    "risky_imports_str": "N/A", "all_detections": [], "advanced": {},
                }
            _apply_scan_result_to_file(file_meta, offline_cache)
            results["heuristic"] = offline_cache

            # VirusTotal
            try:
                vt_raw = smart_virustotal_scan(
                    file_meta.get("filepath") if file_exists else None, file_hash
                )
                if vt_raw and "scans" not in vt_raw:
                    vt_raw["scans"] = {}
                results["virustotal"] = vt_raw
            except Exception as exc:
                logger.warning("VirusTotal error: %s", exc)
                results["virustotal"] = {"error": str(exc), "positives": 0,
                                         "engine_count": 0, "method": "error", "scans": {}}

            # AI analysis
            results["ai_analysis"] = analyze_file_ai(
                entropy=offline_cache.get("entropy", 0),
                patterns=offline_cache.get("pattern_result", "None"),
                imports=offline_cache.get("risky_imports_str", "None"),
                risk_score=offline_cache.get("risk_score", 0),
            )
            file_meta["ai_analysis"] = results["ai_analysis"]

            # Final risk
            final_risk        = offline_cache.get("risk_score", 0)
            detection_details = (offline_cache.get("suspicious_functions", []) +
                                 offline_cache.get("heuristics", []))

            vt = results.get("virustotal", {})
            if isinstance(vt, dict) and "error" not in vt:
                total = vt.get("engine_count", 0)
                pos   = vt.get("positives", 0)
                if total:
                    final_risk = max(final_risk, int((pos / total) * 100))
                if pos:
                    detection_details.append(
                        f"VirusTotal: {pos}/{total} engines detected threat"
                    )

            file_meta["risk_score"]   = min(final_risk, 100)
            file_meta["threat_level"], file_meta["status"] = determine_threat_level(
                final_risk, detection_details
            )
            file_meta["explanation"] = generate_explanation(file_meta)

            # Always save the file record — manual delete from dashboard
            fb.save_uploaded_file(file_meta)

            return render_template(
                "scan.html",
                file=file_meta,
                result=True,
                already_scanned=False,
                results=results,
            )

        finally:
            scan_semaphore.release()

    if already_scanned:
        return render_template("scan.html", file=file_meta, result=True,
                               already_scanned=True)

    return render_template("scan.html", file=file_meta, result=False,
                           auto_scan=auto_scan, already_scanned=already_scanned)


@app.route("/multiple_scan/<file_id>", methods=["GET", "POST"])
@login_required
def multiple_scan(file_id):
    file_meta = fb.get_uploaded_file(str(file_id))
    if not file_meta or file_meta.get("user_id") != current_user.uid:
        flash("File not found.")
        return redirect(url_for("dashboard"))

    if file_meta.get("status") != "Pending":
        flash("This file has already been scanned.", "warning")
        return redirect(url_for("dashboard"))

    if not scan_semaphore.acquire(blocking=False):
        flash("System is busy. Please try again in a moment.", "warning")
        return redirect(url_for("dashboard"))

    try:
        scan_types_param = request.args.get("scans", ",".join(ALL_SCAN_TYPES))
        file_exists      = os.path.isfile(file_meta.get("filepath", ""))

        cached_bytes: bytes | None = _pop_bytes(file_meta["id"])

        if request.method == "POST":
            raw = request.form.getlist("scan_types")
            if raw:
                scan_types_param = ",".join(raw)
            if not scan_types_param:
                scan_types_param = ",".join(ALL_SCAN_TYPES)

            scan_list = [s.strip() for s in scan_types_param.split(",") if s.strip()]
            if not scan_list:
                scan_list = ALL_SCAN_TYPES

            file_bytes: bytes | None = None
            file_hash  = file_meta.get("hash", "")

            if file_exists:
                try:
                    with safe_open(file_meta["filepath"], "rb") as fh:
                        file_bytes = fh.read()
                    file_hash = hashlib.sha256(file_bytes).hexdigest()
                except Exception as exc:
                    logger.error("Cannot read file for multiple_scan: %s", exc)
                    file_exists = False

            if not file_exists:
                file_bytes = cached_bytes
                if file_bytes:
                    file_hash = hashlib.sha256(file_bytes).hexdigest()
                    logger.info("multiple_scan: using cached bytes for AV-deleted file %s",
                                file_meta.get("filename"))
                else:
                    logger.warning("multiple_scan: no bytes available for %s", file_meta.get("filename"))

            offline_cache: dict | None = None
            results: dict = {}

            for scan_type in scan_list:
                if scan_type == "heuristic":
                    if file_bytes:
                        offline_cache = _run_full_heuristic_scan(
                            file_meta.get("filename"), file_bytes, file_hash
                        )
                    else:
                        offline_cache = {
                            "hash":                 file_hash,
                            "entropy":              file_meta.get("entropy", 0.0),
                            "heuristics":           [
                                "File deleted by antivirus — bytes unavailable for deep scan"
                            ],
                            "suspicious_functions": [],
                            "risky_imports":        [],
                            "risk_score":           max(file_meta.get("risk_score", 0), 85),
                            "pattern_result":       "AV-deleted — no bytes available",
                            "signature_status":     "File deleted by antivirus",
                            "risky_imports_str":    "N/A",
                            "all_detections":       [
                                "File deleted by antivirus — bytes unavailable"
                            ],
                            "advanced":             {},
                        }
                    _apply_scan_result_to_file(file_meta, offline_cache)
                    results["heuristic"] = offline_cache

                elif scan_type == "virustotal":
                    try:
                        vt_raw = smart_virustotal_scan(
                            file_meta.get("filepath") if file_exists else None,
                            file_hash,
                        )
                        if vt_raw and "scans" not in vt_raw:
                            vt_raw["scans"] = {}
                        results["virustotal"] = vt_raw
                    except Exception as exc:
                        logger.warning("VirusTotal error: %s", exc)
                        results["virustotal"] = {
                            "error": str(exc),
                            "positives": 0, "engine_count": 0,
                            "method": "error", "scans": {},
                        }

                elif scan_type == "ai_analysis":
                    if offline_cache is None:
                        if file_bytes:
                            offline_cache = _run_full_heuristic_scan(
                                file_meta.get("filename"), file_bytes, file_hash
                            )
                        else:
                            offline_cache = {
                                "entropy": file_meta.get("entropy", 0.0),
                                "pattern_result": "N/A",
                                "risky_imports_str": "None",
                                "risk_score": file_meta.get("risk_score", 0),
                                "advanced": {},
                            }
                    patterns = offline_cache.get("pattern_result", "None")
                    imports  = offline_cache.get("risky_imports_str", "None")
                    results["ai_analysis"] = analyze_file_ai(
                        entropy=offline_cache.get("entropy", 0),
                        patterns=patterns,
                        imports=imports,
                        risk_score=offline_cache.get("risk_score", 0),
                    )

            final_risk        = 0
            detection_details = []

            if "heuristic" in results:
                hd         = results["heuristic"]
                final_risk = max(final_risk, hd.get("risk_score", 0))
                _apply_scan_result_to_file(file_meta, hd)
                detection_details += (
                    hd.get("suspicious_functions", []) + hd.get("heuristics", [])
                )

            if "virustotal" in results:
                vt = results["virustotal"]
                if isinstance(vt, dict) and "error" not in vt:
                    total = vt.get("engine_count", 0)
                    pos   = vt.get("positives",    0)
                    if total:
                        final_risk = max(final_risk, int((pos / total) * 100))
                    if pos:
                        detection_details.append(
                            f"VirusTotal: {pos}/{total} engines detected threat"
                        )

            if "ai_analysis" in results:
                file_meta["ai_analysis"] = results["ai_analysis"]

            file_meta["risk_score"] = min(final_risk, 100)
            file_meta["threat_level"], file_meta["status"] = determine_threat_level(
                final_risk, detection_details
            )
            file_meta["explanation"] = generate_explanation(file_meta)

            fb.save_uploaded_file(file_meta)

            return render_template(
                "scan.html",
                file=file_meta,
                result=True,
                scan_mode="multiple",
                results=results,
            )

        return render_template(
            "scan.html",
            file=file_meta,
            result=False,
            scan_mode="multiple",
            scan_types=scan_types_param.split(",") if scan_types_param else ALL_SCAN_TYPES,
        )

    finally:
        scan_semaphore.release()


def _get_all_scanned_files():
    # 1. Load user uploads from Firebase
    files = fb.list_user_files(current_user.uid)
    scanned = [f for f in files if f.get("status") != "Pending"]
    
    # Track seen paths and hashes to prevent double-counting
    seen_paths = set(f.get("filepath") for f in scanned if f.get("filepath"))
    seen_hashes = set(f.get("hash") for f in scanned if f.get("hash"))

    # 2. Load local real-time monitor detections from Desktop JSON
    detections_file = os.path.join(os.path.expanduser("~"), "Desktop", "TrustFile_Detections.json")
    if os.path.exists(detections_file):
        try:
            with open(detections_file, "r", encoding="utf-8") as f:
                raw_detections = json.load(f)
                for entry in raw_detections:
                    if isinstance(entry, dict):
                        
                        path_str = entry.get("file_path", "") or entry.get("filepath", "") or ""
                        time_str = entry.get("timestamp", "") or ""
                        file_hash = entry.get("hash", "")

                        # Deduplicate if already present in database
                        if path_str in seen_paths or (file_hash and file_hash in seen_hashes):
                            continue

                        h = hashlib.sha256(f"{path_str}{time_str}".encode("utf-8")).hexdigest()
                        
                        local_entry = {
                            "id": f"local_{h}",
                            "filename": os.path.basename(path_str),
                            "filepath": path_str,
                            "upload_time": time_str,
                            "status": entry.get("status", "Safe"),
                            "threat_level": entry.get("threat_level", "Low"),
                            "risk_score": entry.get("risk_score", 0),
                            "entropy": entry.get("entropy", 0.0),
                            "hash": file_hash,
                            "pattern_result": ", ".join(entry.get("patterns", [])[:3]) if isinstance(entry.get("patterns"), list) else entry.get("pattern_result", ""),
                            "signature_status": ", ".join(entry.get("heuristics", [])[:3]) if isinstance(entry.get("heuristics"), list) else entry.get("signature_status", ""),
                            "ai_analysis": entry.get("ai_analysis", ""),
                            "user_id": current_user.uid
                        }
                        scanned.append(local_entry)
                        if path_str:
                            seen_paths.add(path_str)
                        if file_hash:
                            seen_hashes.add(file_hash)
        except Exception as e:
            logger.error("Error reading TrustFile_Detections.json: %s", e)
            
    return scanned


@app.route("/view_result/<file_id>")
@login_required
def view_result(file_id):
    file_meta = fb.get_uploaded_file(str(file_id))
    if not file_meta or file_meta.get("user_id") != current_user.uid:
        # Fallback to check local monitor detections if local_
        if str(file_id).startswith("local_"):
            detections_file = os.path.join(os.path.expanduser("~"), "Desktop", "TrustFile_Detections.json")
            if os.path.exists(detections_file):
                try:
                    with open(detections_file, "r", encoding="utf-8") as f:
                        detections = json.load(f)
                        for entry in detections:
                            if isinstance(entry, dict):
                                path_str = entry.get("file_path", "") or entry.get("filepath", "") or ""
                                time_str = entry.get("timestamp", "") or ""
                                h = hashlib.sha256(f"{path_str}{time_str}".encode("utf-8")).hexdigest()
                                if f"local_{h}" == str(file_id):
                                    local_meta = {
                                        "id": f"local_{h}",
                                        "filename": os.path.basename(path_str),
                                        "filepath": path_str,
                                        "upload_time": time_str,
                                        "status": entry.get("status", "Safe"),
                                        "threat_level": entry.get("threat_level", "Low"),
                                        "risk_score": entry.get("risk_score", 0),
                                        "entropy": entry.get("entropy", 0.0),
                                        "hash": entry.get("hash", ""),
                                        "pattern_result": ", ".join(entry.get("patterns", [])[:3]) if isinstance(entry.get("patterns"), list) else entry.get("pattern_result", ""),
                                        "signature_status": ", ".join(entry.get("heuristics", [])[:3]) if isinstance(entry.get("heuristics"), list) else entry.get("signature_status", ""),
                                        "ai_analysis": entry.get("ai_analysis", ""),
                                        "user_id": current_user.uid
                                    }
                                    return render_template("scan.html", file=local_meta, result=True)
                except Exception as e:
                    logger.error("Error reading TrustFile_Detections.json in view_result: %s", e)
        
        flash("File not found or access denied.")
        return redirect(url_for("dashboard"))
    return render_template("scan.html", file=file_meta, result=True)


# ── Helper: send file to recycle bin (falls back to permanent delete) ────────
def _trash_file(filepath: str) -> None:
    """Move a file to the system recycle bin. Falls back to os.remove if
    send2trash is not available or the operation fails."""
    if not filepath or not os.path.isfile(filepath):
        return
    if _send_to_trash is not None:
        try:
            _send_to_trash(filepath)
            logger.info("Moved to recycle bin: %s", filepath)
            return
        except Exception as exc:
            logger.warning("send2trash failed for %s: %s — falling back to delete", filepath, exc)
    try:
        os.remove(filepath)
        logger.info("Permanently deleted (no recycle bin): %s", filepath)
    except OSError as exc:
        logger.warning("Failed to delete file %s: %s", filepath, exc)


# ── Delete file ───────────────────────────────────────────────────────────────
@app.route("/delete/<file_id>", methods=["POST"], endpoint="delete_file")
@login_required
def delete_file(file_id):
    if str(file_id).startswith("local_"):
        # This is a local detection. Trash the physical file and remove from TrustFile_Detections.json
        detections_file = os.path.join(os.path.expanduser("~"), "Desktop", "TrustFile_Detections.json")
        if os.path.exists(detections_file):
            try:
                with open(detections_file, "r", encoding="utf-8") as f:
                    detections = json.load(f)
                
                target_filepath = None
                for entry in detections:
                    if isinstance(entry, dict):
                        path_str = entry.get("file_path", "") or entry.get("filepath", "") or ""
                        time_str = entry.get("timestamp", "") or ""
                        h = hashlib.sha256(f"{path_str}{time_str}".encode("utf-8")).hexdigest()
                        if f"local_{h}" == str(file_id):
                            target_filepath = path_str
                            break
                
                if target_filepath:
                    _trash_file(target_filepath)
                    updated = [e for e in detections if (e.get("file_path") or e.get("filepath") or "") != target_filepath]
                    with open(detections_file, "w", encoding="utf-8") as f:
                        json.dump(updated, f, indent=4)
                    flash("Local file moved to Recycle Bin and record deleted.")
                else:
                    flash("Local file record not found.")
            except Exception as e:
                logger.error("Error deleting local detection: %s", e)
                flash("Error deleting local record.")
        else:
            flash("Local detection log file not found.")
        return redirect(request.referrer or url_for("history"))

    record = fb.get_uploaded_file(str(file_id))
    if record and record.get("user_id") == current_user.uid:
        target_hash = record.get("hash")
        target_path = record.get("filepath")

        # Move the physical file to the Recycle Bin
        _trash_file(target_path)

        # Remove all duplicate records from Firebase database
        user_files = fb.list_user_files(current_user.uid)
        deleted_count = 0
        for f in user_files:
            same_hash = (target_hash and f.get("hash") == target_hash)
            same_path = (target_path and f.get("filepath") == target_path)
            if same_hash or same_path or f.get("id") == str(file_id):
                fb.delete_uploaded_file(f["id"])
                deleted_count += 1

        if deleted_count > 1:
            flash(f"Moved file to Recycle Bin and deleted {deleted_count} duplicate records.")
        else:
            flash("File moved to Recycle Bin and record deleted.")
    else:
        flash("File not found or access denied.")
    return redirect(request.referrer or url_for("history"))

# ── History ───────────────────────────────────────────────────────────────────
@app.route("/history")
@login_required
def history():
    from collections import defaultdict
    scanned = _get_all_scanned_files()

    # Group files by scan date (YYYY-MM-DD)
    grouped = defaultdict(list)
    for f in scanned:
        raw_time = f.get("upload_time", "")
        try:
            if raw_time:
                dt = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
                day_key = dt.strftime("%Y-%m-%d")
                day_label = dt.strftime("%B %d, %Y")  # e.g. July 19, 2026
            else:
                day_key = "Unknown"
                day_label = "Unknown Date"
        except Exception:
            day_key = "Unknown"
            day_label = "Unknown Date"
        f["_day_key"] = day_key
        f["_day_label"] = day_label
        grouped[day_key].append(f)

    # Build summary list sorted newest-first
    day_summaries = []
    for day_key, day_files in sorted(grouped.items(), reverse=True):
        threat_counts = {"safe": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
        for df in day_files:
            tl = (df.get("threat_level") or "safe").lower()
            if tl in threat_counts:
                threat_counts[tl] += 1
            else:
                threat_counts["safe"] += 1
        highest = "safe"
        for level in ["critical", "high", "medium", "low"]:
            if threat_counts[level] > 0:
                highest = level
                break
        day_summaries.append({
            "day_key":       day_key,
            "day_label":     day_files[0]["_day_label"],
            "total":         len(day_files),
            "threat_counts": threat_counts,
            "highest":       highest,
        })

    return render_template("history.html", day_summaries=day_summaries)


@app.route("/history/day/<date>")
@login_required
def history_day(date):
    """Show all scan results for a specific date."""
    scanned = _get_all_scanned_files()

    day_files = []
    day_label = date
    for f in scanned:
        raw_time = f.get("upload_time", "")
        try:
            if raw_time:
                dt = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
                day_key = dt.strftime("%Y-%m-%d")
                day_label = dt.strftime("%B %d, %Y")
            else:
                day_key = "Unknown"
        except Exception:
            day_key = "Unknown"
        if day_key == date:
            f["_day_label"] = day_label
            day_files.append(f)

    # Sort newest scan first within the day
    day_files.sort(key=lambda x: x.get("upload_time", ""), reverse=True)

    return render_template("history_day.html", files=day_files, date=date, day_label=day_label)

# ── Reports ───────────────────────────────────────────────────────────────────
@app.route("/reports")
@login_required
def reports():
    from collections import defaultdict
    files = fb.list_user_files(current_user.uid)

    # ── Severity counters ──────────────────────────────────────────────────────
    critical = high = medium = low_count = safe = 0
    for f in files:
        risk = f.get("risk_score", 0) or 0
        if f.get("status") == "Pending":
            continue
        if risk >= 70:
            critical += 1
        elif risk >= 50:
            high += 1
        elif risk >= 30:
            medium += 1
        elif risk > 0:
            low_count += 1
        else:
            safe += 1

    total = len(files) or 1
    threats = critical + high + medium + low_count
    safe_percent  = round(safe   / total * 100)
    threat_percent = round(threats / total * 100)

    # ── 7-day daily counts ─────────────────────────────────────────────────────
    from datetime import timedelta
    today = datetime.utcnow().date()
    day_labels = []
    safe_counts   = []
    threat_counts = []
    for offset in range(6, -1, -1):
        day = today - timedelta(days=offset)
        day_labels.append(day.strftime("%a"))
        s_count = t_count = 0
        for f in files:
            upload_time = f.get("upload_time", "")
            try:
                fdate = datetime.fromisoformat(upload_time.replace("Z", "+00:00")).date()
            except Exception:
                continue
            if fdate == day:
                risk = f.get("risk_score", 0) or 0
                if risk > 0:
                    t_count += 1
                else:
                    s_count += 1
        safe_counts.append(s_count)
        threat_counts.append(t_count)

    return render_template(
        "reports.html",
        files=files,
        safe_percent=safe_percent,
        threat_percent=threat_percent,
        critical=critical,
        high=high,
        medium=medium,
        low=low_count,
        safe_counts=safe_counts,
        threat_counts=threat_counts,
        days=day_labels,
    )

# ── Settings ──────────────────────────────────────────────────────────────────
# ── Settings (disabled — redirects to dashboard) ──────────────────────────────
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    return redirect(url_for("dashboard"))

# ── Monitor API ───────────────────────────────────────────────────────────────
try:
    from file_monitor import start_system_monitor, stop_system_monitor, get_monitor
except ImportError:
    # PythonAnywhere / Linux: watchdog & win10toast unavailable — provide stubs
    logger.warning("file_monitor not available (missing watchdog/win10toast). Real-time monitoring disabled.")
    def start_system_monitor(*a, **kw): return None
    def stop_system_monitor(*a, **kw): pass
    def get_monitor(*a, **kw): return None
import threading

system_monitor = None

def get_user_monitor_settings(user_id: str) -> dict:
    s = get_or_create_user_settings(user_id)
    return {
        "auto_quarantine":  s.get("auto_quarantine", True),
        "notify_on_threat": s.get("notify_on_threat", True),
        "notify_safe":      s.get("notify_safe", False),
        "alert_sound":      s.get("alert_sound", True),
    }

def save_scan_to_db(
    filename: str, filepath: str, scan_result: dict, user_id: str | None = None
) -> None:
    try:
        if user_id is None:
            user_id = "system_monitor"

        file_hash = scan_result.get("hash", "")
        # Prevent logging duplicate scan records for the same file in Firebase
        if file_hash or filepath:
            existing_files = fb.list_user_files(user_id)
            for existing in existing_files:
                same_hash = (file_hash and existing.get("hash") == file_hash)
                same_path = (existing.get("filepath") == filepath)
                if same_hash or same_path:
                    logger.info("save_scan_to_db: duplicate scan record blocked for %s", filename)
                    return

        
        try:
            size_bytes = os.path.getsize(filepath)
            size_str = f"{round(size_bytes / 1024, 2)} KB"
        except Exception:
            size_str = "0 KB"

        adv = scan_result.get("advanced", {})
        file_record = {
            "id": str(uuid.uuid4()),
            "filename": filename,
            "filepath": filepath,
            "upload_time": datetime.now(timezone.utc).isoformat(),
            "status": scan_result.get("status", "Safe"),
            "threat_level": scan_result.get("threat_level", "Low"),
            "risk_score": scan_result.get("risk_score", 0),
            "entropy": scan_result.get("entropy", 0),
            "hash": scan_result.get("hash", ""),
            "pattern_result": ", ".join(scan_result.get("patterns", [])[:3]),
            "signature_status": ", ".join(scan_result.get("heuristics", [])[:3]),
            "risky_imports": ", ".join(scan_result.get("risky_imports", [])),
            "ai_analysis": scan_result.get("ai_analysis", ""),
            "user_id": user_id,
            "size": size_str,
            "advanced_heuristics": adv,
            "detected_type": adv.get("detected_type", "") if adv else "",
            "confidence": adv.get("confidence", 0) if adv else 0,
            "iocs": adv.get("iocs", []) if adv else [],
        }
        fb.save_uploaded_file(file_record)
        logger.info("Monitor scan saved: %s for user_id %s", filename, user_id)
    except Exception as exc:
        logger.error("save_scan_to_db failed for %s: %s", filename, exc)



@app.route("/api/auto_scan", methods=["POST"])
@csrf.exempt
def auto_scan_api():
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400
        
        filename = secure_filename(file.filename)
        file_bytes = file.read()
        if not file_bytes:
            return jsonify({"error": "The uploaded file is empty"}), 400
            
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        
        # 1. Run local heuristic scan
        heuristic_res = _run_full_heuristic_scan(filename, file_bytes, file_hash)
        
        # 2. Run smart VirusTotal scan
        temp_dir = os.path.join(app.config["UPLOAD_FOLDER"], "auto_scans")
        os.makedirs(temp_dir, exist_ok=True)
        temp_path = os.path.abspath(os.path.join(temp_dir, filename))
        with open(temp_path, "wb") as out:
            out.write(file_bytes)
            
        vt_res = None
        try:
            vt_res = smart_virustotal_scan(temp_path, file_hash)
        except Exception as exc:
            logger.warning("VirusTotal auto scan error: %s", exc)
            vt_res = {
                "error": str(exc),
                "positives": 0, "engine_count": 0,
                "method": "error", "scans": {}
            }
        finally:
            try:
                os.remove(temp_path)
            except Exception:
                pass
                
        # 3. AI Analysis
        patterns = heuristic_res.get("pattern_result", "None")
        imports = heuristic_res.get("risky_imports_str", "None")
        ai_res = analyze_file_ai(
            entropy=heuristic_res.get("entropy", 0.0),
            patterns=patterns,
            imports=imports,
            risk_score=heuristic_res.get("risk_score", 0)
        )
        
        # Compute final risk score, threat level, status
        final_risk = heuristic_res.get("risk_score", 0)
        detection_details = heuristic_res.get("suspicious_functions", []) + heuristic_res.get("heuristics", [])
        
        if vt_res and "error" not in vt_res:
            total = vt_res.get("engine_count", 0)
            pos = vt_res.get("positives", 0)
            if total:
                final_risk = max(final_risk, int((pos / total) * 100))
            if pos:
                detection_details.append(f"VirusTotal: {pos}/{total} engines detected threat")
                
        final_risk = min(final_risk, 100)
        threat_level, status = determine_threat_level(final_risk, detection_details)
        
        return jsonify({
            "success": True,
            "filename": filename,
            "hash": file_hash,
            "entropy": heuristic_res.get("entropy", 0),
            "risk_score": final_risk,
            "threat_level": threat_level,
            "status": status,
            "patterns": heuristic_res.get("suspicious_functions", []),
            "heuristics": heuristic_res.get("heuristics", []),
            "risky_imports": heuristic_res.get("risky_imports", []),
            "ai_analysis": ai_res,
            "virustotal": vt_res
        }), 200
        
    except Exception as e:
        logger.error("Auto-scan API error: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/start_monitor", methods=["POST"])
@csrf.exempt
@login_required
def start_monitor_api():
    global system_monitor
    try:
        settings = get_user_monitor_settings(current_user.uid)
        api_url  = request.url_root.rstrip("/")
        
        # Capture user ID before threading context is lost
        monitor_owner_id = current_user.uid
        
        def _start():
            global system_monitor
            
            # Bound callback that always uses the monitor owner's ID
            def _db_cb(filename, filepath, result, user_id=None):
                save_scan_to_db(filename, filepath, result, user_id=monitor_owner_id)
                
            system_monitor = start_system_monitor(api_url, settings, _db_cb)
            
        threading.Thread(target=_start, daemon=True).start()
        return jsonify({"success": True, "message": "System monitor started"}), 200
    except Exception as exc:
        logger.error("start_monitor_api error: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/stop_monitor", methods=["POST"])
@csrf.exempt
@login_required
def stop_monitor_api():
    global system_monitor
    try:
        if system_monitor:
            stop_system_monitor()
        return jsonify({"success": True, "message": "System monitor stopped"}), 200
    except Exception as exc:
        logger.error("stop_monitor_api error: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/realtime_detections")
@login_required
def realtime_detections_api():
    detections_file = os.path.join(os.path.expanduser("~"), "Desktop", "TrustFile_Detections.json")
    
    detections = []
    if os.path.exists(detections_file):
        try:
            with open(detections_file, "r", encoding="utf-8") as f:
                raw_detections = json.load(f)
                for entry in raw_detections:
                    if isinstance(entry, dict):
                        # Generate a synthetic ID using file_path and timestamp
                        path_str = entry.get("file_path", "") or entry.get("filepath", "") or ""
                        time_str = entry.get("timestamp", "") or ""
                        h = hashlib.sha256(f"{path_str}{time_str}".encode("utf-8")).hexdigest()
                        entry["id"] = f"local_{h}"
                        entry["filepath"] = path_str
                        detections.append(entry)
        except Exception as e:
            logger.error("Error reading TrustFile_Detections.json: %s", e)
            
    try:
        files = fb.list_user_files(current_user.uid)
        # Sort by upload_time descending
        files.sort(key=lambda x: x.get("upload_time", ""), reverse=True)
        
        recent_data = []
        for scan in files[:10]:
            # Skip Pending entries only
            if scan.get("status") == "Pending":
                continue
            recent_data.append({
                "id":           scan.get("id"),
                "timestamp":    scan.get("upload_time"),
                "filename":     scan.get("filename"),
                "threat_level": scan.get("threat_level", "Low"),
                "risk_score":   scan.get("risk_score", 0),
                "status":       scan.get("status", "Safe"),
                "ai_analysis":  (scan.get("ai_analysis")[:100] + "...") if scan.get("ai_analysis") else None,
            })
    except Exception as exc:
        logger.error("realtime_detections_api recent scans error: %s", exc)
        recent_data = []

    return jsonify({
        "realtime": detections[:20],
        "recent_scans": recent_data
    }), 200


@app.route("/api/monitor_status")
@login_required
def monitor_status_api():
    monitor       = get_monitor()
    status        = monitor.get_status() if (monitor and monitor.running) else {"running": False}
    user_settings = get_or_create_user_settings(current_user.uid)
    return jsonify({
        "running":             status.get("running", False),
        "monitored_locations": status.get("monitored_paths", 0),
        "enabled":             status.get("running", False),
        "settings": {
            "auto_quarantine":  user_settings.get("auto_quarantine", True),
            "notify_on_threat": user_settings.get("notify_on_threat", True),
        } if user_settings else {},
    })

@app.route("/api/monitored_locations")
@login_required
def monitored_locations_api():
    """Return list of monitored locations"""
    try:
        monitor = get_monitor()
        if monitor and monitor.running and hasattr(monitor, 'event_handler'):
            paths = monitor.event_handler.get_monitored_paths()
            locations = []
            for path in paths[:20]:  # Limit to 20 for display
                locations.append({
                    "path": path,
                    "type": "drive" if ":" in path and len(path) <= 4 else "folder",
                    "status": "active"
                })
            return jsonify({"locations": locations}), 200
        return jsonify({"locations": []}), 200
    except Exception as exc:
        logger.error(f"monitored_locations_api error: {exc}")
        return jsonify({"locations": [], "error": str(exc)}), 500


@app.route("/api/save_theme", methods=["POST"])
@csrf.exempt
@login_required
def save_theme_api():
    try:
        data  = request.get_json(silent=True) or {}
        theme = data.get("theme", "dark")
        if theme not in {"dark", "light"}:
            return jsonify({"error": "Invalid theme value"}), 400
        s = get_or_create_user_settings(current_user.uid)
        s["theme"] = theme
        fb.save_user_settings(current_user.uid, s)
        return jsonify({"success": True, "theme": theme}), 200
    except Exception as exc:
        logger.error("save_theme_api error: %s", exc)
        return jsonify({"error": "Internal server error"}), 500


# ── Home ──────────────────────────────────────────────────────────────────────
@app.route("/")
def home():
    return render_template("home.html")

if __name__ == "__main__":
    os.makedirs(app.config.get("UPLOAD_FOLDER", "uploads"), exist_ok=True)
    # Set APP_DEBUG=true in .env for development. NEVER use debug=True in production.
    _debug = os.environ.get("APP_DEBUG", "false").lower() == "true"
    # Exclude uploads/ from the reloader — temp files written during auto_scan
    # were causing the server to restart mid-scan, killing VirusTotal requests.
    app.run(
        debug=_debug,
        host="0.0.0.0",
        port=5000,
        exclude_patterns=[
            "**/uploads/*", "**/uploads/**/*",
            "**\\uploads\\*", "**\\uploads\\**\\*",
            "**/__pycache__/*", "**/__pycache__/**/*",
            "**\\__pycache__\\*", "**\\__pycache__\\**\\*"
        ],
    )

