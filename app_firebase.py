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
import io
import smtplib
import secrets
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone, timedelta
from threading import Semaphore

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import firebase_utils as fb

from flask_wtf.csrf import CSRFProtect, CSRFError

# ── Scan Dependencies ────────────────────────────────────────────────────────
from api.malware_api import check_hash_api, smart_virustotal_scan, get_cached_result
from api.ai_analysis import analyze_file_ai
from api.advanced_heuristics import run_advanced_heuristics

MEDIA_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".tiff", ".ico", ".heic", ".heif", ".raw", ".cr2", ".nef",
    ".mp4", ".avi", ".mov", ".mkv", ".flv", ".wmv", ".webm", ".3gp", ".m4v", ".mpg", ".mpeg",
    ".mp3", ".wav", ".ogg", ".flac", ".aac", ".m4a"
}
BINARY_EXTENSIONS = {
    ".zip", ".tar", ".gz", ".exe", ".dll", ".bin", ".dat", ".pdf", ".doc",
    ".docx", ".xls", ".xlsx"
} | MEDIA_EXTENSIONS

ALLOWED_SCAN_EXTENSIONS = {
    # Scripts & Executables
    ".txt", ".py", ".pyw", ".js", ".ts", ".vbs", ".vbe", ".bas", ".cls", ".frm", ".ps1", ".psm1", ".psd1",
    ".bat", ".cmd", ".com", ".exe", ".dll", ".bin", ".dat", ".sh", ".bash", ".elf", ".msi", ".hta", ".scr", ".wsf", ".wsh", ".reg", ".inf", ".sys",
    # Web & Server Scripts
    ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps", ".jsp", ".jspx", ".asp", ".aspx", ".cgi", ".pl", ".rb", ".go", ".java", ".class", ".dex", ".wasm",
    # Source Code
    ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".cs", ".rs", ".swift", ".kt", ".kts", ".lua", ".sql", ".r", ".scala", ".dart",
    # Markup, Documents & Macro-Enabled Office Files
    ".html", ".htm", ".css", ".xml", ".json", ".yaml", ".yml", ".pdf", ".doc", ".docx", ".docm", ".dotm", ".dotx", ".xls", ".xlsx", ".xlsm", ".xltm", ".xltx", ".ppt", ".pptx", ".pptm", ".potm", ".potx", ".odt", ".ods", ".odp", ".rtf", ".csv", ".tsv", ".log", ".svg",
    # Shortcuts, Packages & Email
    ".lnk", ".url", ".chm", ".msg", ".eml", ".crx", ".xpi", ".swf",
    # Archives & Disk Images
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".7z", ".rar", ".jar", ".apk", ".iso", ".img", ".cab", ".vhd", ".vhdx",
    # Raw samples & arbitrary payloads
    ".sample", ".malware", ".payload", ".dump", ".raw", ".out", ".so", ".dylib", ".tmp", ".bak", ".old"
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

def _get_bytes(file_id):
    if file_id in _BYTE_CACHE:
        _BYTE_CACHE.move_to_end(file_id)
        return _BYTE_CACHE[file_id]
    return None

def _pop_bytes(file_id):
    return _BYTE_CACHE.pop(file_id, None)

def is_binary_file(file_path):
    return os.path.splitext(file_path)[1].lower() in BINARY_EXTENSIONS

# ── In-memory guest session store (no login required) ───────────────────────
# Maps guest_id (str) -> list of scan result dicts.
# Data is lost when the worker process restarts, which is intentional.
GUEST_SESSIONS: dict = {}

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

def strip_comments_and_docstrings(text: str) -> str:
    """Strip docstrings and single/multiline comments from text to avoid false positives on comments."""
    if not text:
        return ""
    # Strip python multiline docstrings
    cleaned = re.sub(r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'', '', text)
    # Strip C-style block comments
    cleaned = re.sub(r'/\*[\s\S]*?\*/', '', cleaned)
    # Filter out single-line comment lines (#, //, ;, --, rem)
    active_lines = []
    for line in cleaned.splitlines():
        s = line.strip()
        if s.startswith("#") or s.startswith("//") or s.startswith(";") or s.startswith("--") or s.lower().startswith("rem "):
            continue
        active_lines.append(line)
    return "\n".join(active_lines)


def _in_memory_heuristics(text: str) -> list:
    findings = []
    active_text = strip_comments_and_docstrings(text)

    if re.search(r"requests\.(post|get).*?(webhook|pastebin|ngrok|token|password|cookie)", active_text, re.I):
        findings.append("Data Exfiltration")
    if re.search(r"socket\.socket.*?connect.*?subprocess\.(Popen|call|run)", active_text, re.I | re.DOTALL):
        findings.append("Reverse Shell")
    if re.search(r"\breg(\.exe)?\s+add\b|\bschtasks(\.exe)?\b|\b(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\r\n]*\\Run\b", active_text, re.I):
        findings.append("Persistence Mechanism")
    return findings

def determine_threat_level(risk_score: int, detection_details: list, pattern_result: str = "") -> tuple[str, str]:
    # Threat level is determined strictly by the 5 standard risk score tiers:
    # BENIGN: 0–15 | LOW: 16–35 | MEDIUM: 36–55 | HIGH: 56–80 | CRITICAL: 81–100
    if risk_score >= 81:
        level = "Critical"
    elif risk_score >= 56:
        level = "High"
    elif risk_score >= 36:
        level = "Medium"
    elif risk_score >= 16:
        level = "Low"
    else:
        level = "Benign"

    # Grayware override: prank/nuisance files should always show at least LOW, never BENIGN,
    # because they have a confirmed (though harmless) behavior pattern.
    if level == "Benign":
        det_str = " ".join(str(d) for d in detection_details).lower() + str(pattern_result).lower()
        if "[grayware]" in det_str:
            level = "Low"

    status = "Threat" if level in {"Critical", "High", "Medium"} else "Benign"
    return level, status

def generate_explanation(file_dict: dict) -> str:
    risk = file_dict.get("risk_score", 0) or 0
    all_det = " ".join(file_dict.get("all_detections", []) + [file_dict.get("explanation", ""), file_dict.get("signature_status", ""), file_dict.get("pattern_result", "")]).lower()
    has_persistence = "persistence" in all_det or "reg add" in all_det or "schtasks" in all_det or "hklm" in all_det

    # Only show CRITICAL persistence warning if the final score is in High/Critical (>= 56).
    if has_persistence and risk >= 56:
        return (
            "⚠️ CRITICAL: Windows persistence mechanisms detected. Includes Registry Run Key modification (reg add HKLM\\...\\Run) and Scheduled Task creation (schtasks). "
            "These are standard techniques used by malware to maintain access after reboot. The commands are live and dangerous."
        )

    # Standard Medium Risk Policy Explanation
    if 36 <= risk <= 55:
        return "MEDIUM RISK: This file contains suspicious characteristics, but malware was not confirmed. Review the detected indicators and verify the file source before opening."

    reasons = []
    if file_dict.get("pattern_result") and file_dict.get("pattern_result") != "Clean":
        reasons.append(f"it exhibits {file_dict.get('pattern_result').lower()} behavior")
    if file_dict.get("signature_status") and file_dict.get("signature_status") != "None":
        reasons.append(f"it performs suspicious actions such as {file_dict.get('signature_status').lower()}")
    if file_dict.get("risky_imports") and file_dict.get("risky_imports") != "None":
        reasons.append(f"it uses risky modules like {file_dict.get('risky_imports')}")

    if risk >= 81:
        intro, level = "This file is very dangerous", "a critical threat"
    elif risk >= 56:
        intro, level = "This file is potentially harmful", "a high-risk threat"
    elif risk >= 36:
        intro, level = "This file shows suspicious behavior", "moderately suspicious"
    elif risk >= 16:
        intro, level = "This file has low risk", "low-risk"
    else:
        intro, level = "This file appears safe", "benign"

    if reasons:
        return f"{intro} ({level}) because " + ", ".join(reasons) + "."
    if risk <= 15:
        return f"{intro}. No significant suspicious behavior detected."
    return f"This file is classified as {level} based on static heuristic inspection."

def _sync_file_with_vt_consensus(file_dict: dict) -> bool:
    """Checks if a file record in Firebase should be updated based on VirusTotal consensus.
    If VirusTotal reports 0 detections across >= 20 engines, caps risk_score at 40 (Medium)
    and synchronizes threat_level, explanation, and AI verdict."""
    if not isinstance(file_dict, dict):
        return False

    file_hash = file_dict.get("hash")
    vt = file_dict.get("virustotal")

    updated = False  # initialize BEFORE the refresh block so we don't overwrite it

    # If VT is missing, timed out, had 0 engines, or missing scans dict, query Firebase vt_cache or quick hash check
    if not vt or not isinstance(vt, dict) or vt.get("error") or vt.get("engine_count", 0) == 0 or not vt.get("scans"):
        if file_hash:
            cached_vt = get_cached_result(file_hash)
            if not cached_vt or not cached_vt.get("scans"):
                try:
                    cached_vt = check_hash_api(file_hash)
                except Exception:
                    cached_vt = None
            if cached_vt and cached_vt.get("engine_count", 0) > 0:
                vt = cached_vt
                file_dict["virustotal"] = cached_vt
                # Immediately persist refreshed VT data to Firebase so future loads are fast
                file_id = file_dict.get("id")
                user_id = file_dict.get("user_id")
                if file_id:
                    try:
                        from firebase_admin import db as _fdb
                        _fdb.reference(f"uploaded_files/{file_id}").update({"virustotal": cached_vt})
                        if user_id:
                            _fdb.reference(f"user_files/{user_id}/{file_id}").update({"virustotal": cached_vt})
                    except Exception as _pe:
                        logger.warning("Could not persist refreshed VT data: %s", _pe)
                updated = True

    if not vt or not isinstance(vt, dict) or vt.get("error"):
        return False

    pos = vt.get("positives", 0)
    total = vt.get("engine_count", 0) or vt.get("total_engines", 0)

    current_risk = file_dict.get("risk_score", 0) or 0

    has_active_threat = any(k in str(file_dict.get("pattern_result") or "").lower() or k in str(file_dict.get("suspicious_signatures") or "").lower() or k in str(file_dict.get("heuristics") or "").lower() for k in [
        "persistence mechanism", "invoke-expression", "obfuscated loader", "obfuscated execution",
        "amsi bypass", "uac bypass", "shadow copy deletion", "php shell execution", "powershell download"
    ])

    if (total >= 20 or len(vt.get("scans", {})) >= 20) and pos == 0:
        if not has_active_threat:
            if current_risk > 30:
                file_dict["risk_score"] = 30
                current_risk = 30
                updated = True
            elif current_risk > 0 and current_risk == file_dict.get("raw_heuristic_score"):
                is_grayware = "[grayware]" in str(file_dict.get("pattern_result", "")).lower()
                current_risk = max(0, current_risk - 15)
                if is_grayware and current_risk < 10:
                    current_risk = 10
                file_dict["risk_score"] = current_risk
                updated = True

        new_level, new_status = determine_threat_level(current_risk, [], file_dict.get("pattern_result", ""))
        if file_dict.get("threat_level") != new_level or file_dict.get("status") != new_status:
            file_dict["threat_level"] = new_level
            file_dict["status"] = new_status
            updated = True

        new_exp = generate_explanation(file_dict)
        if file_dict.get("explanation") != new_exp:
            file_dict["explanation"] = new_exp
            updated = True
    elif pos >= 5:
        # High confidence malware confirmed by 5+ global security vendors
        vt_score = min(98, 80 + (pos * 2))
        if current_risk < vt_score:
            file_dict["risk_score"] = vt_score
            current_risk = vt_score
            updated = True
        new_level, new_status = determine_threat_level(current_risk, [f"VirusTotal: {pos}/{total} engines"])
        if file_dict.get("threat_level") != new_level or file_dict.get("status") != new_status:
            file_dict["threat_level"] = new_level
            file_dict["status"] = new_status
            updated = True

        # Ensure AI analysis reflects the critical threat level
        ai_data = file_dict.get("ai_analysis")
        is_stale_ai = (
            not ai_data
            or not isinstance(ai_data, dict)
            or (current_risk >= 70 and str(ai_data.get("verdict", "")).upper() in {"LOW RISK", "LOW", "BENIGN", "CLEAN", "MEDIUM"})
            or (current_risk <= 40 and str(ai_data.get("verdict", "")).upper() in {"CRITICAL", "CRITICAL RISK", "HIGH RISK", "HIGH"})
        )
        if is_stale_ai:
            file_dict["ai_analysis"] = analyze_file_ai(
                entropy=file_dict.get("entropy", 0),
                patterns=file_dict.get("pattern_result") or f"VirusTotal confirmed threat: {pos}/{total} engines flagged malicious",
                imports=file_dict.get("risky_imports", "None"),
                risk_score=current_risk,
                filename=file_dict.get("filename", ""),
            )
            file_dict["explanation"] = _extract_ai_text(file_dict["ai_analysis"])
            updated = True

    return updated

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

def _extract_ai_text(ai_data) -> str:
    """Extract plain text from ai_analysis (dict or str). Always returns a string."""
    if not ai_data:
        return ""
    if isinstance(ai_data, dict):
        return (ai_data.get("reason") or ai_data.get("explanation") or
                ai_data.get("text") or ai_data.get("verdict") or "")
    return str(ai_data)

def _extract_ai_verdict(ai_data) -> str:
    """Extract verdict label from ai_analysis."""
    if isinstance(ai_data, dict):
        return ai_data.get("verdict") or ai_data.get("label") or "Assessment Complete"
    return "Assessment Complete"

def _extract_ai_confidence(ai_data) -> int:
    """Extract confidence % (0-100) from ai_analysis."""
    if isinstance(ai_data, dict):
        return round(min(float(ai_data.get("confidence", 0.9)), 1.0) * 100)
    return 90

def _get_safe_ai_content_snippet(filename: str, file_bytes: bytes) -> str:
    """Safely extracts an in-memory static preview snippet for AI analysis without executing anything."""
    if not file_bytes:
        return ""
    ext = os.path.splitext(filename)[1].lower()
    text_extensions = {
        ".py", ".pyw", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".bas",
        ".js", ".ts", ".html", ".htm", ".txt", ".sh", ".json", ".xml", ".css",
        ".csv", ".md", ".php", ".phtml", ".jsp", ".asp", ".aspx", ".rb", ".pl", ".log"
    }
    
    # 1. Script / Source Text
    if ext in text_extensions:
        try:
            return file_bytes[:16000].decode("utf-8", errors="ignore")[:4000]
        except Exception:
            return ""

    # 2. ZIP Archive / Office Container
    if ext in {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"} or file_bytes[:4] == b"\x50\x4b\x03\x04":
        try:
            import zipfile
            with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zf:
                infolist = zf.infolist()
                names = [e.filename for e in infolist[:30]]
                summary_lines = [f"Archive Manifest ({len(infolist)} total items):", ", ".join(names[:15])]
                
                # If script exists inside ZIP, include its text
                script_exts = (".ps1", ".bat", ".cmd", ".vbs", ".js", ".py", ".sh")
                for e in infolist:
                    if any(e.filename.lower().endswith(sfx) for sfx in script_exts):
                        inner_raw = zf.read(e.filename)[:4000]
                        inner_txt = inner_raw.decode("utf-8", errors="ignore")[:2000]
                        summary_lines.append(f"\nExtracted Script [{e.filename}]:\n{inner_txt}")
                        break
                return "\n".join(summary_lines)[:4000]
        except Exception:
            return "ZIP Archive (manifest unreadable)"

    # 3. Executable / Binary File
    import re
    strings = re.findall(rb"[\x20-\x7e]{6,}", file_bytes[:32768])
    interesting_strings = []
    for s in strings:
        try:
            st = s.decode("ascii", errors="ignore").strip()
            if any(k in st.lower() for k in ["http", "https", "c2", "cmd", "powershell", "reg", "run", "schtasks", "alloc", "inject", "hook", "socket", "key", "password"]):
                interesting_strings.append(st)
        except Exception:
            pass
    if interesting_strings:
        return "Extracted Static Strings / API References:\n" + "\n".join(interesting_strings[:25])
    return ""

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
    text       = file_bytes.decode("utf-8", errors="ignore")

    active_text = strip_comments_and_docstrings(text)

    if not is_binary:
        heuristics = _in_memory_heuristics(active_text)
        text_lower = active_text.lower()

        string_patterns = {
            "Code Execution":  r"\b(eval|exec)\s*\(",
            "System Command":  r"\b(os\.system|cmd\.exe|powershell)\b",
            "Process Spawn":   r"\b(subprocess\.(Popen|call|run)|start)\b",
            "Infinite Loop":   r"(:\w+.*goto\s+\w+)|(while\s+true)",
            "Network":         r"\b(requests\.(get|post)|socket|http|ftp)\b",
            "Encoding":        r"\b(base64|b64decode|hex|encode|decode)\b",
            "Script Engine":   r"\b(cscript(\.exe)?|powershell(\.exe)?|wscript\.shell)\b",
            "File Access":     r"\b(open|write|delete|remove|mkdir)\b",
            "Batch Abuse":     r"\b(start|taskkill|shutdown|del)\b",
        }
        for label, pattern in string_patterns.items():
            if re.findall(pattern, text_lower):
                suspicious.append(f"{label} detected")

        dangerous_mods = {"os", "sys", "subprocess", "socket", "requests"}
        for imp in dangerous_mods:
            if re.search(rf"\bimport {imp}\b|\bfrom {imp} import", active_text):
                risky_imports.append(imp)

    norm_ext = ext.lower().strip()
    if not norm_ext.startswith("."):
        norm_ext = "." + norm_ext

    # ── EICAR Antivirus Test Signature Inspection (Raw & In-Memory ZIP) ───────
    # The real EICAR test file is exactly 68 bytes: X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
    # IMPORTANT: Only flag as EICAR when the binary payload is tiny (< 500 bytes).
    # Python/JS/TS source code (.py, .js, .ts) may contain EICAR as a detection
    # constant string — scanning these would cause a false positive.
    EICAR_BINARY = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    SOURCE_CODE_EXTS = {".py", ".js", ".ts", ".rb", ".php", ".java", ".go", ".cs",
                        ".cpp", ".c", ".h", ".rs", ".lua", ".pl", ".r", ".swift",
                        ".kt", ".md", ".txt", ".json", ".html", ".css", ".xml"}

    is_eicar_found = False
    ARCHIVE_EXTS = {".zip", ".jar", ".apk", ".rar", ".7z", ".docx", ".xlsx", ".pptx", ".tar", ".gz"}
    # Raw file check — only for non-archive raw files (eicar.com, eicar.txt) that are tiny (actual EICAR = 68 bytes, allow up to 500)
    if norm_ext not in ARCHIVE_EXTS and file_bytes[:4] != b"\x50\x4b\x03\x04" and EICAR_BINARY in file_bytes and len(file_bytes) < 500:
        is_eicar_found = True
        heuristics.append("EICAR Antivirus Test Signature detected")
        suspicious.append("EICAR Standard AV Test Signature")

    if (norm_ext in {".zip", ".jar", ".apk"} or file_bytes[:4] == b"\x50\x4b\x03\x04") and not is_eicar_found:
        try:
            import zipfile
            with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zf:
                for entry in zf.infolist():
                    entry_ext = os.path.splitext(entry.filename)[1].lower()
                    # Skip source code files — they may contain EICAR as a detection constant
                    if entry_ext in SOURCE_CODE_EXTS:
                        continue
                    # Only flag small entries (real EICAR = 68 bytes, allow up to 500)
                    if entry.file_size > 500:
                        continue
                    if entry.file_size < 10 * 1024 * 1024:
                        raw_entry = zf.read(entry.filename)
                        if EICAR_BINARY in raw_entry:
                            is_eicar_found = True
                            heuristics.append(f"EICAR Test Signature detected inside archive entry '{entry.filename}'")
                            suspicious.append(f"EICAR Test File in '{entry.filename}'")
                            break
        except Exception:
            pass

    # Check for active persistence commands in non-commented code
    has_persistence_lotl = bool(re.search(
        r"\breg(\.exe)?\s+add\b|\bschtasks(\.exe)?\b|\b(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\r\n]*\\Run\b|\bcertutil.*-(urlcache|decode)|\bwmic.*process|\bbitsadmin|\bnet\s+(user|localgroup)",
        active_text, re.I
    ))
    has_reg_or_schtasks = bool(re.search(
        r"\breg(\.exe)?\s+add\b|\bschtasks(\.exe)?\b|\b(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\r\n]*\\Run\b",
        active_text, re.I
    ))

    PASSIVE_MARKUP_EXTS = {".html", ".htm", ".css", ".txt", ".json", ".xml", ".svg", ".md", ".rst"}
    is_passive_markup = norm_ext in PASSIVE_MARKUP_EXTS
    if is_passive_markup and not has_persistence_lotl:
        suppress_labels = {"file access", "network", "script engine", "system command", "process spawn", "batch abuse"}
        suspicious = [s for s in suspicious if not any(lbl in s.lower() for lbl in suppress_labels)]

    # ── Grayware / Prank Detector (Low Risk — content-based, NOT extension-based) ──
    # Every CONFIRMED disruptive/prank pattern adds a score contribution.
    # Score is based on actual detected behavior inside the file, never on filename/ext alone.
    # Cap: grayware alone cannot exceed 30 — it can never falsely trigger Medium/High/Critical.
    _grayware_notes = []
    _grayware_score = 0
    _text_lower = active_text.lower()

    # 1. VBScript: Repeated MsgBox / InputBox popup loop (classic prank)
    if norm_ext in {".vbs", ".vbe"} and re.search(r"\bfor\b.{0,30}\bto\b.{0,10}\d+", active_text, re.I):
        if re.search(r"\bmsgbox\b|\binputbox\b", active_text, re.I):
            _grayware_notes.append("[GRAYWARE] VBScript repeated popup loop detected (prank/nuisance — no system-level threat)")
            _grayware_score += 15

    # 2. Batch: Infinite loop with disruptive display commands
    if norm_ext in {".bat", ".cmd"}:
        if re.search(r":(loop|start)\b.*\n.*goto\s+(loop|start)", active_text, re.I | re.S):
            if re.search(r"\bstart\b|\bcolor\b|\becho\b|\bpause\b", active_text, re.I):
                _grayware_notes.append("[GRAYWARE] Batch infinite loop with disruptive display commands (prank pattern)")
                _grayware_score += 15
        # Batch: timed shutdown/restart (annoying but no data theft)
        if re.search(r"\bshutdown\s+/[sra]\s+/t\s+\d+", active_text, re.I):
            _grayware_notes.append("[GRAYWARE] Timed shutdown/restart command detected (prank/annoyance — no malicious payload)")
            _grayware_score += 15

    # 3. PowerShell: MessageBox spam via Windows Forms
    if norm_ext in {".ps1"}:
        if re.search(r"windows\.forms\.messagebox|system\.windows\.forms", active_text, re.I):
            if re.search(r"\bfor\b|\bwhile\b|\bdo\b", active_text, re.I):
                _grayware_notes.append("[GRAYWARE] PowerShell repeated Windows Forms dialog loop (prank pattern)")
                _grayware_score += 15
        # PowerShell: audio beep loop prank
        if re.search(r"\[console\]::beep\s*\(", active_text, re.I):
            _grayware_notes.append("[GRAYWARE] PowerShell repeated console beep loop (audio prank pattern)")
            _grayware_score += 15

    # 4. Python: Repeated print / input / tkinter messagebox in large loop
    if norm_ext in {".py"}:
        if re.search(r"(while\s+true|for\s+\w+\s+in\s+range\s*\(\s*\d{3,})", active_text, re.I):
            if re.search(r"\bprint\s*\(|\binput\s*\(|\btkinter\b|\bshowinfo\b|\bshowerror\b", active_text, re.I):
                _grayware_notes.append("[GRAYWARE] Python repeated dialog/print loop (prank/nuisance pattern)")
                _grayware_score += 15

    # 5. Universal: Fork bomb — self-replicating process (resource exhaustion, more disruptive)
    if re.search(r"start\s+%0\s*%\*|:\s*\(\s*\)\s*\{\s*:\s*\|", active_text, re.I):
        _grayware_notes.append("[GRAYWARE] Fork bomb pattern detected (process replication loop — system resource abuse)")
        _grayware_score += 25  # More disruptive than a simple popup

    # 6. Universal: Fake error / BSOD / "your PC is infected" mimicry (social engineering)
    #    Only relevant in script/executable files — NOT in documents (.docx, .pdf, .txt, .html)
    #    because research papers and educational content routinely mention "BSOD" or "critical error"
    #    in descriptive/educational context and are NOT social engineering payloads.
    _BSOD_ACTIVE_EXTS = {
        ".vbs", ".bat", ".cmd", ".ps1", ".js", ".wsf", ".hta", ".py", ".sh",
        ".exe", ".scr", ".com", ".pif", ".vbe", ".jse",
    }
    if norm_ext in _BSOD_ACTIVE_EXTS:
        if re.search(r"(blue\s*screen|bsod|critical\s*error|your\s*pc\s*(has\s+a\s+virus|is\s+infected))", _text_lower):
            _grayware_notes.append("[GRAYWARE] Fake system error / BSOD mimicry text (social engineering prank — no actual damage)")
            _grayware_score += 15


    # 7. VBScript/Batch: CD-ROM tray open/close prank (hardware disruption)
    if re.search(r"MediaPlayer\.openPlayer|mc\s+open\s+type\s+cdaudio|Set\s+oWMP\s*=.*MediaPlayer", active_text, re.I):
        _grayware_notes.append("[GRAYWARE] CD-ROM drive tray loop command (hardware prank pattern)")
        _grayware_score += 15

    # 8. Universal: Repeated desktop wallpaper change / taskbar hide (UI disruption)
    if re.search(r"SystemParametersInfo|SPI_SETDESKWALLPAPER|ShowWindow.*SW_HIDE", active_text, re.I):
        _grayware_notes.append("[GRAYWARE] Desktop/UI disruption command detected (wallpaper/taskbar prank pattern)")
        _grayware_score += 15

    # 9. Batch/VBScript: Delete Recycle Bin / temp files disruption (non-destructive cleaning prank)
    if re.search(r"rd\s+/s\s+/q\s+%temp%|rd\s+/s\s+/q.*recycle", active_text, re.I):
        _grayware_notes.append("[GRAYWARE] Disruptive temp/recycle bin deletion loop (nuisance prank — targets temp files only)")
        _grayware_score += 15

    if _grayware_notes:
        # Cap: grayware alone cannot push into Medium (36+) — max contribution is 30
        _grayware_score = min(_grayware_score, 30)
        heuristics = list(dict.fromkeys(heuristics + _grayware_notes))
        # Note: _grayware_score is applied after risk_score is initialized below
    # ── End Grayware Detector ─────────────────────────────────────────────────

    threshold  = get_file_type_entropy_threshold("x" + ext)
    risk_score = 0

    # Apply confirmed grayware score (content-based Low Risk contribution)
    if _grayware_notes:
        risk_score += _grayware_score

    norm_ext = ext.lower().strip()
    if not norm_ext.startswith("."):
        norm_ext = "." + norm_ext

    inherently_compressed = {".pdf", ".docx", ".xlsx", ".pptx", ".zip", ".png", ".jpg", ".jpeg", ".gif", ".jar", ".apk"}
    if norm_ext not in inherently_compressed:
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
        if any(h == gw for gw in _grayware_notes):
            continue  # Already accounted for in _grayware_score
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
    if is_eicar_found:
        risk_score = max(risk_score, 85)

    # For pure grayware/prank scripts with no confirmed malware indicators, cap at _grayware_score (max 30)
    has_active_malware = bool(
        any("obfuscated" in d.lower() or "persistence" in d.lower() or "reverse shell" in d.lower() or "cradle" in d.lower() or "shadow copy" in d.lower() or "autorun" in d.lower() for d in heuristics + suspicious)
    )
    if _grayware_notes and not has_active_malware:
        risk_score = min(risk_score, _grayware_score)

    risk_score  = min(risk_score, 100)


    if not is_binary:
        has_exec_func = bool(re.search(
            r"\b(eval|exec|compile|subprocess|os\.system|os\.popen|shell_exec|passthru)\b|\b(eval|exec)\s*\(|Invoke-Expression|\biex\b",
            active_text, re.I
        ))
        has_obf_func = bool(re.search(
            r"\b(base64|b64decode|b64encode|codecs|zlib|decompress|uncompress)\b|-[Ee][Nn][Cc]|\b(chr|ord)\s*\(|\\x[0-9a-fA-F]{2}",
            active_text, re.I
        ))

        if has_reg_or_schtasks:
            if "Windows Persistence Mechanism (reg add / schtasks / HKLM Run)" not in suspicious:
                suspicious.append("Windows Persistence Mechanism (reg add / schtasks / HKLM Run)")
            if "Windows Persistence Mechanism: reg add or schtasks command" not in heuristics:
                heuristics.append("Windows Persistence Mechanism: reg add or schtasks command")
            risk_score = max(risk_score, 85)
        elif has_persistence_lotl:
            if "Living-off-the-Land Command Execution (certutil/wmic/bitsadmin/net user)" not in suspicious:
                suspicious.append("Living-off-the-Land Command Execution (certutil/wmic/bitsadmin/net user)")
            risk_score = max(risk_score, 70)
        elif has_exec_func and has_obf_func:
            if "Obfuscated Execution Routine (exec/eval + base64)" not in suspicious:
                suspicious.append("Obfuscated Execution Routine (exec/eval + base64)")
            if "Obfuscated Loader Pattern: eval/exec combined with base64/encoding" not in heuristics:
                heuristics.append("Obfuscated Loader Pattern: eval/exec combined with base64/encoding")
            # ZIP/archive containers: cap at Medium (55) — these patterns often appear
            # in legitimate source code inside project ZIPs. Let VT consensus override.
            if norm_ext in {".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx"} or file_bytes[:4] == b"\x50\x4b\x03\x04":
                risk_score = max(risk_score, 45)
            else:
                risk_score = max(risk_score, 95)
        elif is_passive_markup:
            has_code_exec = any("code execution" in s.lower() or "encoding" in s.lower() for s in suspicious)
            if has_code_exec and risk_score < 15:
                risk_score = 15

    # ── Advanced heuristics (always, on bytes) ────────────────────────────────
    adv: dict = {}
    try:
        adv = run_advanced_heuristics(filename, file_bytes)
        adv_score = adv.get("score", 0)
        adv_detections = adv.get("detections", [])
        heuristics = list(dict.fromkeys(heuristics + adv_detections))
        # Merge scores cleanly: highest confirmed threat score wins
        risk_score = max(risk_score, adv_score)
        if is_eicar_found:
            risk_score = max(risk_score, 85)
    except Exception as exc:
        logger.warning("Advanced heuristics failed in _run_full_heuristic_scan: %s", exc)


    all_patterns_combined = suspicious + [h for h in heuristics if h not in suspicious]
    pattern_str = ", ".join(all_patterns_combined[:3]) or "No suspicious patterns"
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
        "is_eicar":             is_eicar_found,  # Explicit confirmed binary EICAR flag
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

# Apply ProxyFix for Vercel/reverse-proxy HTTPS headers
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


_secret = os.environ.get("TRUSTFILE_SECRET_KEY") or "b979550ef58e9dd5670e175aa34eef959f51911a92f2e7da4989d4ff87793dd4"
app.config["SECRET_KEY"] = _secret

# CSRF configuration
app.config["WTF_CSRF_SSL_STRICT"] = False  # Allows cryptographic token validation behind cloud reverse proxies / strict referrer policies
app.config["WTF_CSRF_TIME_LIMIT"] = 3600   # 1 hour CSRF token validity

# Initialize CSRF protection (adds csrf_token() globally)
csrf = CSRFProtect(app)

# Unlimited upload size at Flask level (no application file/folder size cap)
app.config["MAX_CONTENT_LENGTH"] = None


_is_vercel = "VERCEL" in os.environ or "VERCEL_ENV" in os.environ or os.environ.get("SERVER_SOFTWARE", "").startswith("Vercel") or os.path.exists("/var/task")
if _is_vercel:
    app.config["UPLOAD_FOLDER"] = "/tmp/uploads"
    # On Vercel (HTTPS), session cookies must be Secure + SameSite=Lax
    # so they persist across serverless container redirects.
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["REMEMBER_COOKIE_SECURE"] = True
    app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
else:
    app.config["UPLOAD_FOLDER"] = os.environ.get("UPLOAD_FOLDER", os.path.join(os.path.dirname(__file__), "uploads"))
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

@app.errorhandler(413)
def request_entity_too_large(error):
    flash("⚠️ Upload exceeded web server payload capacity. Please upload in smaller batches if Nginx blocks the connection.", "warning")
    return redirect(url_for("uploadfiles"))


@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    logger.warning("CSRF validation failure handled: %s", getattr(error, 'description', error))
    flash("Your security session was refreshed. Please try again.")
    target = request.path if request.path in ["/login", "/signup", "/forgot_password"] else url_for("login")
    return redirect(target)


@app.errorhandler(500)
def internal_server_error(error):
    logger.exception("500 Internal Server Error handled: %s", error)
    flash("A temporary server issue occurred. You can use Quick Scan while we resolve it.")
    return redirect(url_for("guest_scan"))




# ── CSS Cache Busting ─────────────────────────────────────────────────────────
import time as _time
_CSS_VERSION = str(int(_time.time()))

@app.context_processor
def inject_css_version():
    return {"css_version": _CSS_VERSION}


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
        if data and isinstance(data, dict):
            return User(
                uid=data.get("uid", user_id),
                username=data.get("username", "User"),
                email=data.get("email", ""),
                password_hash=data.get("password", "")
            )
    except Exception as e:
        logger.warning("Failed to load user %s: %s", user_id, e)
    return None

# ── Auth routes ────────────────────────────────────────────────────────────────
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        try:
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "").strip()
            confirm_password = request.form.get("confirm_password", "").strip()

            if not (username and email and password):
                flash("Please fill out all fields.")
                return redirect(url_for("signup"))

            # ── Server-side password strength enforcement ──────────────────────
            import re as _re
            if len(password) < 8:
                flash("Password must be at least 8 characters long.")
                return redirect(url_for("signup"))
            if not _re.search(r"[A-Z]", password):
                flash("Password must contain at least one uppercase letter.")
                return redirect(url_for("signup"))
            if not _re.search(r"[a-z]", password):
                flash("Password must contain at least one lowercase letter.")
                return redirect(url_for("signup"))
            if not _re.search(r"[0-9]", password):
                flash("Password must contain at least one number.")
                return redirect(url_for("signup"))
            if not _re.search(r"[^A-Za-z0-9]", password):
                flash("Password must contain at least one special character (e.g. @, !, #).")
                return redirect(url_for("signup"))
            if " " in password:
                flash("Password must not contain spaces.")
                return redirect(url_for("signup"))
            if confirm_password and password != confirm_password:
                flash("Passwords do not match.")
                return redirect(url_for("signup"))
            # ──────────────────────────────────────────────────────────────────
            if fb.get_user_by_email(email):
                flash("Email already in use.")
                return redirect(url_for("signup"))
            password_hash = generate_password_hash(password, method="pbkdf2:sha256")
            uid = fb.save_user({"username": username, "email": email, "password": password_hash})
            flash("Account created! Please log in.")
            return redirect(url_for("login"))
        except Exception as exc:
            logger.exception("Signup error: %s", exc)
            flash("An error occurred during account creation. Please try again or use Quick Scan.")
            return redirect(url_for("signup"))
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("20 per minute")
def login():
    if request.method == "POST":
        try:
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "").strip()
            user_rec = fb.get_user_by_email(email)
            if user_rec and isinstance(user_rec, dict) and check_password_hash(user_rec.get("password", ""), password):
                user = User(
                    uid=user_rec.get("uid", str(uuid.uuid4())),
                    username=user_rec.get("username", "User"),
                    email=user_rec.get("email", email),
                    password_hash=user_rec.get("password", "")
                )
                login_user(user)
                next_page = request.args.get("next")
                if next_page and next_page.startswith("/"):
                    return redirect(next_page)
                return redirect(url_for("dashboard"))
            else:
                flash("Incorrect email or password. Please try again.")
                return redirect(url_for("login"))
        except Exception as exc:
            logger.exception("Login error: %s", exc)
            flash("Incorrect email or password. Please try again.")
            return redirect(url_for("login"))
    return render_template("login.html")


def _send_otp_email(to_email: str, otp: str) -> bool:
    """Send a 6-digit OTP to the given email via Gmail SMTP with dual-port fallback (587 STARTTLS / 465 SSL).
    Falls back gracefully if MAIL_USER/MAIL_PASS are not set or cloud network blocks SMTP."""
    mail_user = os.getenv("MAIL_USER") or "reymartaportadera@gmail.com"
    mail_pass = os.getenv("MAIL_PASS") or "zyngiormyvjtbkdb"
    if not mail_user or not mail_pass:
        app.logger.warning("[OTP FALLBACK — no MAIL_USER/MAIL_PASS] OTP for %s: %s", to_email, otp)
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "TrustFile — Password Reset Code"
    msg["From"]    = f"TrustFile Security <{mail_user}>"
    msg["To"]      = to_email
    html_body = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;
                padding:32px;background:#0f1117;border-radius:12px;border:1px solid #1e293b;">
        <h2 style="color:#ef4444;margin:0 0 4px;letter-spacing:2px;">TRUST<span style='color:#fff'>FILE</span></h2>
        <p style="color:#94a3b8;margin:0 0 24px;font-size:12px;letter-spacing:2px;">SECURE FILE SCANNER</p>
        <p style="color:#e2e8f0;margin:0 0 16px;font-size:15px;">Your 6-digit password reset verification code is:</p>
        <div style="background:#181f2e;border:1px solid rgba(239,68,68,0.4);
                    border-radius:10px;padding:24px;text-align:center;margin:0 0 24px;">
            <span style="font-size:38px;font-weight:800;letter-spacing:12px;
                         color:#ef4444;font-family:monospace;">{otp}</span>
        </div>
        <p style="color:#64748b;font-size:12px;line-height:1.6;">
            This code expires in <strong style='color:#94a3b8'>10 minutes</strong>.<br>
            If you did not request a password reset, you can safely ignore this email.
        </p>
    </div>
    """
    msg.attach(MIMEText(html_body, "html"))

    # Attempt 1: Direct Port 465 SSL (Direct Gmail SSL Socket — Most Reliable)
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10) as server:
            server.login(mail_user, mail_pass)
            server.sendmail(mail_user, to_email, msg.as_string())
        return True
    except Exception as exc1:
        app.logger.warning("SMTP Port 465 SSL failed (%s), attempting Port 587 STARTTLS...", exc1)

    # Attempt 2: Port 587 STARTTLS with explicit EHLO negotiation
    try:
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(mail_user, mail_pass)
            server.sendmail(mail_user, to_email, msg.as_string())
        return True
    except Exception as exc2:
        app.logger.error("All SMTP attempts failed for %s: %s", to_email, exc2)
        return False


@app.route("/forgot_password", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def forgot_password():
    step  = request.args.get("step", "1")
    token = request.args.get("token", "")

    if request.method == "POST":
        form_step = request.form.get("step", "1")

        # ── STEP 1: Check email exists → send OTP ───────────────────────────
        if form_step == "1":
            email = request.form.get("email", "").strip().lower()
            if not email:
                flash("Please enter your email address.")
                return redirect(url_for("forgot_password"))

            user_rec = fb.get_user_by_email(email)
            # Always show the same message (no user enumeration)
            if not user_rec:
                flash("If that email is registered, a reset code will be sent shortly.")
                return redirect(url_for("forgot_password", step="2", token="invalid"))

            otp         = str(secrets.randbelow(900000) + 100000)   # 6-digit
            reset_token = secrets.token_urlsafe(32)
            expires_at  = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()

            fb.save_password_reset(reset_token, {
                "email":      email,
                "otp_hash":   generate_password_hash(otp, method="pbkdf2:sha256"),
                "expires_at": expires_at,
                "verified":   False,
            })
            sent = _send_otp_email(email, otp)
            mail_user = os.getenv("MAIL_USER") or "reymartaportadera@gmail.com"
            mail_pass = os.getenv("MAIL_PASS") or "zyngiormyvjtbkdb"
            if sent:
                flash("A 6-digit code was sent to your email. Check your inbox (and spam folder).", "success")
            elif not mail_user or not mail_pass:
                flash(f"A 6-digit reset code has been generated. (Cloud Backup Notice: Your code is: {otp})", "info")
            else:
                flash(f"Email delivery was delayed by mail server. Your backup 6-digit code is: {otp}", "warning")

            return redirect(url_for("forgot_password", step="2", token=reset_token))

        # ── RESEND OTP: Generate new code & resend to email ──────────────────
        elif form_step == "resend":
            token = request.form.get("token", "")
            rec = fb.get_password_reset(token) if token and token != "invalid" else None
            if not rec:
                flash("If that email is registered, a new reset code will be sent shortly.", "info")
                return redirect(url_for("forgot_password", step="2", token="invalid"))

            email = rec.get("email", "")
            otp = str(secrets.randbelow(900000) + 100000)   # 6-digit
            expires_at = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()

            rec["otp_hash"] = generate_password_hash(otp, method="pbkdf2:sha256")
            rec["expires_at"] = expires_at
            rec["verified"] = False
            fb.save_password_reset(token, rec)

            sent = _send_otp_email(email, otp)
            mail_user = os.getenv("MAIL_USER") or "reymartaportadera@gmail.com"
            mail_pass = os.getenv("MAIL_PASS") or "zyngiormyvjtbkdb"
            if sent:
                flash("A new 6-digit code was sent to your email. Check your inbox.", "success")
            elif not mail_user or not mail_pass:
                flash(f"A new 6-digit reset code has been generated. (Cloud Backup Notice: Your code is: {otp})", "info")
            else:
                flash(f"Email delivery was delayed by mail server. Your backup 6-digit code is: {otp}", "warning")

            return redirect(url_for("forgot_password", step="2", token=token))

        # ── STEP 2: Verify OTP ───────────────────────────────────────────────
        elif form_step == "2":

            token     = request.form.get("token", "")
            otp_input = request.form.get("otp", "").strip()

            rec = fb.get_password_reset(token) if token != "invalid" else None
            if not rec:
                flash("Invalid or expired reset session. Please start again.")
                return redirect(url_for("forgot_password"))

            expires_at = datetime.fromisoformat(rec["expires_at"])
            if datetime.now(timezone.utc) > expires_at:
                fb.delete_password_reset(token)
                flash("Your reset code has expired. Please try again.")
                return redirect(url_for("forgot_password"))

            if not check_password_hash(rec["otp_hash"], otp_input):
                flash("Incorrect code. Please try again.")
                return redirect(url_for("forgot_password", step="2", token=token))

            rec["verified"] = True
            fb.save_password_reset(token, rec)
            return redirect(url_for("forgot_password", step="3", token=token))

        # ── STEP 3: Set new password ─────────────────────────────────────────
        elif form_step == "3":
            token            = request.form.get("token", "")
            new_password     = request.form.get("new_password", "").strip()
            confirm_password = request.form.get("confirm_password", "").strip()

            rec = fb.get_password_reset(token)
            if not rec or not rec.get("verified"):
                flash("Invalid or expired reset session. Please start again.")
                return redirect(url_for("forgot_password"))

            expires_at = datetime.fromisoformat(rec["expires_at"])
            if datetime.now(timezone.utc) > expires_at:
                fb.delete_password_reset(token)
                flash("Your reset session has expired. Please try again.")
                return redirect(url_for("forgot_password"))

            if not new_password or not confirm_password:
                flash("Please fill in all fields.")
                return redirect(url_for("forgot_password", step="3", token=token))

            if len(new_password) < 8:
                flash("Password must be at least 8 characters.")
                return redirect(url_for("forgot_password", step="3", token=token))

            if new_password != confirm_password:
                flash("Passwords do not match.")
                return redirect(url_for("forgot_password", step="3", token=token))

            user_rec = fb.get_user_by_email(rec["email"])
            if not user_rec:
                flash("Account not found. Please try again.")
                return redirect(url_for("forgot_password"))

            user_rec["password"] = generate_password_hash(new_password, method="pbkdf2:sha256")
            fb.save_user(user_rec)
            fb.delete_password_reset(token)

            flash("Your password has been successfully reset! Please log in.")
            return redirect(url_for("login"))

    return render_template("forgot_password.html", step=step, token=token)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

def get_or_create_user_settings(uid: str) -> dict:
    return {
        "auto_scan_enabled": True,
        "auto_scan_mode": "single",
        "scan_types": ["heuristic"],
        "notify_on_threat": True,
        "theme": "dark",
        "auto_quarantine": False,
        "alert_sound": True,
        "notify_safe": False,
    }

def _get_effective_folder_name(f: dict) -> str | None:
    if f.get("folder_name"):
        return f.get("folder_name")
    rel = f.get("relative_path") or f.get("filepath") or ""
    parts = rel.replace("\\", "/").strip("/").split("/")
    if len(parts) >= 3:
        return parts[-2]
    return None

# ── Dashboard ────────────────────────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    all_files = fb.list_user_files(current_user.uid)
    settings  = get_or_create_user_settings(current_user.uid)

    files = all_files

    counters = dict(total_scans=len(files), safe_files=0, low_threat=0,
                    medium_threat=0, high_threat=0, critical_threat=0)

    standalone_files = []
    folder_groups_dict = {}

    for f in files:
        if _sync_file_with_vt_consensus(f):
            try:
                fb.save_uploaded_file(f)
            except Exception:
                pass

        risk = f.get("risk_score", 0) or 0
        all_det = f.get("all_detections", [])
        if not all_det:
            all_det = [f.get("pattern_result", ""), f.get("signature_status", "")]
        lvl, st = determine_threat_level(risk, all_det, f.get("pattern_result", "") or f.get("signature_status", ""))
        f["threat_level"] = lvl
        f["status"] = st
        if lvl == "Critical":
            counters["critical_threat"] += 1
        elif lvl == "High":
            counters["high_threat"] += 1
        elif lvl == "Medium":
            counters["medium_threat"] += 1
        elif lvl == "Low":
            counters["low_threat"] += 1
        else:
            counters["safe_files"] += 1

        try:
            size = os.path.getsize(f["filepath"])
            f["size"] = f"{round(size / 1024, 2)} KB"
        except Exception:
            f["size"] = f.get("size", "N/A")

        f["explanation"] = f.get("explanation", "")
        f["threat_ratio"] = risk

        # Folder grouping vs Standalone files separation
        fname = _get_effective_folder_name(f)

        if fname:
            if fname not in folder_groups_dict:
                folder_groups_dict[fname] = {
                    "name": fname,
                    "files": [],
                    "threat_count": 0,
                    "max_risk": 0,
                    "threat_level": "Benign",
                    "upload_time": f.get("upload_time")
                }
            grp = folder_groups_dict[fname]
            grp["files"].append(f)
            if f.get("upload_time") and (not grp.get("upload_time") or f.get("upload_time") > grp["upload_time"]):
                grp["upload_time"] = f.get("upload_time")
            if risk > 0:
                grp["threat_count"] += 1
            if risk > grp["max_risk"]:
                grp["max_risk"] = risk
                grp["threat_level"] = f["threat_level"]
        else:
            standalone_files.append(f)

    folder_groups = list(folder_groups_dict.values())

    return render_template("dashboard.html", files=standalone_files, folder_groups=folder_groups, settings=settings, **counters)



# ── API: Single File Upload Stream (Instant Multi-Engine Threat Scan) ────────
@app.route("/api/upload_single_file", methods=["POST"])
@csrf.exempt
@login_required
def upload_single_file_api():
    try:
        return _upload_single_file_impl()
    except Exception as exc:
        import traceback
        logger.error("upload_single_file_api unhandled crash: %s\n%s", exc, traceback.format_exc())
        return jsonify({"error": f"Server error during upload: {exc}"}), 500


def _upload_single_file_impl():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "No file provided"}), 400

    raw_filename = os.path.basename(f.filename)
    filename = secure_filename(raw_filename) or f"file_{uuid.uuid4().hex[:8]}"
    ext = os.path.splitext(filename)[1].lower()

    # Extract folder name & source location if provided or present in relative path
    folder_name = request.form.get("folder_name") or (f.filename.split("/")[0] if "/" in f.filename else None)
    req_source = request.form.get("source_location")
    if req_source and not req_source.startswith("Documents / "):
        source_location = req_source
    elif folder_name:
        source_location = f"Scanned Folder / {folder_name} / {raw_filename}"
    else:
        source_location = f"Uploaded File / {raw_filename}"

    file_bytes = f.read()
    if not file_bytes:
        return jsonify({"skipped": True, "reason": "Empty file"}), 200

    file_hash = hashlib.sha256(file_bytes).hexdigest()

    try:
        user_folder = os.path.join(app.config.get("UPLOAD_FOLDER", "/tmp/uploads"), str(current_user.uid))
        os.makedirs(user_folder, exist_ok=True)
        path = os.path.abspath(os.path.join(user_folder, filename))
        if len(path) > 255:
            filename = uuid.uuid4().hex + ext
            path = os.path.abspath(os.path.join(user_folder, filename))
        with open(path, "wb") as out:
            out.write(file_bytes)
    except OSError:
        fallback_dir = os.path.join("/tmp/uploads", str(current_user.uid))
        os.makedirs(fallback_dir, exist_ok=True)
        path = os.path.join(fallback_dir, filename)
        with open(path, "wb") as out:
            out.write(file_bytes)

    relative_path = os.path.join(str(current_user.uid), filename)
    file_id = str(uuid.uuid4())

    # ── Engine 1: Full heuristic scan (fast, local — no network) ──────────────
    scan_res = _run_full_heuristic_scan(filename, file_bytes, file_hash)
    risk_score = scan_res.get("risk_score", 0)

    # ── Engine 2: VirusTotal scan (network — cap at 8 s on Vercel) ────────────
    vt_result = {}
    try:
        import signal as _signal
        def _vt_timeout(signum, frame):
            raise TimeoutError("VirusTotal timeout")
        try:
            _signal.signal(_signal.SIGALRM, _vt_timeout)
            _signal.alarm(8)
        except (AttributeError, OSError):
            pass  # SIGALRM unavailable on Windows (local dev only)
        try:
            vt_raw = smart_virustotal_scan(path, file_hash)
            if vt_raw and "scans" not in vt_raw:
                vt_raw["scans"] = {}
            vt_result = vt_raw or {}
            vt_pos = vt_result.get("positives", 0)
            vt_total = vt_result.get("engine_count", 0)
            if vt_total and vt_pos:
                risk_score = max(risk_score, int((vt_pos / vt_total) * 100))
            elif (vt_total >= 20 or len(vt_result.get("scans", {})) >= 20) and vt_pos == 0:
                _pat = str(scan_res.get("pattern_result", "")).lower()
                _heur = str(scan_res.get("heuristics", [])).lower()
                has_active_threat = any(k in _pat or k in _heur for k in [
                    "persistence mechanism", "invoke-expression", "obfuscated loader", "obfuscated execution",
                    "amsi bypass", "uac bypass", "shadow copy deletion", "php shell execution", "powershell download"
                ])
                if not has_active_threat:
                    # When VirusTotal reports 0 detections across 20+ engines,
                    # cap internal heuristic risk score at maximum of LOW (30%).
                    # BUT: grayware scores (prank/nuisance) must keep a minimum floor of 10
                    # so the AI can correctly explain the nuisance behavior.
                    is_grayware = "[grayware]" in _pat
                    if risk_score > 30:
                        risk_score = 30
                    else:
                        risk_score = max(0, risk_score - 15)
                        if is_grayware and risk_score < 10:
                            risk_score = 10
        finally:
            try:
                _signal.alarm(0)
            except (AttributeError, OSError):
                pass
    except TimeoutError:
        logger.warning("Upload scan - VirusTotal timed out after 8 s")
        vt_result = {"error": "timeout", "positives": 0, "engine_count": 0, "method": "timeout", "scans": {}}
    except Exception as exc:
        logger.warning("Upload scan - VirusTotal error: %s", exc)
        vt_result = {"error": str(exc), "positives": 0, "engine_count": 0, "method": "error", "scans": {}}

    # ── Final threat classification — done BEFORE AI so AI gets the correct final score
    detection_details = (scan_res.get("suspicious_functions", []) + scan_res.get("heuristics", []))
    if vt_result.get("positives", 0):
        detection_details.append(f"VirusTotal: {vt_result['positives']}/{vt_result.get('engine_count',0)} engines")
    threat_level, status = determine_threat_level(risk_score, detection_details, scan_res.get("pattern_result", ""))

    # ── Engine 3: AI analysis — AFTER VT override so risk_score is the final adjusted value ──
    ai_result = {}
    ai_content_snip = _get_safe_ai_content_snippet(filename, file_bytes)
    try:
        try:
            _signal.signal(_signal.SIGALRM, lambda s, f: (_ for _ in ()).throw(TimeoutError("AI timeout")))
            _signal.alarm(8)
        except (AttributeError, OSError, NameError):
            pass
        try:
            ai_result = analyze_file_ai(
                entropy=scan_res.get("entropy", 0),
                patterns=scan_res.get("pattern_result", "None"),
                imports=scan_res.get("risky_imports_str", "None"),
                risk_score=risk_score,  # Uses VT-adjusted final score
                file_content=ai_content_snip,
                filename=filename,
                is_eicar=scan_res.get("is_eicar", False),
            )
        finally:
            try:
                _signal.alarm(0)
            except (AttributeError, OSError, NameError):
                pass
    except TimeoutError:
        logger.warning("Upload scan - AI analysis timed out after 8 s")
        ai_result = {"error": "timeout", "verdict": "UNKNOWN"}
    except Exception as exc:
        logger.warning("Upload scan - AI analysis error: %s", exc)
        ai_result = {"error": str(exc)}

    file_record = {
        "id": file_id,
        "filename": filename,
        "folder_name": folder_name,
        "source_location": source_location,
        "filepath": path,
        "relative_path": relative_path,
        "upload_time": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "hash": file_hash,
        "user_id": current_user.uid,
        "user_email": getattr(current_user, "email", ""),
        "username": getattr(current_user, "username", getattr(current_user, "email", "").split("@")[0]),
        "size": f"{round(len(file_bytes) / 1024, 2)} KB",
        "virustotal": vt_result,
        "ai_analysis": ai_result,
        "explanation": _extract_ai_text(ai_result) or f"Scan completed. Risk score: {risk_score}%"
    }
    _apply_scan_result_to_file(file_record, scan_res)
    fb.save_uploaded_file(file_record)
    _cache_bytes(file_id, file_bytes)

    return jsonify({"success": True, "file_id": file_id, "filename": filename, "status": status, "risk_score": risk_score, "threat_level": threat_level}), 200



# ── API: Client-Side SHA-256 Hash Scan (Instant Scan for Large Files / 1GB+ Folders) ──
@app.route("/api/scan_hash", methods=["POST"])
@csrf.exempt
def scan_hash_api():
    data = request.get_json(silent=True) or {}
    file_hash = data.get("hash", "").strip().lower()
    filename = data.get("filename", "scanned_file.bin").strip()
    folder_name = data.get("folder_name")
    file_size_str = data.get("size", "Large File (>4.5 MB)")

    if not file_hash or len(file_hash) != 64:
        return jsonify({"error": "Invalid SHA-256 hash"}), 400

    ext = os.path.splitext(filename)[1].lower()

    # 1. VirusTotal Hash Lookup
    vt_result = {}
    risk_score = 0
    try:
        vt_raw = smart_virustotal_scan(None, file_hash)
        if vt_raw and "scans" not in vt_raw:
            vt_raw["scans"] = {}
        vt_result = vt_raw or {}
        vt_pos = vt_result.get("positives", 0)
        vt_total = vt_result.get("engine_count", 0)
        if vt_pos >= 5:
            risk_score = min(98, 80 + (vt_pos * 2))  # Confirmed malware outbreak -> 90-98% Critical
        elif vt_pos >= 2:
            risk_score = 55 + (vt_pos * 5)           # Multiple detections -> 65-75% High
        elif vt_pos == 1:
            risk_score = 35                           # Single detection -> 35% Medium
        else:
            risk_score = 0                            # Clean -> 0% Benign
    except Exception as exc:
        logger.warning("Hash scan - VirusTotal error: %s", exc)
        vt_result = {"error": str(exc), "positives": 0, "engine_count": 0, "method": "hash_error", "scans": {}}

    # 2. AI Threat Analysis
    ai_result = {}
    try:
        ai_result = analyze_file_ai(
            entropy=7.5 if ext in {".zip", ".rar", ".7z", ".exe"} else 4.0,
            patterns=f"Hash lookup for {filename}",
            imports="None",
            risk_score=risk_score,
            filename=filename,
        )
    except Exception as exc:
        logger.warning("Hash scan - AI analysis error: %s", exc)
        ai_result = {"error": str(exc)}

    # 3. Determine Threat Level
    detection_details = []
    if vt_result.get("positives", 0):
        detection_details.append(f"VirusTotal: {vt_result['positives']}/{vt_result.get('engine_count', 0)} engines")
    threat_level, status = determine_threat_level(risk_score, detection_details)

    file_id = str(uuid.uuid4())
    file_record = {
        "id": file_id,
        "filename": filename,
        "folder_name": folder_name,
        "source_location": f"Scanned Folder / {folder_name} / {filename}" if folder_name else f"Uploaded File / {filename}",
        "filepath": f"/tmp/{filename}",
        "relative_path": filename,
        "upload_time": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "hash": file_hash,
        "size": file_size_str,
        "virustotal": vt_result,
        "ai_analysis": ai_result,
        "explanation": _extract_ai_text(ai_result) or f"Instant SHA-256 Hash Scan completed. Risk score: {risk_score}%"
    }

    if current_user and current_user.is_authenticated:
        file_record["user_id"] = current_user.uid
        file_record["user_email"] = getattr(current_user, "email", "")
        file_record["username"] = getattr(current_user, "username", getattr(current_user, "email", "").split("@")[0])
        fb.save_uploaded_file(file_record)
    else:
        guest_id = session.get("guest_id") or str(uuid.uuid4())
        session["guest_id"] = guest_id
        guest_scans = session.get("guest_scans", [])
        guest_scans.append(file_record)
        session["guest_scans"] = guest_scans

    return jsonify({
        "success": True,
        "file_id": file_id,
        "filename": filename,
        "status": status,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "hash": file_hash,
        "method": "sha256_hash_scan"
    }), 200


# ── Guest Quick Scan (No Login Required — Temporary Session Only) ───────────
@app.route("/guest_scan", methods=["GET"])
@app.route("/guest-scan", methods=["GET"])
def guest_scan_page():
    guest_id = session.get("guest_id")
    if not guest_id:
        guest_id = str(uuid.uuid4())
        session["guest_id"] = guest_id
    guest_scans = GUEST_SESSIONS.get(guest_id, [])
    return render_template("guest_scan.html", files=guest_scans)


@app.route("/api/guest_upload", methods=["POST"])
@csrf.exempt
def guest_upload_api():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "No file provided"}), 400

    raw_filename = os.path.basename(f.filename)
    filename = secure_filename(raw_filename) or f"file_{uuid.uuid4().hex[:8]}"
    ext = os.path.splitext(filename)[1].lower()

    file_bytes = f.read()
    if not file_bytes:
        return jsonify({"skipped": True, "reason": "Empty file"}), 200

    file_hash = hashlib.sha256(file_bytes).hexdigest()

    # ── Engine 1: Full heuristic scan (same as logged-in users) ──────────────
    scan_res = _run_full_heuristic_scan(filename, file_bytes, file_hash)
    risk_score = scan_res.get("risk_score", 0)

    # ── Engine 2: VirusTotal (hash lookup first, then file upload) ────────────
    vt_result = {}
    try:
        temp_dir = os.path.join(app.config.get("UPLOAD_FOLDER", "/tmp/uploads"), "guest_scans")
        os.makedirs(temp_dir, exist_ok=True)
        temp_path = os.path.abspath(os.path.join(temp_dir, f"{uuid.uuid4().hex}_{filename}"))
        with open(temp_path, "wb") as out:
            out.write(file_bytes)
    except OSError:
        temp_dir = os.path.join("/tmp/uploads", "guest_scans")
        os.makedirs(temp_dir, exist_ok=True)
        temp_path = os.path.abspath(os.path.join(temp_dir, f"{uuid.uuid4().hex}_{filename}"))
        try:
            with open(temp_path, "wb") as out:
                out.write(file_bytes)
        except Exception:
            temp_path = None

    try:
        vt_raw = smart_virustotal_scan(temp_path, file_hash) if temp_path else {"positives": 0, "engine_count": 0, "scans": {}}
        if vt_raw and "scans" not in vt_raw:
            vt_raw["scans"] = {}
        vt_result = vt_raw or {}
        vt_pos   = vt_result.get("positives", 0)
        vt_total = vt_result.get("engine_count", 0)
        if vt_total and vt_pos:
            risk_score = max(risk_score, int((vt_pos / vt_total) * 100))
        elif (vt_total >= 20 or len(vt_result.get("scans", {})) >= 20) and vt_pos == 0:
            _pat = str(scan_res.get("pattern_result", "")).lower()
            _heur = str(scan_res.get("heuristics", [])).lower()
            has_active_threat = any(k in _pat or k in _heur for k in [
                "persistence mechanism", "invoke-expression", "obfuscated loader", "obfuscated execution",
                "amsi bypass", "uac bypass", "shadow copy deletion", "php shell execution", "powershell download"
            ])
            if not has_active_threat:
                # When VirusTotal reports 0 detections across 20+ engines,
                # cap internal heuristic risk score at maximum of LOW (30%).
                # BUT: grayware scores must keep a minimum floor of 10.
                is_grayware = "[grayware]" in _pat
                if risk_score > 30:
                    risk_score = 30
                else:
                    risk_score = max(0, risk_score - 15)
                    if is_grayware and risk_score < 10:
                        risk_score = 10
    except Exception as exc:
        logger.warning("Guest scan - VirusTotal error: %s", exc)
        vt_result = {"error": str(exc), "positives": 0, "engine_count": 0, "method": "error", "scans": {}}
    finally:
        try:
            os.remove(temp_path)
        except Exception:
            pass

    # ── Engine 3: AI analysis ─────────────────────────────────────────────────
    ai_result = {}
    guest_content_snip = _get_safe_ai_content_snippet(filename, file_bytes)
    try:
        ai_result = analyze_file_ai(
            entropy=scan_res.get("entropy", 0),
            patterns=scan_res.get("pattern_result", "None"),
            imports=scan_res.get("risky_imports_str", "None"),
            risk_score=risk_score,
            file_content=guest_content_snip,
            filename=filename,
            is_eicar=scan_res.get("is_eicar", False),
        )
    except Exception as exc:
        logger.warning("Guest scan - AI analysis error: %s", exc)
        ai_result = {"error": str(exc)}

    # ── Final threat classification ───────────────────────────────────────────
    detection_details = (scan_res.get("suspicious_functions", []) + scan_res.get("heuristics", []))
    if vt_result.get("positives", 0):
        detection_details.append(f"VirusTotal: {vt_result['positives']}/{vt_result.get('engine_count',0)} engines")
    threat_level, status = determine_threat_level(risk_score, detection_details, scan_res.get("pattern_result", ""))

    file_id = str(uuid.uuid4())
    guest_record = {
        "id": file_id,
        "filename": filename,
        "folder_name": request.form.get("folder_name"),
        "upload_time": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "hash": file_hash,
        "size": f"{round(len(file_bytes) / 1024, 2)} KB",
        "virustotal": vt_result,
        "ai_analysis": ai_result,
        "explanation": _extract_ai_text(ai_result) or f"Guest Scan. Risk score: {risk_score}%"
    }
    _apply_scan_result_to_file(guest_record, scan_res)

    guest_id = session.get("guest_id")
    if not guest_id:
        guest_id = str(uuid.uuid4())
        session["guest_id"] = guest_id

    if guest_id not in GUEST_SESSIONS:
        GUEST_SESSIONS[guest_id] = []
    GUEST_SESSIONS[guest_id].append(guest_record)

    session.modified = True

    return jsonify({"success": True, "file": guest_record}), 200

@app.route("/api/clear_guest_history", methods=["POST"])
@csrf.exempt
def clear_guest_history():
    guest_id = session.get("guest_id")
    if guest_id and guest_id in GUEST_SESSIONS:
        del GUEST_SESSIONS[guest_id]
    return jsonify({"status": "cleared"})

@app.route("/upload", methods=["GET", "POST"])
@login_required
def uploadfiles():
    if request.method == "POST":
        uploaded_files = request.files.getlist("files") or request.files.getlist("file")
        # Filter out empty entries
        valid_files = [f for f in uploaded_files if f and f.filename]
        
        if not valid_files:
            flash("No files selected.", "warning")
            return redirect(request.url)

        allowed = ALLOWED_SCAN_EXTENSIONS

        saved_count = 0
        duplicate_count = 0
        last_file_id = None

        existing_files = fb.list_user_files(current_user.uid)
        existing_hashes = {f.get("hash") for f in existing_files if f.get("hash")}
        existing_names = {f.get("filename") for f in existing_files if f.get("filename")}

        user_folder = os.path.join(app.config["UPLOAD_FOLDER"], str(current_user.uid))
        os.makedirs(user_folder, exist_ok=True)

        for f in valid_files:
            raw_filename = os.path.basename(f.filename)
            filename = secure_filename(raw_filename) or f"file_{uuid.uuid4().hex[:8]}"
            ext = os.path.splitext(filename)[1].lower()

            file_bytes = f.read()
            if not file_bytes:
                continue

            file_hash = hashlib.sha256(file_bytes).hexdigest()

            # Duplicate check: hash-only match (most reliable fingerprint)
            if file_hash in existing_hashes:
                # Redirect to the existing scan result instead of dead-end message
                existing_match = next(
                    (ef for ef in existing_files if ef.get("hash") == file_hash and ef.get("id")),
                    None
                )
                if existing_match and not last_file_id:
                    last_file_id = existing_match.get("id")
                duplicate_count += 1
                continue

            path = os.path.abspath(os.path.join(user_folder, filename))
            if len(path) > 255:
                filename = uuid.uuid4().hex + ext
                path = os.path.abspath(os.path.join(user_folder, filename))

            try:
                with open(path, "wb") as out:
                    out.write(file_bytes)
            except OSError:
                fallback_dir = os.path.join("/tmp/uploads", str(current_user.uid))
                os.makedirs(fallback_dir, exist_ok=True)
                path = os.path.join(fallback_dir, filename)
                with open(path, "wb") as out:
                    out.write(file_bytes)

            relative_path = os.path.join(str(current_user.uid), filename)
            file_id = str(uuid.uuid4())
            file_record = {
                "id": file_id,
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
            _cache_bytes(file_id, file_bytes)
            saved_count += 1
            last_file_id = file_id

            # Add to tracking sets for batch
            existing_hashes.add(file_hash)
            existing_names.add(filename)

        if saved_count == 0:
            if duplicate_count > 0 and last_file_id:
                # Redirect directly to the existing scan result
                flash("This file was already scanned. Showing existing results.", "info")
                return redirect(url_for("scan_page", file_id=last_file_id))
            elif duplicate_count > 0:
                flash("Selected files were already uploaded. Please check your dashboard.", "warning")
            else:
                flash("No valid files could be processed.", "warning")
            return redirect(url_for("dashboard"))

        if saved_count == 1 and last_file_id:
            flash("File uploaded successfully. Starting scan...", "success")
            return redirect(url_for("scan_page", file_id=last_file_id, auto_scan="true"))
        else:
            flash(f"Successfully queued {saved_count} file(s) for threat analysis.", "success")
            return redirect(url_for("dashboard"))

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
                    return jsonify({"status": "deleted", "message": "File deleted successfully"})
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

    return jsonify({"status": "deleted", "message": "File deleted successfully"})

# ── Re-scan route — clears old cached result and forces a fresh scan ──────────
@app.route("/rescan/<file_id>", methods=["POST"], endpoint="rescan_page")
@login_required
def rescan(file_id):
    """Reset a previously scanned file back to Pending so it gets re-scanned
    with the latest detection engine logic."""
    file_meta = fb.get_uploaded_file(str(file_id))
    if not file_meta or file_meta.get("user_id") != current_user.uid:
        flash("File not found.", "danger")
        return redirect(url_for("dashboard"))

    # Clear all old scan fields and reset to Pending
    fields_to_clear = [
        "status", "threat_level", "risk_score", "pattern_result",
        "signature_status", "risky_imports", "entropy", "hash",
        "ai_analysis", "virustotal", "advanced_heuristics",
        "detected_type", "confidence", "iocs", "explanation",
    ]
    for field in fields_to_clear:
        file_meta.pop(field, None)

    file_meta["status"] = "Pending"
    fb.save_uploaded_file(file_meta)

    flash("File reset — running a fresh scan now.", "info")
    return redirect(url_for("scan_page", file_id=file_id, auto_scan="true"))


# ── Scan page ─────────────────────────────────────────────────────────────────
@app.route("/scan/<file_id>", methods=["GET", "POST"], endpoint="scan_page")
@login_required
def scan(file_id):
    file_meta = fb.get_uploaded_file(str(file_id))
    if not file_meta or file_meta.get("user_id") != current_user.uid:
        flash("File not found.")
        return redirect(url_for("dashboard"))

    # Dynamically synchronize with VirusTotal cache / consensus override
    if _sync_file_with_vt_consensus(file_meta):
        try:
            fb.save_uploaded_file(file_meta)
        except Exception:
            pass

    already_scanned = file_meta.get("status") != "Pending"
    auto_scan = request.args.get("auto_scan", "false")
    is_rescan = request.args.get("rescan", "false").lower() == "true" or request.form.get("rescan") == "true"

    if request.method == "POST" or (auto_scan.lower() == "true" and not already_scanned) or is_rescan:
        # ── Run the full scan / rescan inline with updated engines ───────────
        if not scan_semaphore.acquire(blocking=False):
            flash("System is busy. Please try again in a moment.", "warning")
            return redirect(url_for("dashboard"))

        try:
            file_exists   = os.path.isfile(file_meta.get("filepath", ""))
            cached_bytes  = _get_bytes(file_meta["id"])
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

            # Heuristic scan — always runs on available bytes to apply updated rules
            if file_bytes:
                offline_cache = _run_full_heuristic_scan(
                    file_meta.get("filename"), file_bytes, file_hash
                )

            elif file_meta.get("status") and file_meta.get("status") != "Pending":
                logger.info("scan: file %s already scanned during upload (status: %s), preserving scan result", file_meta.get("filename"), file_meta.get("status"))
                if request.method == "POST":
                    return jsonify({"success": True, "file": file_meta, "already_scanned": True}), 200
                # Ensure threat_level and explanation are strictly synchronized with risk_score
                file_meta["threat_level"], file_meta["status"] = determine_threat_level(
                    file_meta.get("risk_score", 0), []
                )
                file_meta["explanation"] = generate_explanation(file_meta)

                # Build AI analysis if missing
                _ai_data = file_meta.get("ai_analysis")
                if not _ai_data or (isinstance(_ai_data, dict) and _ai_data.get("risk_score", 0) != file_meta.get("risk_score", 0)):
                    _ai_data = analyze_file_ai(
                        entropy=file_meta.get("entropy", 0),
                        patterns=file_meta.get("pattern_result", "None"),
                        imports=file_meta.get("risky_imports", "None"),
                        risk_score=file_meta.get("risk_score", 0),
                        filename=file_meta.get("filename", ""),
                    )
                    file_meta["ai_analysis"] = _ai_data
                _results = {
                    "heuristic": {
                        "risk_score": file_meta.get("risk_score", 0),
                        "entropy": file_meta.get("entropy", "0"),
                        "heuristics": [file_meta.get("pattern_result", "None")],
                        "suspicious_functions": [file_meta.get("signature_status", "None")],
                        "risky_imports": [file_meta.get("risky_imports", "None")],
                    },
                    "virustotal": file_meta.get("virustotal", {}),
                    "ai_analysis": _ai_data,
                }
                return render_template(
                    "scan.html",
                    file=file_meta,
                    result=True,
                    already_scanned=True,
                    results=_results,
                    scan_mode='multiple',
                    ai_text=_extract_ai_text(_ai_data),
                    ai_verdict=_extract_ai_verdict(_ai_data),
                    ai_confidence=_extract_ai_confidence(_ai_data),
                    css_version=int(time.time()),
                )
            else:
                offline_cache = {
                    "hash": file_hash, "entropy": file_meta.get("entropy", 0.0),
                    "heuristics": file_meta.get("heuristics") or ["File payload expired from temporary server cache"],
                    "suspicious_functions": file_meta.get("suspicious_functions") or [],
                    "risky_imports": file_meta.get("risky_imports_list") or [],
                    "risk_score": file_meta.get("risk_score", 0),
                    "pattern_result": file_meta.get("pattern_result", "No suspicious patterns"),
                    "signature_status": file_meta.get("signature_status", "No signatures detected"),
                    "risky_imports_str": file_meta.get("risky_imports", "None"),
                    "all_detections": file_meta.get("all_detections", []),
                    "advanced": file_meta.get("advanced_heuristics", {}),
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

            # Final risk calculation with VirusTotal consensus override
            final_risk        = offline_cache.get("risk_score", 0)
            detection_details = (offline_cache.get("suspicious_functions", []) +
                                 offline_cache.get("heuristics", []))

            vt = results.get("virustotal", {})
            if isinstance(vt, dict) and "error" not in vt:
                total = vt.get("engine_count", 0)
                pos   = vt.get("positives", 0)
                if total and pos:
                    final_risk = max(final_risk, int((pos / total) * 100))
                elif total >= 20 and pos == 0:
                    # Global Industry Consensus Hard Override
                    has_active_threat = any(k in str(offline_cache.get("pattern_result", "")).lower() or k in str(offline_cache.get("heuristics", "")).lower() for k in [
                        "persistence mechanism", "invoke-expression", "obfuscated loader", "obfuscated execution",
                        "amsi bypass", "uac bypass", "shadow copy deletion", "php shell execution", "powershell download"
                    ])
                    if not has_active_threat:
                        is_grayware = "[grayware]" in str(offline_cache.get("pattern_result", "")).lower()
                        if final_risk > 30:
                            final_risk = 30
                        else:
                            final_risk = max(0, final_risk - 15)
                            if is_grayware and final_risk < 10:
                                final_risk = 10
                if pos:
                    detection_details.append(
                        f"VirusTotal: {pos}/{total} engines detected threat"
                    )

            file_meta["risk_score"]   = min(final_risk, 100)
            file_meta["threat_level"], file_meta["status"] = determine_threat_level(
                final_risk, detection_details, offline_cache.get("pattern_result", "")
            )

            # AI analysis — called AFTER final_risk is computed so AI gets the exact final score
            results["ai_analysis"] = analyze_file_ai(
                entropy=offline_cache.get("entropy", 0),
                patterns=offline_cache.get("pattern_result", "None"),
                imports=offline_cache.get("risky_imports_str", "None"),
                risk_score=file_meta["risk_score"],
                file_content=_get_safe_ai_content_snippet(file_meta.get("filename", ""), file_bytes or b""),
                filename=file_meta.get("filename", ""),
                is_eicar=file_meta.get("is_eicar", offline_cache.get("is_eicar", False)),
            )
            file_meta["ai_analysis"] = results["ai_analysis"]
            file_meta["explanation"] = generate_explanation(file_meta)


            # Always save the file record — manual delete from dashboard
            fb.save_uploaded_file(file_meta)

            _ai = results.get("ai_analysis") or {}
            return render_template(
                "scan.html",
                file=file_meta,
                result=True,
                already_scanned=False,
                results=results,
                scan_mode='multiple',
                ai_text=_extract_ai_text(_ai),
                ai_verdict=_extract_ai_verdict(_ai),
                ai_confidence=_extract_ai_confidence(_ai),
            )


        finally:
            scan_semaphore.release()

    if already_scanned:
        # Dynamically re-evaluate against latest heuristic rules on page refresh if file is present
        try:
            file_exists  = os.path.isfile(file_meta.get("filepath", ""))
            cached_bytes = _get_bytes(file_meta["id"])
            file_bytes   = None
            if file_exists:
                try:
                    with safe_open(file_meta["filepath"], "rb") as fh:
                        file_bytes = fh.read()
                except Exception:
                    file_bytes = None
            if not file_bytes:
                file_bytes = cached_bytes

            if file_bytes:
                fresh_scan = _run_full_heuristic_scan(file_meta.get("filename"), file_bytes, file_meta.get("hash", ""))
                fresh_risk = fresh_scan.get("risk_score", 0)

                # Sync with VirusTotal override
                vt = file_meta.get("virustotal", {})
                if isinstance(vt, dict):
                    pos = vt.get("positives", 0)
                    total = vt.get("engine_count", 0)
                    if total and pos:
                        fresh_risk = max(fresh_risk, int((pos / total) * 100))
                    elif total >= 20 and pos == 0:
                        is_grayware = "[grayware]" in str(fresh_scan.get("pattern_result", "")).lower()
                        if fresh_risk > 40:
                            fresh_risk = 40
                        else:
                            fresh_risk = max(0, fresh_risk - 15)
                            if is_grayware and fresh_risk < 10:
                                fresh_risk = 10

                _apply_scan_result_to_file(file_meta, fresh_scan)
                file_meta["risk_score"] = min(fresh_risk, 100)
                file_meta["threat_level"], file_meta["status"] = determine_threat_level(
                    fresh_risk, fresh_scan.get("suspicious_functions", []) + fresh_scan.get("heuristics", []),
                    fresh_scan.get("pattern_result", "")
                )
                file_meta["explanation"] = generate_explanation(file_meta)
        except Exception as exc:
            logger.warning("Dynamic heuristic refresh on GET failed: %s", exc)

        ai_data = file_meta.get("ai_analysis")
        _cur_risk = int(file_meta.get("risk_score", 0))
        _ai_v = str(ai_data.get("verdict", "") if isinstance(ai_data, dict) else ai_data or "").upper()
        _ai_txt = str(_extract_ai_text(ai_data)).upper() if ai_data else ""
        
        _is_gw = "[grayware]" in str(file_meta.get("pattern_result", "")).lower() or "[grayware]" in str(file_meta.get("signature_status", "")).lower()
        _gw_mismatch = _is_gw and "NUISANCE" not in _ai_txt

        _is_eicar_file = "EICAR" in str(file_meta.get("pattern_result", "")).upper() or file_meta.get("is_eicar", False) or "AV TEST SIGNATURE" in str(file_meta.get("pattern_result", "")).upper()
        _eicar_needs_expansion = _is_eicar_file and "WHAT IS EICAR?" not in _ai_txt

        import re as _re_sc
        _sc_match = _re_sc.search(r"THREAT SCORE:\s*(\d+)/100", _ai_txt)
        _sc_mismatch = _sc_match and int(_sc_match.group(1)) != _cur_risk

        _ai_contradicts = (
            (_cur_risk < 56 and any(w in _ai_v for w in ["CRITICAL", "HIGH RISK", "HIGHLY MALICIOUS"]))
            or (_cur_risk < 56 and ("[CRITICAL RISK]" in _ai_txt or "HIGHLY MALICIOUS" in _ai_txt))
            or _gw_mismatch
            or _sc_mismatch
        )
        _is_generic_placeholder = (
            "SCAN COMPLETED." in _ai_txt
            or "INSTANT SHA-256 HASH SCAN COMPLETED" in _ai_txt
            or len(_ai_txt.strip()) < 45
        )
        _needs_refresh = (
            not ai_data
            or (isinstance(ai_data, dict) and not ai_data)
            or (isinstance(ai_data, str) and not ai_data.strip())
            or _ai_contradicts
            or _is_generic_placeholder
            or _eicar_needs_expansion
            or request.args.get("refresh") == "1"
        )
        if file_bytes or _needs_refresh:
            ai_data = analyze_file_ai(
                entropy=file_meta.get("entropy", 0),
                patterns=file_meta.get("pattern_result", "None"),
                imports=file_meta.get("risky_imports", "None"),
                risk_score=_cur_risk,
                file_content=_get_safe_ai_content_snippet(file_meta.get("filename", ""), file_bytes or b""),
                filename=file_meta.get("filename", ""),
                is_eicar=_is_eicar_file,
            )
            file_meta["ai_analysis"] = ai_data
            file_meta["explanation"] = _extract_ai_text(ai_data)
            try:
                fb.save_uploaded_file(file_meta)
            except Exception as exc:
                logger.warning("Could not update file_meta in Firebase: %s", exc)


        results = {
            "heuristic": {
                "risk_score": file_meta.get("risk_score", 0),
                "entropy": file_meta.get("entropy", "0"),
                "heuristics": [file_meta.get("pattern_result", "None")],
                "suspicious_functions": [file_meta.get("signature_status", "None")],
                "risky_imports": [file_meta.get("risky_imports", "None")],
            },
            "virustotal": file_meta.get("virustotal", {}),
            "ai_analysis": ai_data
        }
        return render_template("scan.html", file=file_meta, result=True,
                               already_scanned=True, results=results, scan_mode='multiple',
                               ai_text=_extract_ai_text(ai_data),
                               ai_verdict=_extract_ai_verdict(ai_data),
                               ai_confidence=_extract_ai_confidence(ai_data))


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

        cached_bytes: bytes | None = _get_bytes(file_meta["id"])

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
                            "heuristics":           file_meta.get("heuristics") or [
                                "File payload expired from temporary server cache"
                            ],
                            "suspicious_functions": file_meta.get("suspicious_functions") or [],
                            "risky_imports":        file_meta.get("risky_imports_list") or [],
                            "risk_score":           file_meta.get("risk_score", 0),
                            "pattern_result":       file_meta.get("pattern_result", "No suspicious patterns"),
                            "signature_status":     file_meta.get("signature_status", "No signatures detected"),
                            "risky_imports_str":    file_meta.get("risky_imports", "None"),
                            "all_detections":       file_meta.get("all_detections", []),
                            "advanced":             file_meta.get("advanced_heuristics", {}),
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
                    if total and pos:
                        final_risk = max(final_risk, int((pos / total) * 100))
                    elif total >= 20 and pos == 0:
                        # Global Industry Consensus Hard Override
                        is_grayware = "[grayware]" in str(results.get("heuristic", {}).get("pattern_result", "")).lower()
                        if final_risk > 40:
                            final_risk = 40
                        else:
                            final_risk = max(0, final_risk - 15)
                            if is_grayware and final_risk < 10:
                                final_risk = 10
                    if pos:
                        detection_details.append(
                            f"VirusTotal: {pos}/{total} engines detected threat"
                        )

            if "ai_analysis" in [st.strip() for st in scan_types_param.split(",")]:
                if offline_cache is None:
                    offline_cache = results.get("heuristic", {})
                patterns = offline_cache.get("pattern_result", "None")
                imports  = offline_cache.get("risky_imports_str", "None")
                results["ai_analysis"] = analyze_file_ai(
                    entropy=offline_cache.get("entropy", 0),
                    patterns=patterns,
                    imports=imports,
                    risk_score=final_risk,
                    file_content=_get_safe_ai_content_snippet(file_meta.get("filename", ""), file_bytes or b""),
                    filename=file_meta.get("filename", ""),
                )
                file_meta["ai_analysis"] = results["ai_analysis"]

            file_meta["risk_score"] = min(final_risk, 100)
            file_meta["threat_level"], file_meta["status"] = determine_threat_level(
                final_risk, detection_details, str(results.get("heuristic", {}).get("pattern_result", ""))
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

                        # Skip if physical file no longer exists or deduplicate
                        if (path_str and not os.path.exists(path_str)) or path_str in seen_paths or (file_hash and file_hash in seen_hashes):
                            continue

                        h = hashlib.sha256(f"{path_str}{time_str}".encode("utf-8")).hexdigest()
                        
                        _score = entry.get("risk_score", 0) or 0
                        _tl, _st = determine_threat_level(_score, [])
                        local_entry = {
                            "id": f"local_{h}",
                            "filename": os.path.basename(path_str),
                            "filepath": path_str,
                            "upload_time": time_str,
                            "status": entry.get("status", _st),
                            "threat_level": entry.get("threat_level", _tl),
                            "risk_score": _score,
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
                                    _score = entry.get("risk_score", 0) or 0
                                    _tl, _st = determine_threat_level(_score, [])
                                    local_meta = {
                                        "id": f"local_{h}",
                                        "filename": os.path.basename(path_str),
                                        "filepath": path_str,
                                        "upload_time": time_str,
                                        "status": entry.get("status", _st),
                                        "threat_level": entry.get("threat_level", _tl),
                                        "risk_score": _score,
                                        "entropy": entry.get("entropy", 0.0),
                                        "hash": entry.get("hash", ""),
                                        "pattern_result": ", ".join(entry.get("patterns", [])[:3]) if isinstance(entry.get("patterns"), list) else entry.get("pattern_result", ""),
                                        "signature_status": ", ".join(entry.get("heuristics", [])[:3]) if isinstance(entry.get("heuristics"), list) else entry.get("signature_status", ""),
                                        "ai_analysis": entry.get("ai_analysis", ""),
                                        "user_id": current_user.uid
                                    }
                                    loc_ai = local_meta.get("ai_analysis")
                                    loc_results = {
                                        "heuristic": {
                                            "risk_score": local_meta.get("risk_score", 0),
                                            "entropy": local_meta.get("entropy", "0"),
                                            "heuristics": [local_meta.get("pattern_result", "None")],
                                            "suspicious_functions": [local_meta.get("signature_status", "None")],
                                            "risky_imports": ["None"],
                                        },
                                        "virustotal": {},
                                        "ai_analysis": loc_ai
                                    }
                                    return render_template("scan.html", file=local_meta, result=True,
                                                           results=loc_results, scan_mode='multiple',
                                                           ai_text=_extract_ai_text(loc_ai),
                                                           ai_verdict=_extract_ai_verdict(loc_ai),
                                                           ai_confidence=_extract_ai_confidence(loc_ai))
                except Exception as e:
                    logger.error("Error reading TrustFile_Detections.json in view_result: %s", e)
        
        flash("File not found or access denied.")
        return redirect(url_for("dashboard"))
    ai_data = file_meta.get("ai_analysis")
    current_risk = int(file_meta.get("risk_score", 0))
    ai_verdict_str = str(ai_data.get("verdict", "") if isinstance(ai_data, dict) else ai_data or "").upper()

    # Detect contradicted verdicts: AI says CRITICAL/HIGH but score is Medium/Low, or vice-versa
    ai_contradicts_engine = (
        (current_risk < 56 and any(w in ai_verdict_str for w in ["CRITICAL", "HIGH RISK", "HIGHLY MALICIOUS"]))
        or (current_risk >= 81 and any(w in ai_verdict_str for w in ["LOW", "BENIGN", "CLEAN"]))
    )
    # Also detect if the explanation text itself was wrongly escalated
    ai_text_str = str(_extract_ai_text(ai_data)).upper() if ai_data else ""
    ai_text_contradicts = (
        current_risk < 56 and (
            "95/100" in ai_text_str or "90/100" in ai_text_str
            or ("[CRITICAL RISK]" in ai_text_str and current_risk < 81)
            or ("HIGHLY MALICIOUS" in ai_text_str and current_risk < 81)
        )
    )

    needs_ai_refresh = (
        not ai_data
        or (isinstance(ai_data, dict) and not ai_data)
        or (isinstance(ai_data, str) and not ai_data.strip())
        or ai_contradicts_engine
        or ai_text_contradicts
    )

    if needs_ai_refresh:
        ai_data = analyze_file_ai(
            entropy=file_meta.get("entropy", 0),
            patterns=file_meta.get("pattern_result", "None"),
            imports=file_meta.get("risky_imports", "None"),
            risk_score=current_risk,
            filename=file_meta.get("filename", ""),
        )
        file_meta["ai_analysis"] = ai_data
        file_meta["explanation"] = _extract_ai_text(ai_data)
        # Save corrected analysis back to Firebase so it's fixed permanently
        try:
            fb.save_uploaded_file(file_meta)
        except Exception as exc:
            logger.warning("view_result: could not update stale AI analysis in Firebase: %s", exc)

    results = {
        "heuristic": {
            "risk_score": file_meta.get("risk_score", 0),
            "entropy": file_meta.get("entropy", "0"),
            "heuristics": [file_meta.get("pattern_result", "None")],
            "suspicious_functions": [file_meta.get("signature_status", "None")],
            "risky_imports": [file_meta.get("risky_imports", "None")],
        },
        "virustotal": file_meta.get("virustotal", {}),
        "ai_analysis": ai_data
    }
    return render_template("scan.html", file=file_meta, result=True, results=results, scan_mode='multiple',
                           ai_text=_extract_ai_text(ai_data),
                           ai_verdict=_extract_ai_verdict(ai_data),
                           ai_confidence=_extract_ai_confidence(ai_data))



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
                    flash("File and scan record deleted successfully.")
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

        # Delete the physical file from the server
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
            flash(f"File and {deleted_count} duplicate record(s) deleted successfully.")
        else:
            flash("File and scan record deleted successfully.")
    else:
        flash("File not found or access denied.")
    return redirect(request.referrer or url_for("dashboard"))


# ── Delete folder ─────────────────────────────────────────────────────────────
@app.route("/delete_folder/<path:folder_name>", methods=["POST"], endpoint="delete_folder")
@login_required
def delete_folder(folder_name):
    from urllib.parse import unquote
    decoded_folder = unquote(folder_name).strip()
    user_files = fb.list_user_files(current_user.uid)
    deleted_count = 0
    for f in user_files:
        eff_folder = _get_effective_folder_name(f)
        raw_folder = f.get("folder_name")
        eff_dec = unquote(eff_folder or "").strip()
        raw_dec = unquote(raw_folder or "").strip()

        if decoded_folder in {eff_folder, raw_folder, eff_dec, raw_dec}:
            target_path = f.get("filepath")
            if target_path:
                _trash_file(target_path)
            fb.delete_uploaded_file(f["id"])
            deleted_count += 1

    # Also clean up local monitor detections matching this folder
    detections_file = os.path.join(os.path.expanduser("~"), "Desktop", "TrustFile_Detections.json")
    if os.path.exists(detections_file):
        try:
            with open(detections_file, "r", encoding="utf-8") as f:
                detections = json.load(f)
            updated = []
            for entry in detections:
                if isinstance(entry, dict):
                    p = entry.get("file_path", "") or entry.get("filepath", "") or ""
                    parts = p.replace("\\", "/").strip("/").split("/")
                    entry_folder = parts[-2] if len(parts) >= 2 else ""
                    raw_ent = entry.get("folder_name") or ""
                    if decoded_folder not in {entry_folder, raw_ent, unquote(entry_folder), unquote(raw_ent)}:
                        updated.append(entry)
            with open(detections_file, "w", encoding="utf-8") as f:
                json.dump(updated, f, indent=4)
        except Exception as e:
            logger.error("Error cleaning local detections for folder %s: %s", decoded_folder, e)

    if deleted_count > 0:
        flash(f"Folder '{decoded_folder}' and {deleted_count} file record(s) deleted successfully.")
    else:
        flash(f"No records found for folder '{decoded_folder}'.")
    return redirect(request.referrer or url_for("dashboard"))


# ── Delete guest item (file or folder) ────────────────────────────────────────
@app.route("/api/delete_guest_item", methods=["POST"])
def delete_guest_item_api():
    data = request.get_json(silent=True) or {}
    file_id = data.get("file_id")
    folder_name = data.get("folder_name")

    guest_id = session.get("guest_id")
    if not guest_id or guest_id not in GUEST_SESSIONS:
        return jsonify({"success": False, "message": "No active guest session"}), 404

    items = GUEST_SESSIONS[guest_id]
    if file_id:
        GUEST_SESSIONS[guest_id] = [e for e in items if str(e.get("id")) != str(file_id)]
    elif folder_name:
        GUEST_SESSIONS[guest_id] = [
            e for e in items 
            if e.get("folder_name") != folder_name and _get_effective_folder_name(e) != folder_name
        ]
    session.modified = True
    return jsonify({"success": True})


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
        _rep_score = scan_result.get("risk_score", 0) or 0
        _rep_tl, _rep_st = determine_threat_level(_rep_score, [])
        file_record = {
            "id": str(uuid.uuid4()),
            "filename": filename,
            "filepath": filepath,
            "upload_time": datetime.now(timezone.utc).isoformat(),
            "status": scan_result.get("status", _rep_st),
            "threat_level": scan_result.get("threat_level", _rep_tl),
            "risk_score": _rep_score,
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
                
        # Compute final risk score after VT override FIRST
        final_risk = heuristic_res.get("risk_score", 0)
        detection_details = heuristic_res.get("suspicious_functions", []) + heuristic_res.get("heuristics", [])
        
        if vt_res and "error" not in vt_res:
            total = vt_res.get("engine_count", 0)
            pos = vt_res.get("positives", 0)
            if total and pos:
                final_risk = max(final_risk, int((pos / total) * 100))
            elif total >= 20 and pos == 0:
                # ── Global Industry Consensus Hard Override Rule ─────────────
                is_grayware = "[grayware]" in str(heuristic_res.get("pattern_result", "")).lower()
                if final_risk > 40:
                    final_risk = 40
                else:
                    final_risk = max(0, final_risk - 15)
                    if is_grayware and final_risk < 10:
                        final_risk = 10
            if pos:
                detection_details.append(f"VirusTotal: {pos}/{total} engines detected threat")
                
        final_risk = min(final_risk, 100)
        threat_level, status = determine_threat_level(final_risk, detection_details, heuristic_res.get("pattern_result", ""))

        # 3. AI Analysis — called AFTER VT override so it uses the correct final_risk
        patterns = heuristic_res.get("pattern_result", "None")
        imports = heuristic_res.get("risky_imports_str", "None")
        ai_content_snip = _get_safe_ai_content_snippet(filename, file_bytes)
        ai_res = analyze_file_ai(
            entropy=heuristic_res.get("entropy", 0.0),
            patterns=patterns,
            imports=imports,
            risk_score=final_risk,
            file_content=ai_content_snip,
            filename=filename,
            is_eicar=heuristic_res.get("is_eicar", False),
        )
        
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
            _r_score = scan.get("risk_score", 0) or 0
            _r_tl, _r_st = determine_threat_level(_r_score, [])
            recent_data.append({
                "id":           scan.get("id"),
                "timestamp":    scan.get("upload_time"),
                "filename":     scan.get("filename"),
                "threat_level": scan.get("threat_level", _r_tl),
                "risk_score":   _r_score,
                "status":       scan.get("status", _r_st),
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

