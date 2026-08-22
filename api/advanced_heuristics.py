"""
TrustFile – Advanced Heuristic Analysis Engine  (v3 — Context-Aware FP Guard)
==============================================================================
Full rewrite of the scoring, entropy, and Office-handling layers.

What changed from v2
─────────────────────
RULE 1  – Score-only-on-evidence
        Entropy alone can never push a file into Suspicious/High/Malicious.
        It contributes only when ≥1 corroborating indicator also fires.

RULE 2  – ZIP-container awareness
        .docx / .xlsx / .pptx / .apk / .jar are identified at the very start.
        Downstream stages skip or down-weight findings that are trivially
        explained by the container format.

RULE 3  – Contextual PowerShell detection (3-part gate)
        Token "iwr" alone = 0 points.
        Trigger only when download function + URL + execution keyword all
        appear within a 300-char window.

RULE 4  – Entropy co-indicator requirement
        high_entropy score weight is 0 unless one of:
          • embedded_executable, packed, obfuscated script,
            VBA macro, or suspicious API is also present.
        very_high_entropy gets a tiny base score (suspicious but not alone
        conclusive) and full score only with a co-indicator.

RULE 5  – Office XML structural validation
        Files whose ZIP contains the canonical Office entry set receive an
        explicit whitelist note and a -15 score adjustment.

RULE 6  – Confidence tiers (not just a gate)
        Confidence % is derived from the quality of evidence, not only
        from the raw score.  A 90-score file whose only indicator is
        entropy still gets LOW confidence.

RULE 7  – Enriched result display fields
        New keys: entropy_context, file_classification, risk_explanation,
        and a human-readable final_verdict string used directly by the
        Jinja template.

RULE 8  – Context-window string validation
        Every suspicious string hit is checked for surrounding context
        before it contributes to the score.  2-3 char tokens are ignored.

RULE 9  – Whitelist score credits
        Office XML structure   → −15
        Standard media headers → −10
        Confirmed clean magic  → −5
        These are applied before the final clamp.

RULE 10 – Multi-signal final decision
        The verdict combines: file_signature + extension_match +
        script_analysis + macro_analysis + entropy + structural_integrity
        + external_reputation (VT, passed in from app.py).
        No single signal can push a file to Malicious alone.
"""

from __future__ import annotations

import io
import math
import os
import re
import struct
import zipfile
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Magic / extension tables
# ─────────────────────────────────────────────────────────────────────────────

MAGIC_SIGNATURES: dict[bytes, str] = {
    b"\x4d\x5a":                         "PE Executable (EXE/DLL)",
    b"\x7f\x45\x4c\x46":                 "ELF Executable (Linux)",
    b"\x50\x4b\x03\x04":                 "ZIP Archive",
    b"\x50\x4b\x05\x06":                 "ZIP Archive (empty)",
    b"\x52\x61\x72\x21\x1a\x07":         "RAR Archive",
    b"\x1f\x8b":                          "GZIP Compressed",
    b"\x42\x5a\x68":                      "BZIP2 Compressed",
    b"\x25\x50\x44\x46":                  "PDF Document",
    b"\xff\xd8\xff":                      "JPEG Image",
    b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a": "PNG Image",
    b"\x47\x49\x46\x38":                  "GIF Image",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": "MS Office OLE Document",
    b"\x37\x7a\xbc\xaf\x27\x1c":         "7-Zip Archive",
    b"\xca\xfe\xba\xbe":                  "Java Class / Mach-O Fat",
    b"\x4c\x5a\x49\x50":                  "LZIP Compressed",
    b"\xfd\x37\x7a\x58\x5a\x00":         "XZ Compressed",
    b"\x23\x21":                          "Shell Script (shebang)",
    b"\x3c\x3f\x78\x6d\x6c":             "XML Document",
    b"\x3c\x68\x74\x6d\x6c":             "HTML Document",
    b"\xef\xbb\xbf":                      "UTF-8 BOM Text",
}

EXTENSION_TO_EXPECTED_MAGIC: dict[str, list[bytes]] = {
    ".exe":  [b"\x4d\x5a"],
    ".dll":  [b"\x4d\x5a"],
    ".zip":  [b"\x50\x4b\x03\x04", b"\x50\x4b\x05\x06"],
    ".pdf":  [b"\x25\x50\x44\x46"],
    ".jpg":  [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".png":  [b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a"],
    ".gif":  [b"\x47\x49\x46\x38"],
    ".gz":   [b"\x1f\x8b"],
    ".7z":   [b"\x37\x7a\xbc\xaf\x27\x1c"],
    ".rar":  [b"\x52\x61\x72\x21\x1a\x07"],
}

# RULE 2 — ZIP-based containers: these are ZIP files by design.
OFFICE_XML_EXTENSIONS: set[str] = {
    ".docx", ".xlsx", ".pptx", ".dotx", ".xltx", ".potx",
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm",
    ".odt", ".ods", ".odp", ".jar", ".apk",
}

OFFICE_OLE_EXTENSIONS: set[str] = {
    ".doc", ".xls", ".ppt", ".dot", ".xlt", ".pot",
}

# RULE 5 — canonical Office XML structural entries (whitelist validation)
OFFICE_XML_REQUIRED_ENTRIES: set[str] = {
    "[Content_Types].xml",
    "_rels/.rels",
}
OFFICE_XML_CONTENT_PREFIXES: tuple[str, ...] = (
    "word/", "xl/", "ppt/", "docProps/",
)

SCRIPT_EXTENSIONS: set[str] = {
    ".js", ".jse", ".vbs", ".vbe", ".bas", ".cls", ".frm",
    ".bat", ".cmd", ".ps1", ".psm1", ".psd1", ".py", ".pyw",
    ".sh", ".bash", ".hta", ".wsf", ".wsh",
    ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps",
    ".pl", ".rb", ".lua", ".reg", ".inf", ".sql",
}

# Media & container types whose high entropy is structurally expected (RULE 4 whitelist)
INHERENTLY_COMPRESSED_EXTENSIONS: set[str] = {
    ".docx", ".xlsx", ".pptx", ".dotx", ".xltx", ".potx",
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm",
    ".odt", ".ods", ".odp", ".jar", ".apk", ".pdf",
    ".zip", ".gz", ".tgz", ".bz2", ".tbz2", ".7z", ".rar", ".xz",
    ".iso", ".img", ".cab", ".vhd", ".vhdx",
    ".png", ".jpg", ".jpeg", ".gif", ".mp3", ".mp4",
    ".avi", ".mkv", ".aac", ".ogg", ".flac",
}

def strip_comments_and_docstrings(text: str, ext: str = "") -> str:
    """Strip docstrings and single/multiline comments from text to avoid false positives on comments."""
    if not text:
        return ""
    ext = ext.lower()
    # Strip python multiline docstrings
    cleaned = re.sub(r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'', '', text)
    # Strip C-style block comments
    cleaned = re.sub(r'/\*[\s\S]*?\*/', '', cleaned)
    # Strip HTML/XML comments
    cleaned = re.sub(r'<!--[\s\S]*?-->', '', cleaned)
    # Filter out comment lines
    active_lines = []
    for line in cleaned.splitlines():
        s = line.strip()
        # VBScript / VB comment check
        if s.startswith("'") or s.lower().startswith("rem ") or s.lower().startswith("rem\t"):
            continue
        # Batch comment check
        if s.startswith("::") or (ext in [".bat", ".cmd"] and s.lower().startswith("rem")):
            continue
        # Shell / Python / C / JS comments
        if s.startswith("#") or s.startswith("//") or s.startswith(";") or s.startswith("--"):
            continue
        # Inline comment stripping for VBScript (' outside quotes)
        if ext in [".vbs", ".vbe", ".bas", ".cls"] and "'" in line:
            parts = line.split("'")
            prefix = parts[0]
            if prefix.count('"') % 2 == 0:
                line = prefix
        elif "//" in line and ext in [".js", ".ts", ".php", ".c", ".cpp", ".cs"]:
            parts = line.split("//")
            prefix = parts[0]
            if prefix.count('"') % 2 == 0 and prefix.count("'") % 2 == 0:
                line = prefix
        active_lines.append(line)
    return "\n".join(active_lines)


def normalize_and_deobfuscate(text: str, ext: str = "") -> tuple[str, int]:
    """
    Phase 2 Pre-Scan Normalization & Static Deobfuscation Pass.
    Strips comments, folds string concatenations, and resolves Chr() / [char] chains
    without executing code. Returns (normalized_text, fold_count).
    """
    if not text:
        return "", 0
        
    ext = ext.lower()
    fold_count = 0
    
    # 1. First strip all comments and docstrings
    normalized = strip_comments_and_docstrings(text, ext)
    
    # 2. Deobfuscation Pass: Resolve Chr() and ChrW() chains (VBScript / VB)
    def _chr_repl(m):
        nonlocal fold_count
        try:
            val = int(m.group(1))
            if 32 <= val <= 126 or val in (9, 10, 13):
                fold_count += 1
                return f'"{chr(val)}"'
        except Exception:
            pass
        return m.group(0)
        
    normalized = re.sub(r'\bChr[WB]?\s*\(\s*(\d+)\s*\)', _chr_repl, normalized, flags=re.I)
    
    # PowerShell [char] chains
    def _ps_char_repl(m):
        nonlocal fold_count
        try:
            raw = m.group(1)
            val = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
            if 32 <= val <= 126 or val in (9, 10, 13):
                fold_count += 1
                return f'"{chr(val)}"'
        except Exception:
            pass
        return m.group(0)
        
    normalized = re.sub(r'\[char\]\s*(0x[0-9a-fA-F]+|\d+)', _ps_char_repl, normalized, flags=re.I)
    
    # 3. String Concatenation Folding: "foo" & "bar" or "foo" + "bar"
    # Run multiple passes to fold chained concatenations: "a" & "b" & "c" -> "abc"
    for _ in range(5):
        def _concat_repl(m):
            nonlocal fold_count
            fold_count += 1
            return f'"{m.group(1)}{m.group(2)}"'
            
        new_norm = re.sub(r'"([^"\r\n]*)"\s*&\s*"([^"\r\n]*)"', _concat_repl, normalized)
        new_norm = re.sub(r'"([^"\r\n]*)"\s*\+\s*"([^"\r\n]*)"', _concat_repl, new_norm)
        if new_norm == normalized:
            break
        normalized = new_norm

    return normalized, fold_count


def is_executable_or_malicious_payload(decoded_bytes: bytes, decoded_str: str) -> bool:
    """Check if decoded payload contains executable headers or active code constructs vs benign text."""
    if not decoded_bytes:
        return False
    # Check binary headers (PE / ELF / Mach-O / Zip)
    if decoded_bytes.startswith(b"MZ") or decoded_bytes.startswith(b"\x7fELF") or decoded_bytes.startswith(b"PK\x03\x04"):
        return True
    payload_pattern = re.compile(
        r"\b(eval|exec|compile|subprocess|os\.system|os\.popen|powershell|cmd\.exe|"
        r"wscript|cscript|Invoke-Expression|iex|VirtualAlloc|socket|connect|requests|"
        r"wget|curl|reg(\.exe)?\s+add|schtasks|Net\.WebClient|DownloadString|"
        r"def\s+\w+|function\s+\w+|import\s+\w+|from\s+\w+\s+import|<\?php|sh\b|bash\b)\b",
        re.I
    )
    return bool(payload_pattern.search(decoded_str))

# ─────────────────────────────────────────────────────────────────────────────
# IOC patterns
# ─────────────────────────────────────────────────────────────────────────────

IOC_PATTERNS: dict[str, re.Pattern] = {
    "URLs":             re.compile(r"https?://[^\s\"'<>]{8,}", re.I),
    "IP Addresses":     re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "IPv6":             re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
    # Full flag only — never isolated tokens (RULE 3)
    "PowerShell Encoded": re.compile(
        r"-[Ee][Nn][Cc][Oo][Dd][Ee][Dd][Cc][Oo][Mm][Mm][Aa][Nn][Dd]\s+[A-Za-z0-9+/=]{20,}"
        r"|-[Ee][Nn][Cc]\s+[A-Za-z0-9+/=]{20,}",
        re.I,
    ),
    "PowerShell Bypass": re.compile(
        r"-[Ee]xecution[Pp]olicy\s+[Bb]ypass"
        r"|-[Ee][Pp]\s+[Bb]ypass"
        r"|Set-ExecutionPolicy\s+Unrestricted",
        re.I,
    ),
    "CMD Execution":    re.compile(
        r"cmd\.exe\s*/[cCkK]|command\.com|%COMSPEC%", re.I
    ),
    "Registry Paths":   re.compile(
        r"HKEY_[A-Z_]+\\[^\s\"']{5,}|HKLM\\|HKCU\\|HKCR\\|\breg(\.exe)?\s+add\b|\bschtasks(\.exe)?\b", re.I
    ),
    "Windows Persistence Commands": re.compile(
        r"\breg(\.exe)?\s+add\b|\bschtasks(\.exe)?\s*(/create|/run|/change)?\b|\bNew-ScheduledTask\b|\bRegister-ScheduledTask\b|\b(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\r\n]*\\Run\b", re.I
    ),
    "Living-off-the-Land Commands": re.compile(
        r"\bcertutil(\.exe)?\s+.*-(urlcache|decode)\b|\bwmic(\.exe)?\s+.*(process\s+call\s+create|process)\b|\bbitsadmin(\.exe)?\s+.*(/transfer|/create|/addfile)\b|\bnet\s+(user|localgroup)\b", re.I
    ),
    "Suspicious Keywords": re.compile(
        r"\b(backdoor|rootkit|keylogger|ransomware|cryptominer|"
        r"reverse.?shell|c2.?server|command.?and.?control|"
        r"exfiltrat|data.?steal|credential.?harvest|"
        r"mimikatz|cobalt.?strike|metasploit|meterpreter)\b",
        re.I,
    ),
    # Known antivirus test strings / EICAR-family signatures
    "AV Test Signature": re.compile(
        r"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        r"|X5O!P%@AP\[4\\PZX54"
        r"|MEICAR-Test-File"
        r"|AMTSO-FEATURE-SETTINGS-CHECK",
        re.I,
    ),
    "Base64 Strings":   re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
    "Crypto Wallet":    re.compile(
        r"\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}"
        r"|3[a-km-zA-HJ-NP-Z1-9]{25,34}"
        r"|bc1[a-z0-9]{39,59}"
        r"|0x[a-fA-F0-9]{40})\b"
    ),
    "API Keys and Tokens": re.compile(
        r"(api[_-]?key|access[_-]?token|secret[_-]?key|auth[_-]?token)"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?",
        re.I,
    ),
    "Pastebin and Paste Sites": re.compile(
        r"pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.com|"
        r"paste\.org|pastecode\.io",
        re.I,
    ),
    "Ngrok and Tunnels":  re.compile(
        r"ngrok\.io|ngrok\.com|localtunnel|serveo\.net|"
        r"pagekite\.me|bore\.pub",
        re.I,
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# RULE 3 — Contextual PowerShell download detection (3-part gate)
# ─────────────────────────────────────────────────────────────────────────────

_PS_DOWNLOAD_FUNCTIONS = re.compile(
    r"\b(Invoke-WebRequest|iwr|DownloadFile|DownloadString|"
    r"Net\.WebClient|Start-BitsTransfer)\b",
    re.I,
)
_PS_EXECUTION_INDICATORS = re.compile(
    r"\b(iex|Invoke-Expression|powershell\s+-[Ee]nc|"
    r"Start-Process|cmd\s*/[cCkK]|DownloadString)\b",
    re.I,
)
_URL_NEAR = re.compile(r"https?://\S{5,}", re.I)
_WINDOW   = 300   # characters around the download token


def _is_contextual_ps_download(text: str) -> bool:
    """
    RULE 3 implementation.
    Fires only when ALL THREE are present within a 300-char window:
      1. a download function / alias
      2. a URL
      3. an execution keyword
    Isolated 'iwr', 'curl', 'wget' tokens → no score contribution.
    """
    for m in _PS_DOWNLOAD_FUNCTIONS.finditer(text):
        s = max(0, m.start() - _WINDOW)
        e = min(len(text), m.end() + _WINDOW)
        window = text[s:e]
        if _URL_NEAR.search(window) and _PS_EXECUTION_INDICATORS.search(window):
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Suspicious Windows APIs
# ─────────────────────────────────────────────────────────────────────────────

SUSPICIOUS_WINDOWS_APIS: set[str] = {
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
    "VirtualProtect", "VirtualAlloc", "LoadLibraryA", "LoadLibraryW",
    "GetProcAddress", "NtWriteVirtualMemory",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "OutputDebugString",
    "RegSetValueEx", "RegCreateKeyEx", "CreateService",
    "ChangeServiceConfig", "SHGetFolderPath",
    "WSAStartup", "InternetOpen", "InternetConnect",
    "HttpSendRequest", "WinHttpOpen", "socket", "connect",
    "CryptUnprotectData", "LsaRetrievePrivateData", "SamQueryInformationUser",
    "CryptEncrypt", "CryptGenKey", "BCryptEncrypt",
    "FindFirstFileW", "MoveFileEx",
}

DANGEROUS_SCRIPT_PATTERNS: dict[str, re.Pattern] = {
    "Invoke-Expression":   re.compile(r"\bIEX\b|\bInvoke-Expression\b", re.I),
    "Reflection Assembly": re.compile(r"\[Reflection\.Assembly\]|\[System\.Reflection", re.I),
    "AMSI Bypass":         re.compile(
        r"amsiInitFailed|amsi\.dll|AmsiScanBuffer|[Aa]msi[Bb]ypass", re.I
    ),
    "WMI Execution":       re.compile(
        r"Win32_Process|wmic\s+process|Get-WmiObject|Invoke-WmiMethod", re.I
    ),
    "Scheduled Task":      re.compile(
        r"schtasks|New-ScheduledTask|Register-ScheduledTask", re.I
    ),
    "UAC Bypass":          re.compile(
        r"fodhelper|eventvwr|sdclt|[Uu][Aa][Cc]\s*[Bb]ypass", re.I
    ),
    "Process Hollowing":   re.compile(
        r"ZwUnmapViewOfSection|NtUnmapViewOfSection", re.I
    ),
    "Keylogger":           re.compile(
        r"SetWindowsHookEx|GetAsyncKeyState|keyboard[Hh]ook", re.I
    ),
    "Screen Capture":      re.compile(
        r"BitBlt|GetDC\(|CopyFromScreen|screenshot", re.I
    ),
    "Fileless Execution":  re.compile(
        r"Invoke-Shellcode|Invoke-ReflectivePEInjection|shellcode", re.I
    ),
    "PHP Eval Obfuscation": re.compile(
        r"eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|\$_(POST|GET|REQUEST|COOKIE))", re.I
    ),
    "PHP Shell Execution": re.compile(
        r"\b(system|shell_exec|passthru|proc_open|popen|exec)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|HEADER)", re.I
    ),
    "PHP Dynamic Callback": re.compile(
        r"assert\s*\(\s*(base64_decode|\$_)|create_function\s*\(|preg_replace\s*\(\s*['\"].*\/e['\"]", re.I
    ),
    "Shadow Copy Deletion": re.compile(
        r"vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit(\.exe)?\s+/set\s+[^\r\n]*recoveryenabled\s+no", re.I
    ),
    "AutoRun INF Dropper": re.compile(
        r"\[AutoRun\][\s\S]{0,200}(?:Open|ShellExecute)\s*=\s*\S+\.(exe|bat|cmd|com|scr|pif|vbs|ps1)", re.I
    ),
    "SQL Injection Pattern": re.compile(
        r"(?:DROP\s+TABLE|TRUNCATE\s+TABLE|DELETE\s+FROM\s+\w+\s*;|INSERT\s+INTO\s+\w+\s*VALUES\s*\(['\"]?\w+['\"]?\s*,\s*['\"]?\w+['\"]?\))\s*;", re.I
    ),
    "VBE Encoded Script": re.compile(
        r"#@~\^[A-Za-z0-9+/=]{6,}==", re.I
    ),
    "Persistence Registry Run Key": re.compile(
        r"(?:HKEY_CURRENT_USER|HKCU)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", re.I
    ),
    "PowerShell Download Cradle": re.compile(
        r"(?:IEX|Invoke-Expression)\s*\(?(?:\s*\(?\s*New-Object\s+Net\.WebClient\s*\))?\s*\.DownloadString\s*\(", re.I
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# Office Analysis v4 — whitelists, severity tiers, structured patterns
# ─────────────────────────────────────────────────────────────────────────────

# RULE 1 — URL/domain prefixes that are ALWAYS safe in Office XML context.
# These are namespace declarations, schema references, and W3C standards.
OFFICE_SAFE_URL_PREFIXES: tuple[str, ...] = (
    "http://schemas.openxmlformats.org/",
    "https://schemas.openxmlformats.org/",
    "http://schemas.microsoft.com/",
    "https://schemas.microsoft.com/",
    "http://purl.org/",
    "https://purl.org/",
    "http://www.w3.org/",
    "https://www.w3.org/",
    "http://dublincore.org/",
    "https://dublincore.org/",
    "http://ns.adobe.com/",
    "https://ns.adobe.com/",
)

# RULE 8 — XML attribute patterns that are pure namespace / metadata declarations.
# Matching any of these in a line means the line is metadata, not a live link.
OFFICE_NAMESPACE_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r'xmlns\s*:\s*\w+\s*=\s*"https?://', re.I),        # xmlns:x="http://…"
    re.compile(r'xmlns\s*=\s*"https?://', re.I),                   # xmlns="http://…"
    re.compile(r'mc:Ignorable\s*=', re.I),                         # markup-compatibility
    re.compile(r'<\?xml\s+version', re.I),                         # XML declaration
    re.compile(r'x:xmpmeta|x:xmptk', re.I),                       # XMP metadata
    re.compile(r'rdf:about\s*=\s*""', re.I),                       # RDF metadata
)

# RULE 2 — Relationship entry patterns that ARE suspicious in .rels files.
# A relationship is only external when TargetMode="External" is present OR
# the Target value points to a non-schema, non-localhost URL.
_RELS_EXTERNAL_MODE = re.compile(r'TargetMode\s*=\s*["\']External["\']', re.I)
_RELS_TARGET_URL    = re.compile(r'Target\s*=\s*["\']https?://([^"\']+)["\']', re.I)
_RELS_DOTM_TEMPLATE = re.compile(
    r'Target\s*=\s*["\'][^"\']*\.(dot[mx]?|xlt[xm]?|pot[xm]?)["\']', re.I
)

# RULE 3 — Real VBA / macro execution patterns (HIGH / CRITICAL only).
# These only fire inside actual VBA source, .bin, or macro entry streams.
VBA_EXEC_PATTERNS: dict[str, re.Pattern] = {
    "AutoOpen/AutoExec":    re.compile(
        r"\b(AutoOpen|AutoExec|Document_Open|Workbook_Open|Auto_Open)\b", re.I
    ),
    "Shell Execution":      re.compile(
        r"\bShell\s*\(|WScript\.Shell|CreateObject\s*\(\s*['\"]WScript", re.I
    ),
    "CreateObject":         re.compile(
        r'\bCreateObject\s*\(\s*["\']', re.I
    ),
    "Download from URL":    re.compile(
        r"\b(XMLHTTP|WinHttpRequest|URLDownloadToFile)\b", re.I
    ),
    "Write to Filesystem":  re.compile(
        r"\b(Open\s+.{1,60}\s+For\s+(Output|Append|Binary)|FileSystemObject)\b", re.I
    ),
    "PowerShell via VBA":   re.compile(
        r"\bpowershell\b", re.I
    ),
    "CMD Execution":        re.compile(
        r"\bcmd\.exe\b|\bShell\s*\([^)]*cmd", re.I
    ),
    "Encoded/Obfuscated":   re.compile(
        r"\b(Chr\s*\(\d+\)|ChrW\s*\(\d+\))\s*&", re.I
    ),
    "DDE Abuse":            re.compile(
        r"\bDDE(AUTO|INITIATE|REQUEST|EXECUTE)?\b", re.I
    ),
}

# RULE 7 — Patterns checked ONLY inside .rels files (relationship scanning).
# Applied with context-gated logic, not raw string match.
RELS_ONLY_PATTERNS: dict[str, re.Pattern] = {
    "External Template (.dotm/.dot)": _RELS_DOTM_TEMPLATE,
    "External Relationship":          _RELS_EXTERNAL_MODE,
}

# RULE 4 — severity tier constants
SEVERITY_INFO     = "INFO"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_HIGH     = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

# Entry-type → whether it can host real VBA code.
# Only these entry types are scanned for VBA_EXEC_PATTERNS.
VBA_CAPABLE_ENTRIES: set[str] = {
    "vbaProject.bin", "vbaProject.bin.rels",
    "xl/macrosheets/", "word/vbaProject",
    ".xlsm", ".xlsb", ".docm", ".pptm",
}

# Entry suffixes scanned for relationship / remote-link checks (not VBA).
RELS_ENTRY_SUFFIX = ".rels"

# Structured finding dataclass (RULE 9 — enriched reporting).
@dataclass
class OfficeFinding:
    """One structured finding from the Office analyzer."""
    severity:    str   # INFO / MEDIUM / HIGH / CRITICAL
    category:    str   # human label shown in UI
    source_file: str   # ZIP entry name where found
    detail:      str   # actual URL / token / reason
    confidence:  int   # 0-100
    is_vba:      bool  = False   # true only for real macro findings
    is_relation: bool  = False   # true for .rels external findings

# ─────────────────────────────────────────────────────────────────────────────
# Score weights  (v3 — entropy weights are conditional, see calculate_score)
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# v5 Score weights — tiered to match professional AV/EDR scoring
#
# SAFE / INFO   0–5    : valid structure, trusted domains, schema URLs
# LOW RISK      5–15   : unknown URLs, external rels, unsigned EXE, basic network
# MEDIUM RISK  15–35   : macro-enabled docs, obfuscated JS, hidden process, PS exec
# HIGH RISK    35–70   : encoded PS, download cradle, credential dump, persistence
# CRITICAL     70–100  : ransomware, embedded EXE, EICAR, reverse shell, C2
# ─────────────────────────────────────────────────────────────────────────────

SCORE_WEIGHTS: dict[str, int] = {
    # ── SAFE / INFO (0–5) ─────────────────────────────────────────────────────
    "office_xml_structure":        0,    # valid structure — whitelist credit handled separately
    "standard_media_header":       0,
    "clean_magic_match":           0,

    # ── LOW RISK (5–15) ──────────────────────────────────────────────────────
    "suspicious_url":              5,    # unknown external URL alone
    "suspicious_ip":               5,
    "double_extension":            8,    # suspicious but not definitive
    "base64_blob":                 5,    # base64 strings alone are common
    "api_key_exposed":             10,
    "office_ext_relationship":     8,    # any external Office relationship
    "embedded_archive":            8,
    "embedded_pe_unvalidated":     8,    # raw MZ hit, not validated
    "password_protected_zip":      8,
    "registry_persistence":        12,   # registry mod for settings
    "wmi_execution":               12,
    "nested_archive":              10,
    "suspicious_archive_entry":    12,
    "office_external_rel":         10,   # TargetMode=External, non-schema URL

    # ── MEDIUM RISK (15–35) ──────────────────────────────────────────────────
    "suspicious_keyword":          18,   # known malware terminology
    "fake_extension":              20,
    "packed_executable":           20,   # packer without other indicators
    "scheduled_task":              20,
    "suspicious_api":              15,   # generic suspicious API, no context
    "vba_write_fs":                18,
    "vba_create_object":           20,
    "vba_encoded":                 22,
    "crypto_wallet":               20,
    "paste_site":                  22,   # paste site URL
    "iex_usage":                   25,   # IEX alone is medium — needs context
    "office_remote_template":      28,   # remote .dotm template
    "high_entropy_with_coind":     18,   # high entropy + co-indicator
    "very_high_entropy_alone":      5,   # informational only
    "very_high_entropy_with_coind":22,

    # ── HIGH RISK (35–70) ────────────────────────────────────────────────────
    "renamed_executable":          38,
    "powershell_encoded":          45,   # -EncodedCommand is a strong signal
    "powershell_bypass":           38,
    "powershell_download":         40,   # confirmed 3-part download cradle
    "ngrok_tunnel":                42,
    "anti_debug":                  35,
    "uac_bypass":                  45,
    "amsi_bypass":                 50,
    "process_injection_api":       55,
    "credential_api":              55,
    "vba_auto_exec":               45,
    "vba_shell":                   50,
    "vba_download":                42,
    "vba_powershell":              45,
    "vba_cmd_exec":                45,
    "vba_dde":                     48,
    "vba_external_template":       38,
    "appended_payload":            50,
    "dangerous_com_objects":       65,   # WScript.Shell, Scripting.FileSystemObject
    "obfuscation_reconstructed":   40,   # Deobfuscation pass folded hidden string/char primitives

    # ── CRITICAL (70–100) ────────────────────────────────────────────────────
    "obfuscated_loader_exec_pattern": 95,   # exec/eval + base64/encoding routine
    "windows_persistence_lotl":    85,   # reg add / schtasks / HKLM Run persistence / LotL commands
    "dynamic_exec_var":            85,   # Execute(var), Eval(var), IEX $var
    "lolbin_abuse":                85,   # certutil -decode, regsvr32, mshta, bitsadmin
    "taint_staging_flow":          85,   # Input/Read -> Execution sink flow
    "ransomware_api":              72,
    "validated_embedded_pe":       68,
    "polyglot_file":               75,
    "av_test_signature":           85,   # EICAR / known test string

    # ── Reputation credits (negative — reduce score) ──────────────────────────
    "trusted_vendor_signed":      -20,   # digitally signed by trusted vendor
    "known_installer_behavior":   -10,   # matches common installer pattern
    "trusted_domain_only":        -8,    # URLs only to trusted domains

    # ── Confidence gate penalty ───────────────────────────────────────────────
    "insufficient_evidence":      -15,
}

# Indicators that count toward the CRITICAL gate (require ≥2 for Malicious verdict)
HIGH_CONFIDENCE_INDICATORS: set[str] = {
    "obfuscated_loader_exec_pattern", "windows_persistence_lotl", "validated_embedded_pe", "polyglot_file",
    "appended_payload", "powershell_encoded", "amsi_bypass", "process_injection_api",
    "ransomware_api", "credential_api", "uac_bypass", "iex_usage",
    "vba_auto_exec", "vba_shell", "vba_download", "vba_powershell", "vba_dde",
    "renamed_executable", "fake_extension", "av_test_signature",
    "ngrok_tunnel", "powershell_download",
    "dynamic_exec_var", "lolbin_abuse", "taint_staging_flow", "dangerous_com_objects", "obfuscation_reconstructed"
}

# Explicit Named Subset for Active Threat Gate Zero-Day Override Path
ACTIVE_THREAT_GATE_INDICATORS: set[str] = {
    "windows_persistence_lotl",
    "obfuscated_loader_exec_pattern",
    "ransomware_api",
    "dynamic_exec_var",
    "lolbin_abuse",
    "taint_staging_flow",
    "amsi_bypass",
    "uac_bypass",
    "iex_usage",
    "process_injection_api",
    "polyglot_file",
    "appended_payload",
    "av_test_signature"
}

# Trusted vendor strings for reputation scoring (req. 6)
TRUSTED_VENDOR_STRINGS: tuple[str, ...] = (
    "Microsoft Corporation", "Google LLC", "NVIDIA Corporation",
    "Valve Corp", "Adobe Inc", "Mozilla Corporation",
    "Apple Inc", "Intel Corporation", "Advanced Micro Devices",
    "Canonical Ltd", "Oracle Corporation",
)

# Trusted domains — URLs pointing only here get a small credit
TRUSTED_DOMAINS: tuple[str, ...] = (
    "microsoft.com", "google.com", "github.com", "stackoverflow.com",
    "mozilla.org", "apple.com", "adobe.com", "nvidia.com",
    "doi.org", "nih.gov", "ieee.org", "acm.org", "arxiv.org",
    "jstor.org", "scholar.google.com", "pubmed.ncbi.nlm.nih.gov",
    # Major CDN / web delivery networks (commonly found in HTML <link>/<script> tags)
    "jsdelivr.net", "cdnjs.cloudflare.com", "cloudflare.com",
    "unpkg.com", "bootstrapcdn.com", "fontawesome.com",
    "fonts.googleapis.com", "fonts.gstatic.com", "ajax.googleapis.com",
    "code.jquery.com", "maxcdn.bootstrapcdn.com", "stackpath.bootstrapcdn.com",
    "use.fontawesome.com", "kit.fontawesome.com",
    "cdn.jsdelivr.net", "static.cloudflareinsights.com",
    "w3.org", "schema.org", "openxmlformats.org",
    "jquery.com", "angularjs.org", "vuejs.org", "reactjs.org",
    "gravatar.com", "shields.io", "badge.fury.io",
)

# ─────────────────────────────────────────────────────────────────────────────
# Result dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AdvancedHeuristicResult:
    # File classification (RULE 7)
    detected_type:        str  = "Unknown"
    file_classification:  str  = ""   # human-readable: "Microsoft Word Document", etc.
    container_type:       str  = ""
    claimed_extension:    str  = ""
    type_mismatch:        bool = False
    fake_extension:       bool = False
    double_extension:     bool = False
    renamed_executable:   bool = False
    is_office_container:  bool = False   # RULE 2
    is_ole_office:        bool = False
    office_xml_validated: bool = False   # RULE 5 — structural check passed

    # Embedded / polyglot
    embedded_executables: list = field(default_factory=list)
    candidate_pes:        list = field(default_factory=list)
    embedded_archives:    list = field(default_factory=list)
    appended_payload:     bool = False
    polyglot:             bool = False

    # IOC extraction
    iocs:                   dict = field(default_factory=dict)
    ps_download_contextual: bool = False   # RULE 3 — 3-part gate result

    # Script / PE analysis
    suspicious_apis:      list  = field(default_factory=list)
    script_findings:      list  = field(default_factory=list)
    section_entropies:    list  = field(default_factory=list)
    imports:              list  = field(default_factory=list)
    entry_point_anomaly:  bool  = False

    # VBA / OLE — structured findings (v4)
    vba_findings:         list  = field(default_factory=list)   # legacy compat: list[str]
    ole_objects:          list  = field(default_factory=list)
    office_findings:      list  = field(default_factory=list)   # list[OfficeFinding]
    has_vba_project:      bool  = False   # vbaProject.bin present in ZIP
    has_macrosheet:       bool  = False   # xl/macrosheets/ present

    # Entropy (RULE 4)
    entropy:              float = 0.0
    entropy_context:      str   = ""   # RULE 7 — displayed in UI
    entropy_explanation:  str   = ""   # RULE 7 — legacy field kept for compat
    entropy_co_indicator: bool  = False  # true if another signal reinforces entropy
    packed:               bool  = False

    # Archive
    archive_findings:     list  = field(default_factory=list)
    nested_archives:      int   = 0
    password_protected:   bool  = False

    # RULE 9 — whitelist credits applied
    whitelist_credits:    list  = field(default_factory=list)

    # Req. 6 — reputation intelligence
    trusted_vendor:       bool  = False   # digitally signed by known vendor
    reputation_credits:   list  = field(default_factory=list)  # applied credits

    # Req. 8 — structured detection quality summary
    detection_summary:    dict  = field(default_factory=dict)

    # Scoring / verdict (RULE 6 & 10)
    score:                int   = 0
    score_breakdown:      dict  = field(default_factory=dict)
    threat_level:         str   = "Safe"
    confidence:           int   = 0
    confidence_tier:      str   = ""   # "LOW" / "MEDIUM" / "HIGH"
    explanation:          str   = ""
    risk_explanation:     str   = ""   # RULE 7 — plain-English verdict
    final_verdict:        str   = ""   # RULE 7 — one-liner for UI header
    detections:           list  = field(default_factory=list)
    fp_notes:             list  = field(default_factory=list)

    # Depth Control & Grounding
    encoding_layers:        int   = 0
    decoded_size:           int   = 0
    decoded_detections:     int   = 0
    intent_classification:  str   = ""
    indicator_grounding:    list  = field(default_factory=list)

    # Internal
    _hc_indicators:       list  = field(default_factory=list)
    _co_indicators:       list  = field(default_factory=list)  # non-entropy signals


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in counts if c), 2)


def _detect_magic(data: bytes) -> Optional[str]:
    for sig, name in MAGIC_SIGNATURES.items():
        if data[: len(sig)] == sig:
            return name
    return None


def _validate_pe_structure(data: bytes, offset: int) -> bool:
    """Return True only when a full, parseable PE header exists at offset."""
    try:
        if offset + 64 > len(data):
            return False
        if data[offset: offset + 2] != b"\x4d\x5a":
            return False
        e_lfanew = struct.unpack_from("<I", data, offset + 0x3C)[0]
        abs_pe   = offset + e_lfanew
        if abs_pe + 24 > len(data):
            return False
        if data[abs_pe: abs_pe + 4] != b"PE\x00\x00":
            return False
        num_sections = struct.unpack_from("<H", data, abs_pe + 6)[0]
        if not (1 <= num_sections <= 96):
            return False
        opt_sz  = struct.unpack_from("<H", data, abs_pe + 20)[0]
        sec_off = abs_pe + 24 + opt_sz
        if sec_off + 40 > len(data):
            return False
        for i in range(min(num_sections, 4)):
            raw_ptr = struct.unpack_from("<I", data, sec_off + i * 40 + 20)[0]
            raw_sz  = struct.unpack_from("<I", data, sec_off + i * 40 + 16)[0]
            if raw_ptr > 0 and raw_ptr + raw_sz <= len(data):
                return True
        return False
    except (struct.error, IndexError):
        return False


def _is_office_xml_zip(zf: zipfile.ZipFile) -> bool:
    names = {e.filename for e in zf.infolist()}
    return bool(
        names & {"[Content_Types].xml", "_rels/.rels", "AndroidManifest.xml"}
        or any(n.startswith(OFFICE_XML_CONTENT_PREFIXES) for n in names)
    )


def _validate_office_xml_structure(file_bytes: bytes) -> bool:
    """
    RULE 5 — Return True when the ZIP contains the canonical Office entry set:
    [Content_Types].xml, _rels/.rels, and at least one content prefix.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zf:
            names = {e.filename for e in zf.infolist()}
            has_required = OFFICE_XML_REQUIRED_ENTRIES.issubset(names)
            has_content  = any(
                n.startswith(OFFICE_XML_CONTENT_PREFIXES) for n in names
            )
            return has_required and has_content
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — File Type Verification
# ─────────────────────────────────────────────────────────────────────────────

def analyze_file_type(
    file_path: str, file_bytes: bytes, result: AdvancedHeuristicResult
) -> None:
    filename = os.path.basename(file_path)
    parts    = filename.rsplit(".", 2)
    ext      = ("." + parts[-1].lower()) if len(parts) > 1 else ""
    result.claimed_extension = ext

    detected = _detect_magic(file_bytes)
    if detected:
        result.detected_type = detected
    else:
        text_ext_map = {
            ".txt":  "Plain Text Document (.txt)",
            ".py":   "Python Script (.py)",
            ".js":   "JavaScript Source File (.js)",
            ".ps1":  "PowerShell Script (.ps1)",
            ".bat":  "Windows Batch Script (.bat)",
            ".cmd":  "Windows Command Script (.cmd)",
            ".vbs":  "VBScript (.vbs)",
            ".sh":   "Shell Script (.sh)",
            ".json": "JSON Data Document (.json)",
            ".html": "HTML Document (.html)",
            ".htm":  "HTML Document (.htm)",
            ".css":  "CSS Stylesheet (.css)",
            ".xml":  "XML Document (.xml)",
            ".md":   "Markdown Document (.md)",
            ".csv":  "CSV Spreadsheet (.csv)",
        }
        result.detected_type = text_ext_map.get(ext, "Text / Code Artifact" if ext else "Standard Data Stream")

    # ── RULE 2: Identify Office XML containers immediately ───────────────────
    if ext in OFFICE_XML_EXTENSIONS and file_bytes[:4] == b"\x50\x4b\x03\x04":
        result.is_office_container = True
        _classify_office_xml(file_bytes, ext, result)
    elif ext in OFFICE_OLE_EXTENSIONS and file_bytes[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        result.is_ole_office = True
        result.container_type = "OLE Compound Document"
    else:
        result.is_office_container = False
        result.office_xml_validated = False
        result.is_ole_office = False
        if not result.container_type:
            result.container_type = "Standard File Stream"

    # ── RULE 9: Clean magic match credit ────────────────────────────────────
    expected_sigs = EXTENSION_TO_EXPECTED_MAGIC.get(ext, [])
    if expected_sigs and any(
        file_bytes[: len(s)] == s for s in expected_sigs
    ):
        result.whitelist_credits.append("clean_magic_match")

    # ── Double extension ─────────────────────────────────────────────────────
    if len(parts) >= 3:
        result.double_extension = True
        result.detections.append(f"Double extension detected: {filename}")

    # ── Extension / magic mismatch ───────────────────────────────────────────
    if detected and expected_sigs:
        mismatch = not any(
            file_bytes[: len(s)] == s for s in expected_sigs
        )
        # Suppress for known Office containers (they ARE ZIP files by design)
        if mismatch and not (
            result.is_office_container and ext in OFFICE_XML_EXTENSIONS
        ):
            result.type_mismatch  = True
            result.fake_extension = True
            result.detections.append(
                f"Fake extension: file claims '{ext}' but magic bytes "
                f"indicate '{detected}'"
            )

    # ── Renamed executable ───────────────────────────────────────────────────
    is_exe_magic = file_bytes[:2] == b"\x4d\x5a"
    safe_exts    = {".jpg", ".jpeg", ".png", ".gif", ".pdf",
                    ".doc", ".docx", ".xls", ".xlsx", ".txt", ".zip"}
    if is_exe_magic and ext in safe_exts:
        result.renamed_executable = True
        result.detections.append(
            f"Renamed executable: EXE/DLL disguised as '{ext}'"
        )


def _classify_office_xml(
    file_bytes: bytes, ext: str, result: AdvancedHeuristicResult
) -> None:
    """Determine exact Office XML sub-type and run RULE 5 structural check."""
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zf:
            names = {e.filename for e in zf.infolist()}
            if any(n.startswith("word/") for n in names):
                result.file_classification = "Microsoft Word Document"
                result.container_type      = "ZIP-based Office Open XML (Word Document)"
                result.detected_type       = "Microsoft Word Document (.docx)"
            elif any(n.startswith("xl/") for n in names):
                result.file_classification = "Microsoft Excel Workbook"
                result.container_type      = "ZIP-based Office Open XML (Excel Workbook)"
                result.detected_type       = "Microsoft Excel Workbook (.xlsx)"
            elif any(n.startswith("ppt/") for n in names):
                result.file_classification = "Microsoft PowerPoint Presentation"
                result.container_type      = "ZIP-based Office Open XML (PowerPoint Presentation)"
                result.detected_type       = "Microsoft PowerPoint Presentation (.pptx)"
            elif "AndroidManifest.xml" in names or any(
                n.startswith("META-INF/") for n in names
            ):
                result.file_classification = "Android Package / Java Archive"
                result.container_type      = "ZIP-based Android Package (APK/JAR)"
                result.detected_type       = "Android Package / Java Archive"
            else:
                result.file_classification = "ZIP-based Container"
                result.container_type      = "ZIP-based Container"

        # RULE 5 — structural validation
        result.office_xml_validated = _validate_office_xml_structure(file_bytes)
        if result.office_xml_validated:
            result.whitelist_credits.append("office_xml_structure")
            result.fp_notes.append(
                f"Valid {result.file_classification} structure confirmed "
                f"([Content_Types].xml + _rels/.rels + content prefix). "
                f"ZIP-internal signatures are expected and NOT treated as embeds."
            )
        else:
            result.fp_notes.append(
                f"File has Office extension but failed structural validation — "
                "may be a corrupt or non-standard container."
            )
    except (zipfile.BadZipFile, Exception) as exc:
        result.container_type = "ZIP-based Container (unreadable)"
        result.fp_notes.append(f"Could not open ZIP container: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — Embedded Content Detection
# ─────────────────────────────────────────────────────────────────────────────

def analyze_embedded_content(
    file_bytes: bytes, result: AdvancedHeuristicResult
) -> None:

    PASSIVE_TEXT_EXTS = {".txt", ".md", ".json", ".html", ".css", ".xml", ".svg", ".rst"}
    is_passive_text = result.claimed_extension in PASSIVE_TEXT_EXTS

    # ── Embedded PE (validated) ──────────────────────────────────────────────
    # RULE 8: Skip raw byte scan inside Office XML containers & passive text formats.
    if not result.is_office_container and not is_passive_text:
        mz_sig = b"\x4d\x5a"
        offset = 2
        while True:
            pos = file_bytes.find(mz_sig, offset)
            if pos == -1:
                break
            if _validate_pe_structure(file_bytes, pos):
                result.embedded_executables.append(
                    f"Validated PE at offset 0x{pos:X}"
                )
            else:
                result.candidate_pes.append(pos)
            offset = pos + 2

        if result.embedded_executables:
            result.detections.append(
                f"Validated embedded executable(s): "
                f"{len(result.embedded_executables)} location(s)"
            )
        elif result.candidate_pes:
            result.fp_notes.append(
                f"{len(result.candidate_pes)} raw MZ byte sequence(s) found "
                "but none passed PE structure validation — likely false positives."
            )
    elif result.is_office_container:
        result.fp_notes.append(
            "Embedded PE scan skipped: Office XML container — "
            "internal binary streams do not imply executable content."
        )
    elif is_passive_text:
        result.fp_notes.append(
            "Embedded PE scan skipped: Plain text/markup format — "
            "cannot contain executable PE binary structures."
        )

    # ── Embedded ZIP archives (skip Office containers, ZIP containers themselves & passive text) ────────
    is_zip_container = result.claimed_extension in INHERENTLY_COMPRESSED_EXTENSIONS or file_bytes[:4] == b"\x50\x4b\x03\x04"
    if not result.is_office_container and not is_passive_text and not is_zip_container:
        pk_sig = b"\x50\x4b\x03\x04"
        offset = 4
        while True:
            pos = file_bytes.find(pk_sig, offset)
            if pos == -1:
                break
            try:
                zipfile.ZipFile(io.BytesIO(file_bytes[pos:]), "r").close()
                result.embedded_archives.append(
                    f"Validated ZIP at offset 0x{pos:X}"
                )
            except Exception:
                pass
            offset = pos + 4

        if result.embedded_archives:
            result.detections.append(
                f"Validated embedded archive(s): "
                f"{len(result.embedded_archives)} location(s)"
            )

    # ── Appended payload (PNG-specific) ──────────────────────────────────────
    if file_bytes[:8] == b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a":
        iend = file_bytes.rfind(b"\x49\x45\x4e\x44\xae\x42\x60\x82")
        if iend != -1 and iend + 8 < len(file_bytes) - 4:
            trailing = len(file_bytes) - (iend + 8)
            result.appended_payload = True
            result.detections.append(
                f"Appended payload: {trailing} bytes after PNG IEND marker"
            )

    # ── Standard media header credit (RULE 9) ────────────────────────────────
    media_magic = (b"\xff\xd8\xff", b"\x89\x50\x4e\x47", b"\x47\x49\x46\x38")
    if any(file_bytes[:len(m)] == m for m in media_magic):
        result.whitelist_credits.append("standard_media_header")

    # ── Polyglot ─────────────────────────────────────────────────────────────
    if result.embedded_executables and result.detected_type in (
        "JPEG Image", "PNG Image", "PDF Document"
    ):
        result.polyglot = True
        result.detections.append(
            "Polyglot file: valid image/document AND contains validated executable"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Stage 3 — Static String / IOC Analysis
# ─────────────────────────────────────────────────────────────────────────────

def analyze_strings(file_bytes: bytes, result: AdvancedHeuristicResult) -> None:
    # RULE 8 — For binary files, scan decoded text not raw bytes.
    try:
        text = file_bytes.decode("utf-8", errors="ignore")
    except Exception:
        text = ""

    active_text, _ = normalize_and_deobfuscate(text, result.claimed_extension)
    iocs: dict = {}
    _CODE_AND_ARCHIVE_EXTS = {".py", ".js", ".ts", ".rb", ".php", ".java", ".go", ".cs",
                              ".cpp", ".c", ".h", ".rs", ".md", ".txt", ".json", ".html",
                              ".css", ".xml", ".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx"}
    _is_archive_format = (result.claimed_extension or "").lower() in {".zip", ".jar", ".apk", ".tar", ".gz", ".7z", ".rar", ".docx", ".xlsx", ".pptx"}
    for category, pattern in IOC_PATTERNS.items():
        if category == "AV Test Signature":
            if (result.claimed_extension or "").lower() in _CODE_AND_ARCHIVE_EXTS or len(file_bytes) > 500:
                continue
        # Raw compressed archive streams produce random byte combinations that trigger false IP/Wallet matches
        if _is_archive_format and category in {"Crypto Wallet", "IP Addresses", "IPv6"}:
            continue
        # Run IOC pattern matching on active normalized text for scripts/code to prevent comment false positives
        scan_target = active_text if (result.claimed_extension or "").lower() in SCRIPT_EXTENSIONS | _CODE_AND_ARCHIVE_EXTS else text
        matches = list(dict.fromkeys(m.group(0).strip() for m in pattern.finditer(scan_target) if m.group(0).strip()))
        if matches:
            iocs[category] = matches[:20]

    # ── Multi-Layer Controlled Decoding & Base64 Payload Inspection ─────────
    import base64
    layers = 0
    curr_bytes = file_bytes
    decoded_buffers = []
    decoded_raw = []
    while layers < 2:
        b64_matches = re.findall(rb"[A-Za-z0-9+/]{40,}={0,2}", curr_bytes)
        if not b64_matches:
            break
        try:
            dec = base64.b64decode(b64_matches[0])
            if 10 < len(dec) < 50000 and dec != curr_bytes:
                layers += 1
                curr_bytes = dec
                decoded_raw.append(dec)
                try:
                    decoded_buffers.append(dec.decode("utf-8", errors="ignore"))
                except Exception:
                    pass
            else:
                break
        except Exception:
            break

    result.encoding_layers = layers
    result.decoded_size = len(curr_bytes) if layers > 0 else 0

    decoded_text_combined = "\n".join(decoded_buffers)

    # Evaluate whether any decoded Base64 payload actually contains executable constructs
    has_executable_b64 = any(is_executable_or_malicious_payload(raw, buf) for raw, buf in zip(decoded_raw, decoded_buffers))
    if decoded_buffers and not has_executable_b64:
        result.fp_notes.append("Automated Base64 Inspection: Decoded payload is harmless plain text — suppressed obfuscation alert.")

    # ── Indicator Grounding for eval / exec ───────────────────────────────────
    raw_eval = bool(re.search(r"\b(eval|exec)\s*\(", active_text, re.I))
    dec_eval = bool(re.search(r"\b(eval|exec)\s*\(", decoded_text_combined, re.I)) if decoded_text_combined else False

    if raw_eval:
        result.indicator_grounding.append("eval/exec keyword found in active script code")
    elif dec_eval:
        result.indicator_grounding.append("eval-like keyword found only inside decoded string (unvalidated as executable body)")
        result.fp_notes.append("eval/exec token detected only inside decoded string — not validated as executable code structure.")

    if layers > 0 and not has_executable_b64:
        result.fp_notes.append(f"Decode Depth Control: Layer {layers} decoded ({result.decoded_size} bytes). Harmless text payload.")

    # ── Text vs Executable Intent Classification ─────────────────────────────
    PASSIVE_MARKUP_EXTS = {".html", ".htm", ".css", ".txt", ".json", ".xml", ".svg", ".md", ".rst"}
    if result.claimed_extension in PASSIVE_MARKUP_EXTS:
        # Expanded keyword list: includes dynamic execution AND encoding/obfuscation markers
        code_syntax = re.findall(
            r"\b(eval|exec|compile|base64|b64decode|b64encode|decode|encode"
            r"|def |function |import |var |const |let "
            r"|powershell|cmd\.exe|curl|wget|subprocess|os\.system)\b",
            active_text, re.I
        )
        if code_syntax:
            result.intent_classification = "Script / Loader Artifact"
        else:
            result.intent_classification = "Text / Documentation Artifact (non-executable intent)"
            result.fp_notes.append(
                "Intent Classifier: Document/text file contains no active executable code structure "
                "or shell execution commands (RULE 11)."
            )

    # ── Obfuscated Loader / Execution Routine Detection (exec/eval + base64) ─
    has_exec_func = bool(re.search(
        r"\b(eval|exec|compile|subprocess|os\.system|os\.popen|shell_exec|passthru)\b|\b(eval|exec)\s*\(|Invoke-Expression|\biex\b",
        active_text, re.I
    ))
    has_obf_func = bool(re.search(
        r"\b(base64|b64decode|b64encode|codecs|zlib|decompress|uncompress)\b|-[Ee][Nn][Cc]|\b(chr|ord)\s*\(|\\x[0-9a-fA-F]{2}",
        active_text, re.I
    )) or (layers > 0)

    if has_exec_func and has_obf_func:
        if "Obfuscated Execution Routine (exec/eval + base64)" not in result.detections:
            result.detections.append("Obfuscated Execution Routine (exec/eval + base64)")
        if "obfuscated_loader_exec_pattern" not in result._hc_indicators:
            result._hc_indicators.append("obfuscated_loader_exec_pattern")
        if "obfuscated_loader_exec_pattern" not in result._co_indicators:
            result._co_indicators.append("obfuscated_loader_exec_pattern")
        if "Obfuscated Loader Pattern (exec/eval + base64)" not in result.script_findings:
            result.script_findings.append("Obfuscated Loader Pattern (exec/eval + base64)")

    # ── Windows Persistence & LotL Detection (reg add / schtasks / HKLM Run / certutil / wmic) ─
    has_persistence_lotl = bool(re.search(
        r"\breg(\.exe)?\s+add\b|\bschtasks(\.exe)?\b|\b(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\r\n]*\\Run\b|\bcertutil.*-(urlcache|decode)|\bwmic.*process|\bbitsadmin|\bnet\s+(user|localgroup)",
        active_text, re.I
    ))
    if has_persistence_lotl:
        if "Windows Persistence Mechanism (reg add / schtasks / HKLM Run)" not in result.detections:
            result.detections.append("Windows Persistence Mechanism (reg add / schtasks / HKLM Run)")
        if "windows_persistence_lotl" not in result._hc_indicators:
            result._hc_indicators.append("windows_persistence_lotl")
        if "windows_persistence_lotl" not in result._co_indicators:
            result._co_indicators.append("windows_persistence_lotl")
        if "Windows Persistence Mechanism: Registry Run Key modification (reg add) and/or Scheduled Task creation (schtasks)" not in result.script_findings:
            result.script_findings.append("Windows Persistence Mechanism: Registry Run Key modification (reg add) and/or Scheduled Task creation (schtasks)")

    # ── Line-by-Line Evidence Extraction for IOC Table ───────────────────────
    evidence_items = []
    for idx, line in enumerate(text.splitlines(), 1):
        line_clean = line.strip()
        if not line_clean or len(line_clean) > 400:
            continue
        if re.search(r"\b(reg(\.exe)?\s+add|schtasks|HKLM\\|HKCU\\|HKEY_LOCAL_MACHINE\\|HKEY_CURRENT_USER\\|certutil|wmic|bitsadmin|net\s+user|net\s+localgroup|eval|exec|compile|base64|b64decode|subprocess|os\.system)\b", line_clean, re.I):
            evidence_items.append(f"Line {idx}: {line_clean[:120]}")
    if evidence_items:
        iocs["Code Execution and Persistence Evidence"] = evidence_items[:15]

    # RULE 3 — Contextual PowerShell download (3-part gate)
    result.ps_download_contextual = _is_contextual_ps_download(text)
    if result.ps_download_contextual:
        iocs["PowerShell Download (contextual)"] = [
            "Confirmed: download function + URL + execution indicator in context"
        ]
        result.detections.append(
            "PowerShell download cradle with execution indicator detected"
        )
    else:
        if _PS_DOWNLOAD_FUNCTIONS.search(text):
            result.fp_notes.append(
                "PowerShell download function or alias (e.g. 'iwr') found "
                "but lacks URL + execution context — not scored. (RULE 3)"
            )

    result.iocs = iocs

    if "PowerShell Encoded" in iocs:
        result.detections.append("PowerShell encoded command detected")
    if "PowerShell Bypass" in iocs:
        result.detections.append("PowerShell execution policy bypass")
    if "Ngrok and Tunnels" in iocs:
        result.detections.append("Ngrok / reverse tunnel domain detected")
    if "Pastebin and Paste Sites" in iocs:
        result.detections.append("Paste-site URL detected (common C2 staging)")
    if "Crypto Wallet" in iocs:
        result.detections.append("Cryptocurrency wallet address found")
    if "Suspicious Keywords" in iocs:
        result.detections.append(
            f"Suspicious keywords: {', '.join(iocs['Suspicious Keywords'][:5])}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Stage 4 — Entropy & Packing Analysis  (RULE 1 & RULE 4)
# ─────────────────────────────────────────────────────────────────────────────

def analyze_entropy(
    file_bytes: bytes, ext: str, result: AdvancedHeuristicResult
) -> None:
    result.entropy = _entropy(file_bytes)

    # PE section entropy sub-scan
    if file_bytes[:2] == b"\x4d\x5a" and len(file_bytes) > 64:
        try:
            _pe_section_entropy(file_bytes, result)
        except Exception:
            pass

    # ── RULE 1 & 4: Office/compressed containers ─────────────────────────────
    # High entropy in these formats is structurally expected.
    # It NEVER contributes to the score on its own.
    if result.is_office_container or ext in INHERENTLY_COMPRESSED_EXTENSIONS:
        zone = _entropy_zone_label(result.entropy)
        result.entropy_context = (
            f"{result.entropy} — Normal for compressed/Office files "
            f"({result.file_classification or ext}). "
            f"High entropy here does NOT indicate obfuscation."
        )
        result.entropy_explanation = result.entropy_context
        result.fp_notes.append(
            f"Entropy {result.entropy} suppressed from scoring: "
            f"file is a {result.container_type or 'compressed format'} "
            f"(RULE 1/4)."
        )
        return

    # ── Determine file-type-appropriate threshold ─────────────────────────────
    text_formats = {".py", ".js", ".vbs", ".ps1", ".bat", ".txt", ".html", ".css", ".xml", ".csv", ".md", ".rst"}
    if ext in text_formats:
        if result.entropy > 5.0:
            result.entropy_context = (
                f"{result.entropy} — Elevated entropy for text format (>5.0). "
                f"Potential obfuscation/encoding concern."
            )
            result.detections.append(
                f"Elevated text entropy ({result.entropy} > 5.0) — potential obfuscated/encoded content concern"
            )
        else:
            result.entropy_context = (
                f"{result.entropy} — Within normal range for {ext or '.txt'}. No entropy concern."
            )
        result.entropy_explanation = result.entropy_context
        return

    if ext in {".exe", ".dll", ".bin", ".dat"}:
        high_thresh = 7.0
    else:
        high_thresh = 6.5

    zone = _entropy_zone_label(result.entropy)

    if result.entropy > high_thresh + 1.5:
        result.entropy_context = (
            f"{result.entropy} — Very high for {ext or 'this file type'}. "
            f"Possible encryption or packing. "
            f"{'Score boosted because other indicators also present.' if result._co_indicators else 'Score contribution is minimal without corroborating indicators. (RULE 4)'}"
        )
        result.detections.append(
            f"Very high entropy ({result.entropy}) for {ext or 'this file type'}"
        )
    elif result.entropy > high_thresh + 0.5:
        result.entropy_context = (
            f"{result.entropy} — Above normal for {ext or 'this file type'}. "
            f"Possible obfuscation. "
            f"{'Co-indicator present — score applied.' if result._co_indicators else 'Alone this is low confidence. (RULE 4)'}"
        )
        result.detections.append(
            f"Elevated entropy ({result.entropy}) — possible obfuscation"
        )
    else:
        result.entropy_context = (
            f"{result.entropy} — Within normal range for "
            f"{ext or 'this file type'}. No entropy concern."
        )

    result.entropy_explanation = result.entropy_context

    # Packer signatures
    packer_sigs = [
        b"UPX0", b"UPX1", b"UPX!", b"MPRESS", b"PECompact",
        b"ASPack", b"Themida", b"VMProtect", b"ExeStealth",
    ]
    for sig in packer_sigs:
        if sig in file_bytes:
            result.packed = True
            result.detections.append(
                f"Packer signature found: {sig.decode(errors='replace')}"
            )
            break


def _entropy_zone_label(entropy: float) -> str:
    if entropy > 7.5:  return "Encrypted/Packed"
    if entropy > 7.0:  return "Very High"
    if entropy > 6.5:  return "High"
    if entropy > 5.5:  return "Medium"
    return "Normal"


def _pe_section_entropy(file_bytes: bytes, result: AdvancedHeuristicResult) -> None:
    e_lfanew = struct.unpack_from("<I", file_bytes, 0x3C)[0]
    if e_lfanew + 24 > len(file_bytes):
        return
    if file_bytes[e_lfanew: e_lfanew + 4] != b"PE\x00\x00":
        return
    num_sections   = struct.unpack_from("<H", file_bytes, e_lfanew + 6)[0]
    opt_header_sz  = struct.unpack_from("<H", file_bytes, e_lfanew + 20)[0]
    section_offset = e_lfanew + 24 + opt_header_sz

    for i in range(min(num_sections, 96)):
        off = section_offset + i * 40
        if off + 40 > len(file_bytes):
            break
        name       = file_bytes[off: off + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        raw_size   = struct.unpack_from("<I", file_bytes, off + 16)[0]
        raw_offset = struct.unpack_from("<I", file_bytes, off + 20)[0]
        if raw_offset + raw_size > len(file_bytes) or raw_size == 0:
            continue
        sec_ent = _entropy(file_bytes[raw_offset: raw_offset + raw_size])
        result.section_entropies.append((name, sec_ent))
        if sec_ent > 7.2:
            result.detections.append(
                f"PE section '{name}' has very high entropy "
                f"({sec_ent}) — possible encrypted payload / shellcode"
            )


# ─────────────────────────────────────────────────────────────────────────────
# Stage 5 — PE Analysis
# ─────────────────────────────────────────────────────────────────────────────

def analyze_pe(file_bytes: bytes, result: AdvancedHeuristicResult) -> None:
    if file_bytes[:2] != b"\x4d\x5a":
        return
    try:
        text = file_bytes.decode("latin-1")
    except Exception:
        return

    inject_apis = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                   "NtCreateThreadEx", "QueueUserAPC"}
    debug_apis  = {"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                   "NtQueryInformationProcess"}
    cred_apis   = {"CryptUnprotectData", "LsaRetrievePrivateData"}
    ransom_apis = {"CryptEncrypt", "BCryptEncrypt"}

    found = [api for api in SUSPICIOUS_WINDOWS_APIS if api in text]
    result.imports        = found
    result.suspicious_apis = found

    if any(a in inject_apis for a in found):
        result.detections.append(
            "Process injection APIs: " +
            ", ".join(a for a in found if a in inject_apis)
        )
        result._co_indicators.append("process_injection_api")
    if any(a in debug_apis  for a in found):
        result.detections.append("Anti-debug APIs detected")
        result._co_indicators.append("anti_debug")
    if any(a in cred_apis   for a in found):
        result.detections.append("Credential-stealing APIs detected")
        result._co_indicators.append("credential_api")
    if any(a in ransom_apis for a in found):
        result.detections.append("Ransomware-related crypto APIs detected")
        result._co_indicators.append("ransomware_api")


# ─────────────────────────────────────────────────────────────────────────────
# Stage 6 — Script Analysis
# ─────────────────────────────────────────────────────────────────────────────

def analyze_script(
    file_path: str, file_bytes: bytes, result: AdvancedHeuristicResult
) -> None:
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in SCRIPT_EXTENSIONS:
        return
    try:
        text = file_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return

    active_text, fold_count = normalize_and_deobfuscate(text, ext)

    if fold_count > 0:
        result.script_findings.append("Deobfuscation: Statically folded obfuscated string/char primitives")
        result.detections.append(f"Deobfuscation Reconstruction: {fold_count} string/char primitive(s) folded")
        result._hc_indicators.append("obfuscation_reconstructed")
        result._co_indicators.append("obfuscation_reconstructed")

    # RULE 8 — check each pattern with context on active (non-comment) code
    for name, pattern in DANGEROUS_SCRIPT_PATTERNS.items():
        if pattern.search(active_text):
            result.script_findings.append(name)
            result.detections.append(f"Script: {name} detected")
            result._co_indicators.append(name)

    # Dynamic Execution via Variable argument (Execute(var), Eval(var), IEX $var)
    if re.search(r'\b(Execute|ExecuteGlobal|Eval)\s*\(\s*([a-zA-Z_]\w*)\s*\)', active_text, re.I):
        result.script_findings.append("Dynamic Execution via Variable (Execute/Eval)")
        result.detections.append("Script: Dynamic code execution via variable argument detected")
        result._hc_indicators.append("dynamic_exec_var")
        result._co_indicators.append("dynamic_exec_var")

    if re.search(r'\b(Invoke-Expression|IEX)\s+([\$a-zA-Z_]\w*)', active_text, re.I):
        result.script_findings.append("Dynamic Execution via Variable (IEX $var)")
        result.detections.append("PowerShell: Dynamic code execution via variable argument detected")
        result._hc_indicators.append("dynamic_exec_var")
        result._co_indicators.append("dynamic_exec_var")

    # Dangerous COM Object instantiation / reference
    com_match = re.search(r'\b(WScript\.Shell|Scripting\.FileSystemObject|MSXML2\.XMLHTTP|MSXML2\.ServerXMLHTTP|WinHttp\.WinHttpRequest|ADODB\.Stream|Shell\.Application|WScript\.Network)\b', active_text, re.I)
    if com_match:
        com_name = com_match.group(0)
        result.script_findings.append(f"Dangerous COM Object ({com_name})")
        result.detections.append(f"Script: Reference/instantiation of dangerous COM object '{com_name}'")
        result._hc_indicators.append("dangerous_com_objects")
        result._co_indicators.append("dangerous_com_objects")

    # LOLBins Abuse
    lolbin_match = re.search(r'\b(certutil(\.exe)?\s+(-urlcache|-decode|-f)|regsvr32(\.exe)?\s+/[snu]|mshta(\.exe)?\s+(http|javascript|vbscript)|bitsadmin(\.exe)?\s+/transfer|cscript(\.exe)?\s+//[be]|rundll32(\.exe)?\s+javascript)\b', active_text, re.I)
    if lolbin_match:
        result.script_findings.append(f"LOLBin Abuse ({lolbin_match.group(0)})")
        result.detections.append(f"Script: Living-off-the-land binary abuse detected ({lolbin_match.group(0)})")
        result._hc_indicators.append("lolbin_abuse")
        result._co_indicators.append("lolbin_abuse")

    # Taint / Staging Flow (Input / Read -> Execution sink within proximity)
    if re.search(r'\b(InputBox|ReadAll|ReadLine|RegRead|DownloadString|DownloadData|GetResponse)\b[\s\S]{1,300}\b(Execute|ExecuteGlobal|Invoke-Expression|IEX|eval|system|shell_exec)\b', active_text, re.I):
        result.script_findings.append("Taint Flow: Input/Read to Execution Sink")
        result.detections.append("Script: Tainted data flow from input/read source directly into execution sink")
        result._hc_indicators.append("taint_staging_flow")
        result._co_indicators.append("taint_staging_flow")

    # Heavy character-ratio obfuscation check (ignore very short files)
    if len(text) > 200:
        non_alpha = sum(1 for c in text if not c.isalpha() and not c.isspace())
        ratio     = non_alpha / len(text)
        if ratio > 0.45:
            result.script_findings.append("Heavy obfuscation (character ratio)")
            result.detections.append(
                f"Script obfuscation: {ratio:.0%} non-alpha characters"
            )
            result._co_indicators.append("obfuscated_script")

    for line in text.splitlines():
        if len(line) > 500:
            result.script_findings.append("Long single-line (obfuscation indicator)")
            result.detections.append(
                f"Suspiciously long line ({len(line)} chars) in script"
            )
            break


# ─────────────────────────────────────────────────────────────────────────────
# Stage 7 — Office-Specific Analysis
# ─────────────────────────────────────────────────────────────────────────────

def _is_safe_office_url(url: str) -> bool:
    """
    RULE 1 — Return True when a URL is a known-safe Office/W3C schema reference.
    These are namespace declarations and MUST never be flagged.
    """
    url_lower = url.lower()
    return any(url_lower.startswith(p.lower()) for p in OFFICE_SAFE_URL_PREFIXES)


def _line_is_namespace_decl(line: str) -> bool:
    """
    RULE 8 — Return True when the line is purely an XML namespace / metadata
    declaration that carries no executable semantics.
    """
    return any(p.search(line) for p in OFFICE_NAMESPACE_PATTERNS)


def _entry_is_vba_capable(entry_name: str) -> bool:
    """
    Return True only for ZIP entries that can physically contain VBA bytecode.
    RULE 3 — VBA execution patterns are only checked in these entries.
    """
    low = entry_name.lower()
    if "vbaproject" in low:
        return True
    if "macrosheets" in low:
        return True
    for sfx in (".xlsm", ".xlsb", ".docm", ".pptm", ".xlam"):
        if low.endswith(sfx):
            return True
    return False


def _scan_rels_entry(
    entry_name: str, text: str, result: AdvancedHeuristicResult
) -> None:
    """
    RULE 2 & 7 — Scan a .rels entry for genuinely external relationships.

    Only flags when:
      • TargetMode="External" is present on the SAME element as a non-schema URL, OR
      • Target points to a remote .dotm / .dot template, OR
      • Target is an external IP/domain that is not a safe schema prefix.

    Ignores xmlns / namespace lines entirely (RULE 8).
    """
    # Split into XML elements (each <Relationship … /> is one logical unit)
    elements = re.findall(r"<Relationship[^>]+>", text, re.I | re.S)
    if not elements:
        # Fall back to line-by-line for non-standard formatting
        elements = text.splitlines()

    for elem in elements:
        if _line_is_namespace_decl(elem):
            continue

        has_external_mode = bool(_RELS_EXTERNAL_MODE.search(elem))

        # Extract Target URL(s) from this element
        for m in _RELS_TARGET_URL.finditer(elem):
            raw_url = m.group(0)          # full match like Target="http://…"
            url     = m.group(1).strip()  # just the domain+path part

            if _is_safe_office_url("http://" + url) or _is_safe_office_url("https://" + url):
                # RULE 1 — whitelisted schema URL, always safe
                result.fp_notes.append(
                    f"Safe Office schema URL ignored in {entry_name}: {url[:80]}"
                )
                continue

            full_url = re.search(r"https?://[^\s\"'<>]+", raw_url)
            display_url = full_url.group(0) if full_url else url

            # Remote template injection (RULE 7)
            if _RELS_DOTM_TEMPLATE.search(elem):
                finding = OfficeFinding(
                    severity    = SEVERITY_HIGH,
                    category    = "Remote template reference",
                    source_file = entry_name,
                    detail      = f"Remote template URL: {display_url}",
                    confidence  = 80,
                    is_relation = True,
                )
                result.office_findings.append(finding)
                result.vba_findings.append(
                    f"[{entry_name}] Remote template reference: {display_url[:80]}"
                )
                result.detections.append(
                    f"Remote template reference in {entry_name}: {display_url[:80]}"
                )
                result._co_indicators.append("office_remote_template")
                continue

            # TargetMode=External + non-schema URL (RULE 2)
            if has_external_mode:
                finding = OfficeFinding(
                    severity    = SEVERITY_MEDIUM,
                    category    = "Office XML external relationship detected",
                    source_file = entry_name,
                    detail      = f"External relationship Target: {display_url}",
                    confidence  = 65,
                    is_relation = True,
                )
                result.office_findings.append(finding)
                result.vba_findings.append(
                    f"[{entry_name}] External Office relationship: {display_url[:80]}"
                )
                result.detections.append(
                    f"External Office relationship in {entry_name} "
                    f"(TargetMode=External): {display_url[:80]}"
                )
                result._co_indicators.append("office_external_rel")
            # else: internal Target URL with no External mode — not suspicious


def _scan_vba_entry(
    entry_name: str, text: str, result: AdvancedHeuristicResult
) -> None:
    """
    RULE 3 — Scan VBA-capable entries for real macro execution patterns.
    Labels findings as HIGH or CRITICAL, never INFO.
    RULE 4 — Uses the label "Office macro indicator" not "Office macro/feature".
    """
    for pattern_name, pattern in VBA_EXEC_PATTERNS.items():
        m = pattern.search(text)
        if not m:
            continue

        # Choose severity and confidence by pattern type
        if pattern_name in ("AutoOpen/AutoExec", "Shell Execution", "CreateObject",
                             "PowerShell via VBA", "CMD Execution", "DDE Abuse"):
            severity   = SEVERITY_CRITICAL if pattern_name in (
                "AutoOpen/AutoExec", "DDE Abuse") else SEVERITY_HIGH
            confidence = 90
        elif pattern_name in ("Download from URL", "Encoded/Obfuscated"):
            severity   = SEVERITY_HIGH
            confidence = 80
        else:
            severity   = SEVERITY_MEDIUM
            confidence = 65

        token = m.group(0)[:60]
        finding = OfficeFinding(
            severity    = severity,
            category    = f"VBA macro indicator: {pattern_name}",
            source_file = entry_name,
            detail      = f"Pattern '{pattern_name}' matched: {token!r}",
            confidence  = confidence,
            is_vba      = True,
        )
        result.office_findings.append(finding)

        # RULE 4 — do NOT use "Office macro/feature" label
        legacy_key = f"[{entry_name}] VBA: {pattern_name}"
        if legacy_key not in result.vba_findings:
            result.vba_findings.append(legacy_key)
            result.detections.append(
                f"VBA macro indicator [{severity}] in {entry_name}: "
                f"{pattern_name} — {token!r}"
            )
            result._co_indicators.append(
                f"vba_{pattern_name.lower().replace(' ', '_').replace('/', '_')}"
            )


def _scan_xml_for_external_urls(
    entry_name: str, text: str, result: AdvancedHeuristicResult
) -> None:
    """
    RULE 1 & 8 — Scan general XML content (not .rels) for live external URLs.
    Only flags URLs that are:
      • not safe schema prefixes
      • not inside xmlns= or namespace attribute
      • not inside XML comments
    Reports as INFO unless it looks like a download/C2 URL.
    """
    # Strip XML comments first so we don't flag commented-out URLs
    text_no_comments = re.sub(r"<!--.*?-->", "", text, flags=re.S)

    for m in re.finditer(r"https?://[^\s\"'<>&]{8,}", text_no_comments, re.I):
        url  = m.group(0)
        line = text_no_comments[max(0, m.start()-120): m.end()+120]

        # RULE 1 — skip safe schema domains
        if _is_safe_office_url(url):
            continue

        # RULE 8 — skip namespace / metadata declarations
        if _line_is_namespace_decl(line):
            continue

        # Is this URL in a suspicious context?
        suspicious_context = bool(re.search(
            r"(href|src|action|url|link|template|target|attachment|load|fetch|download|http-equiv)",
            line, re.I
        ))

        severity   = SEVERITY_MEDIUM if suspicious_context else SEVERITY_INFO
        confidence = 55 if suspicious_context else 25

        finding = OfficeFinding(
            severity    = severity,
            category    = "External URL in Office document",
            source_file = entry_name,
            detail      = f"URL: {url[:120]}",
            confidence  = confidence,
            is_relation = False,
        )
        result.office_findings.append(finding)

        if suspicious_context:
            result.vba_findings.append(
                f"[{entry_name}] External URL in suspicious context: {url[:80]}"
            )
            result.detections.append(
                f"External URL in Office XML [{severity}] "
                f"({entry_name}): {url[:80]}"
            )


def analyze_office(
    file_path: str, file_bytes: bytes, result: AdvancedHeuristicResult
) -> None:
    """
    v4 — Office-specific analysis with full false-positive reduction.

    Dispatch logic:
      .rels entries   → _scan_rels_entry()      (RULE 2 & 7)
      VBA-capable     → _scan_vba_entry()        (RULE 3)
      other XML       → _scan_xml_for_external_urls()  (RULE 1 & 8)

    RULE 10 — static analysis only; nothing is executed.
    """
    ext = os.path.splitext(file_path)[1].lower()

    # ── Office XML (ZIP-based) ────────────────────────────────────────────────
    if result.is_office_container and file_bytes[:4] == b"\x50\x4b\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zf:
                entry_names = {e.filename for e in zf.infolist()}

                # RULE 3 — detect presence of VBA project / macro sheets
                if any("vbaproject" in n.lower() for n in entry_names):
                    result.has_vba_project = True
                    result.detections.append(
                        "vbaProject.bin present — document contains VBA macros"
                    )
                    result._co_indicators.append("has_vba_project")
                if any("macrosheets" in n.lower() for n in entry_names):
                    result.has_macrosheet = True
                    result.detections.append(
                        "Excel macro sheet (xl/macrosheets/) present"
                    )
                    result._co_indicators.append("has_macrosheet")

                for entry in zf.infolist():
                    name = entry.filename
                    low  = name.lower()

                    # Only process text-based entries (RULE 10 — static only)
                    if not any(low.endswith(sfx) for sfx in (
                        ".xml", ".rels", ".vba", ".bin",
                        ".xlsm", ".xlsb", ".docm", ".pptm",
                    )):
                        continue

                    try:
                        raw  = zf.read(name)
                        text = raw.decode("utf-8", errors="ignore")
                    except Exception:
                        continue

                    if low.endswith(RELS_ENTRY_SUFFIX):
                        # RULE 2 & 7 — relationship scanner
                        _scan_rels_entry(name, text, result)
                    elif _entry_is_vba_capable(name):
                        # RULE 3 — real VBA execution scanner
                        _scan_vba_entry(name, text, result)
                    else:
                        # RULE 1 & 8 — general XML external URL scanner
                        _scan_xml_for_external_urls(name, text, result)

        except (zipfile.BadZipFile, RuntimeError) as exc:
            result.fp_notes.append(f"Could not open Office XML container: {exc}")

    # ── OLE / Legacy Office (.doc, .xls, .ppt) ───────────────────────────────
    elif result.is_ole_office:
        try:
            text = file_bytes.decode("latin-1", errors="ignore")
        except Exception:
            text = ""

        # VBA storage marker in raw OLE stream
        if b"VBA" in file_bytes or b"_VBA_PROJECT" in file_bytes:
            result.has_vba_project = True
            result.vba_findings.append("VBA macro storage detected in OLE document")
            result.detections.append(
                "VBA macro storage found in legacy Office document"
            )
            result._co_indicators.append("vba_macro")
            # Scan the text for real VBA execution patterns
            _scan_vba_entry("(OLE VBA stream)", text, result)
        else:
            # No VBA storage confirmed — only scan for external URLs (INFO level)
            _scan_xml_for_external_urls("(OLE stream)", text, result)

        # Embedded OLE objects
        if b"\x01\x00\x00\x00" in file_bytes and file_bytes[64:].find(b"\xd0\xcf\x11\xe0") != -1:
            result.ole_objects.append("Embedded OLE object detected")
            result.detections.append(
                "Embedded OLE object found — possible payload delivery"
            )


def _scan_text_for_vba(
    entry_name: str, text: str, result: AdvancedHeuristicResult
) -> None:
    """
    Legacy shim kept for OLE path / any callers outside analyze_office.
    Routes to the new v4 scanners based on entry type.
    RULE 4 — never uses the label 'Office macro/feature'.
    """
    if entry_name.lower().endswith(RELS_ENTRY_SUFFIX):
        _scan_rels_entry(entry_name, text, result)
    elif _entry_is_vba_capable(entry_name):
        _scan_vba_entry(entry_name, text, result)
    else:
        _scan_xml_for_external_urls(entry_name, text, result)


# ─────────────────────────────────────────────────────────────────────────────
# Stage 8 — Archive Analysis
# ─────────────────────────────────────────────────────────────────────────────

_SUSPICIOUS_ARCHIVE_NAMES = re.compile(
    r"\.(exe|dll|bat|cmd|vbs|ps1|js|scr|pif|com|lnk)$", re.I
)


def analyze_archive(file_bytes: bytes, result: AdvancedHeuristicResult) -> None:
    if file_bytes[:4] != b"\x50\x4b\x03\x04":
        return
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zf:
            # Office XML containers have their own dedicated analyzer
            if _is_office_xml_zip(zf) and result.is_office_container:
                result.fp_notes.append(
                    "Archive analysis skipped: Office XML container "
                    "(handled by Office-specific analyzer). (RULE 2)"
                )
                return

            entries = zf.infolist()
            has_suspicious_entry = False
            _IGNORED_DEV_DIRS = (".git/", "/.git/", ".github/", "/.github/", ".venv/", "/.venv/",
                                 "node_modules/", "/node_modules/", "__pycache__/", "/__pycache__/",
                                 ".idea/", "/.idea/", ".vscode/", "/.vscode/", ".pytest_cache/")
            for entry in entries:
                name = entry.filename
                normalized_name = name.replace("\\", "/")
                # Skip version control databases and package build artifacts
                if any(ignored in normalized_name or normalized_name.startswith(ignored.lstrip("/")) for ignored in _IGNORED_DEV_DIRS):
                    continue

                low_name = name.lower()

                if _SUSPICIOUS_ARCHIVE_NAMES.search(name):
                    has_suspicious_entry = True
                    result.archive_findings.append(
                        f"Suspicious file in archive: {name}"
                    )
                    result.detections.append(
                        f"Archive contains executable/script file: {name}"
                    )

                if low_name.endswith((".zip", ".rar", ".7z", ".gz", ".tar")):
                    result.nested_archives += 1

                if len(name.rsplit(".", 2)) >= 3:
                    result.archive_findings.append(
                        f"Double extension inside archive: {name}"
                    )

                try:
                    inner = zf.read(entry.filename)
                    entry_ext = os.path.splitext(entry.filename)[1].lower()
                    _SOURCE_EXTS = {".py", ".js", ".ts", ".rb", ".php", ".java", ".go", ".cs",
                                    ".cpp", ".c", ".h", ".rs", ".md", ".txt", ".json", ".html",
                                    ".css", ".xml", ".yml", ".yaml"}
                    # 1. Check for EICAR test signature inside archive entry (real EICAR is 68 bytes, max 500)
                    if entry_ext not in _SOURCE_EXTS and entry.file_size <= 500 and (b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in inner or b"X5O!P%@AP[4\\PZX54" in inner):
                        has_suspicious_entry = True
                        if "AV Test Signature" not in result.iocs:
                            result.iocs["AV Test Signature"] = ["EICAR test signature in " + name]
                        result.detections.append(f"Known AV test signature detected in archive entry: {name}")

                    # 2. Check for Validated PE inside archive
                    if _validate_pe_structure(inner, 0):
                        has_suspicious_entry = True
                        result.archive_findings.append(
                            f"Validated executable inside archive: {name}"
                        )
                        result.detections.append(
                            f"Validated executable hidden in archive: {name}"
                        )
                        # Check PE imports statically in memory
                        try:
                            text_pe = inner.decode("latin-1", errors="ignore")
                            inject_apis = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC"}
                            if any(a in text_pe for a in inject_apis):
                                result.detections.append(f"Process injection API found in archive PE '{name}'")
                                result._co_indicators.append("process_injection_api")
                        except Exception:
                            pass

                    # 3. Check for script files inside archive
                    script_exts = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".py", ".sh", ".hta", ".wsf"}
                    if any(low_name.endswith(sfx) for sfx in script_exts):
                        try:
                            inner_text = inner.decode("utf-8", errors="ignore")
                            inner_active = strip_comments_and_docstrings(inner_text)
                            if _is_contextual_ps_download(inner_text):
                                has_suspicious_entry = True
                                result.ps_download_contextual = True
                                result.detections.append(f"PowerShell download cradle with execution in archive: {name}")
                                result._co_indicators.append("powershell_download")

                            # Filter out regex rule definitions and test dictionaries in source code files
                            lines_to_check = []
                            for line in inner_active.splitlines():
                                stripped = line.strip()
                                if not stripped:
                                    continue
                                if entry_ext in {".py", ".js", ".ts"} and (
                                    "re.compile" in stripped
                                    or stripped.startswith('r"') or stripped.startswith("r'")
                                    or "pattern" in stripped.lower()
                                    or "regex" in stripped.lower()
                                    or "rule" in stripped.lower()
                                    or "signature" in stripped.lower()
                                    or (stripped.startswith('"') and (stripped.endswith('",') or stripped.endswith('":')))
                                    or (stripped.startswith("'") and (stripped.endswith("',") or stripped.endswith("':")))
                                ):
                                    continue
                                lines_to_check.append(line)
                            active_code_to_scan = "\n".join(lines_to_check)

                            # Check for Obfuscated Loader Pattern in script
                            has_exec_call = bool(re.search(r"\b(eval|exec|Invoke-Expression|iex)\b", active_code_to_scan, re.I))
                            has_b64_decode = bool(re.search(r"\b(FromBase64String|base64_decode|b64decode|base64\.b64decode)\b|-enc(odedcommand)?\b", active_code_to_scan, re.I))
                            if has_exec_call and has_b64_decode:
                                has_suspicious_entry = True
                                result.script_findings.append(f"[{name}] Obfuscated Loader Pattern (exec/eval + base64)")
                                result.detections.append(f"Obfuscated loader pattern detected in archive script: {name}")
                                result._co_indicators.append("obfuscated_loader_exec_pattern")
                                result._hc_indicators.append("obfuscated_loader_exec_pattern")

                            for s_name, s_pat in DANGEROUS_SCRIPT_PATTERNS.items():
                                if s_pat.search(active_code_to_scan):
                                    has_suspicious_entry = True
                                    result.script_findings.append(f"[{name}] {s_name}")
                                    result.detections.append(f"Script threat in {name}: {s_name}")
                                    result._co_indicators.append(s_name)
                            if re.search(r"\breg(\.exe)?\s+add\b|\bschtasks(\.exe)?\b|\b(HKLM|HKCU)\\[^\r\n]*\\Run\b", active_code_to_scan, re.I):
                                has_suspicious_entry = True
                                result.script_findings.append(f"[{name}] Windows Persistence Mechanism")
                                result.detections.append(f"Persistence commands detected in {name}")
                                result._co_indicators.append("windows_persistence_lotl")
                                result._hc_indicators.append("windows_persistence_lotl")
                        except Exception:
                            pass
                except Exception:
                    pass

            if result.nested_archives:
                result.detections.append(
                    f"Nested archives found: {result.nested_archives} level(s)"
                )

            if not has_suspicious_entry and not result.nested_archives and not result.password_protected:
                result.fp_notes.append(
                    "Archive contents inspected: all entries are standard non-executable documents or data files."
                )

    except zipfile.BadZipFile:
        pass
    except RuntimeError as exc:
        if "encrypted" in str(exc).lower() or "password" in str(exc).lower():
            result.password_protected = True
            result.detections.append("Password-protected archive detected")


# ─────────────────────────────────────────────────────────────────────────────
# Stage 9 — Scoring Engine  (RULE 1, 4, 6, 9, 10)
# ─────────────────────────────────────────────────────────────────────────────

def _check_reputation(file_bytes: bytes, result: AdvancedHeuristicResult) -> None:
    """
    Req. 6 — Reputation intelligence: scan string content for trusted vendor
    signatures and trusted-domain-only URL patterns.
    Applied before scoring so credits are included in the breakdown.
    """
    try:
        text = file_bytes.decode("latin-1", errors="ignore")
    except Exception:
        return

    # Trusted vendor string present in binary (e.g. version resource)
    for vendor in TRUSTED_VENDOR_STRINGS:
        if vendor in text:
            result.trusted_vendor = True
            result.reputation_credits.append(f"Trusted vendor string: {vendor}")
            result.whitelist_credits.append("trusted_vendor_signed")
            result.fp_notes.append(
                f"Trusted vendor signature found ({vendor}) — "
                "risk score reduced."
            )
            break   # one credit only

    # All URLs point to trusted domains only
    urls = result.iocs.get("URLs", [])
    if urls:
        all_trusted = all(
            any(td in u.lower() for td in TRUSTED_DOMAINS)
            for u in urls
        )
        if all_trusted:
            result.reputation_credits.append("All URLs resolve to trusted domains")
            result.whitelist_credits.append("trusted_domain_only")
            result.fp_notes.append(
                "All detected URLs point to trusted/academic domains — "
                "URL score suppressed."
            )


def _build_detection_summary(result: AdvancedHeuristicResult) -> dict:
    """
    Req. 8 — Build a structured, human-readable detection quality summary.
    Counts are broken out by category rather than giving a raw total.
    """
    iocs = result.iocs
    urls  = iocs.get("URLs", [])
    info_urls = [u for u in urls if any(td in u.lower() for td in TRUSTED_DOMAINS)]
    other_urls = [u for u in urls if u not in info_urls]

    vba_exec = [f for f in result.office_findings
                if f.is_vba and f.severity in (SEVERITY_HIGH, SEVERITY_CRITICAL)]
    vba_info = [f for f in result.office_findings if f.is_vba and f.severity not in
                (SEVERITY_HIGH, SEVERITY_CRITICAL)]
    rels     = [f for f in result.office_findings if f.is_relation]

    summary = {}

    # Informational items (never inflates score)
    if info_urls:
        summary["informational_hyperlinks"] = (
            f"{len(info_urls)} informational hyperlink(s) to trusted/academic domains"
        )
    if result.office_xml_validated:
        summary["office_structure"] = "valid Office XML structure confirmed"
    if result.is_office_container and not result.has_vba_project:
        summary["macros"] = "no macros found"
    if not result.embedded_executables:
        summary["executable_payload"] = "no executable payloads detected"
    if not result.script_findings:
        summary["scripts"] = "no suspicious scripts detected"
    if result.trusted_vendor:
        summary["reputation"] = (
            "trusted vendor signature present — " +
            (result.reputation_credits[0] if result.reputation_credits else "")
        )

    # Genuine findings
    if other_urls:
        summary["external_urls"] = f"{len(other_urls)} unknown external URL(s)"
    if result.embedded_executables:
        summary["embedded_exe"] = (
            f"{len(result.embedded_executables)} validated embedded executable(s)"
        )
    if result.has_vba_project and not vba_exec:
        summary["vba_present"] = "VBA macro project present — no execution patterns"
    if vba_exec:
        summary["vba_execution"] = (
            f"{len(vba_exec)} VBA execution indicator(s): " +
            ", ".join(f.category for f in vba_exec[:3])
        )
    if rels:
        summary["external_relationships"] = (
            f"{len(rels)} external Office relationship(s)"
        )
    if result.ps_download_contextual:
        summary["ps_download"] = (
            "PowerShell download cradle confirmed (download + URL + execution)"
        )
    if result.script_findings:
        summary["script_findings"] = (
            f"{len(result.script_findings)} script finding(s): " +
            ", ".join(result.script_findings[:4])
        )
    if result.packed:
        summary["packing"] = "packer signature detected"
    if "AV Test Signature" in result.iocs:
        summary["av_signature"] = "known AV test signature (EICAR or equivalent)"

    # Re-order: threat findings first, informational/safe second.
    # This ensures the UI headline matches the risk level.
    THREAT_KEYS = ("av_signature", "embedded_exe", "vba_execution", "ps_download",
                   "script_findings", "external_urls", "external_relationships",
                   "vba_present", "packing")
    SAFE_KEYS   = ("office_structure", "macros", "executable_payload", "scripts",
                   "reputation", "informational_hyperlinks")
    ordered: dict = {}
    for k in THREAT_KEYS:
        if k in summary:
            ordered[k] = summary[k]
    for k in SAFE_KEYS:
        if k in summary:
            ordered[k] = summary[k]
    # anything else
    for k, v in summary.items():
        if k not in ordered:
            ordered[k] = v
    return ordered


def calculate_score(result: AdvancedHeuristicResult, file_bytes: bytes = b"") -> None:  # noqa: C901
    """
    v5 — Context-aware, tiered scoring engine.

    Key behavioural changes from v4:
      • Weights mapped to 5 tiers matching professional AV/EDR thresholds
      • Correlation bonuses: weak indicators only matter when combined
      • Office docs with no macros/scripts cap out at LOW RISK
      • Reputation credits applied before final score clamp
      • Confidence is derived from evidence quality, not raw score
      • Detection summary replaces inflated raw counts
    """
    # Reputation check needs bytes — pass them through when available
    if file_bytes:
        _check_reputation(file_bytes, result)

    score     = 0
    breakdown = {}
    hc_count  = 0

    def add(key: str, pts: int | None = None, high_confidence: bool = False) -> int:
        nonlocal hc_count
        w = pts if pts is not None else SCORE_WEIGHTS.get(key, 0)
        if w > 0:
            breakdown[key] = breakdown.get(key, 0) + w
        if high_confidence and key in HIGH_CONFIDENCE_INDICATORS:
            if key not in result._hc_indicators:
                result._hc_indicators.append(key)
            hc_count += 1
        return w

    def credit(key: str) -> int:
        w = SCORE_WEIGHTS.get(key, 0)
        if w != 0:
            breakdown[key] = breakdown.get(key, 0) + w
        return w

    # ── File type ─────────────────────────────────────────────────────────────
    if result.fake_extension:
        score += add("fake_extension", high_confidence=True)
    if result.double_extension:
        score += add("double_extension")
    if result.renamed_executable:
        score += add("renamed_executable", high_confidence=True)

    # ── Embedded / polyglot ───────────────────────────────────────────────────
    if result.embedded_executables:
        score += add("validated_embedded_pe", high_confidence=True)
    elif result.candidate_pes and not result.is_office_container:
        # Unvalidated MZ bytes: small contribution, capped at 1 hit
        score += add("embedded_pe_unvalidated")

    if result.embedded_archives and not result.is_office_container:
        score += add("embedded_archive")

    if result.appended_payload:
        score += add("appended_payload", high_confidence=True)
    if result.polyglot:
        score += add("polyglot_file", high_confidence=True)
    if result.packed:
        score += add("packed_executable")

    # ── Entropy ───────────────────────────────────────────────────────────────
    # Req. 5 — entropy only scored for EXE/DLL/JS/VBS/PS1 families
    if not result.is_office_container and result.claimed_extension not in INHERENTLY_COMPRESSED_EXTENSIONS:
        has_coind = bool(result._co_indicators)
        if result.entropy > 7.5:
            if has_coind:
                score += add("very_high_entropy_with_coind")
            else:
                score += add("very_high_entropy_alone")
                result.fp_notes.append(
                    f"Entropy {result.entropy} is very high but no corroborating "
                    "indicators found — minimal score contribution."
                )
        elif result.entropy > 6.8 and has_coind:
            score += add("high_entropy_with_coind")

    # ── Req. 4 — Clean Container Caps (Office & Generic ZIP) ─────────────────
    # A clean Office document (no macros, no scripts, no PE) must stay in Benign/Low (<= 15).
    is_clean_office = (
        result.is_office_container
        and result.office_xml_validated
        and not result.has_vba_project
        and not result.has_macrosheet
        and not result.embedded_executables
        and not result.script_findings
        and not result.vba_findings
        and not result.packed
    )
    if is_clean_office:
        pre_cap = min(score, 100)
        if pre_cap > 15:
            score = 15
            breakdown["office_clean_doc_cap"] = -(pre_cap - 15)
            result.fp_notes.append(
                f"Score capped at 15 (Benign): clean Office document — "
                f"no macros, scripts, or executable content. "
                f"Original score was {pre_cap}."
            )

    # A clean ZIP archive (with only standard non-executable documents/data) must stay in Benign (<= 15).
    is_clean_zip = (
        (result.claimed_extension == ".zip" or result.detected_type == "ZIP Archive")
        and not result.is_office_container
        and not result.embedded_executables
        and not result.script_findings
        and not result.archive_findings
        and not result.password_protected
        and not result.nested_archives
        and not result.ps_download_contextual
        and "AV Test Signature" not in result.iocs
    )
    if is_clean_zip:
        pre_cap = min(score, 100)
        if pre_cap > 15:
            score = 15
            breakdown["zip_clean_container_cap"] = -(pre_cap - 15)
            result.fp_notes.append(
                f"Score capped at 15 (Benign): clean ZIP archive — "
                f"no executable, script, or persistence payloads inside container. "
                f"Original score was {pre_cap}."
            )

    # ── IOCs ──────────────────────────────────────────────────────────────────
    iocs = result.iocs
    if "PowerShell Encoded" in iocs:
        score += add("powershell_encoded", high_confidence=True)
    if "PowerShell Bypass" in iocs:
        score += add("powershell_bypass")
    if result.ps_download_contextual:
        score += add("powershell_download", high_confidence=True)
        result._co_indicators.append("powershell_download")
    if "Ngrok / Tunnels" in iocs:
        score += add("ngrok_tunnel", high_confidence=True)
    if "Pastebin / Paste Sites" in iocs:
        score += add("paste_site")
    if "Crypto Wallet" in iocs:
        score += add("crypto_wallet")
    if "API Keys / Tokens" in iocs:
        score += add("api_key_exposed")
    if "Suspicious Keywords" in iocs:
        score += add("suspicious_keyword")
    if "AV Test Signature" in iocs:
        score += add("av_test_signature", high_confidence=True)
        result._co_indicators.append("av_test_signature")
        if "Known AV test signature detected (EICAR or equivalent)" not in result.detections:
            result.detections.append("Known AV test signature detected (EICAR or equivalent)")

    # Passive markup formats (HTML/CSS/TXT/JSON/XML/SVG) treat URLs as structural content,
    # not as IOCs. Suppressing URL/IP scoring for these file types prevents false positives
    # on files that legitimately link to CDN resources, stylesheets, or documentation.
    _PASSIVE_MARKUP_EXTS = {".html", ".htm", ".css", ".txt", ".json", ".xml", ".svg", ".md", ".rst", ".csv", ".tsv", ".log"}
    _is_passive_markup = result.claimed_extension in _PASSIVE_MARKUP_EXTS

    # Req. 4 — URL scoring: only add points when NOT all-trusted-domain AND not passive markup
    # Trusted-domain credit is applied via whitelist_credits below.
    urls = iocs.get("URLs", [])
    untrusted_urls = [u for u in urls
                      if not any(td in u.lower() for td in TRUSTED_DOMAINS)]
    if untrusted_urls and not _is_passive_markup:
        # Cap at 3 hits, each worth suspicious_url weight
        score += add("suspicious_url", min(len(untrusted_urls), 3))
    elif urls:
        # All URLs are trusted (or file is passive markup) — informational, no score
        result.fp_notes.append(
            f"{len(urls)} URL(s) detected but scored 0 — "
            + ("passive markup file type" if _is_passive_markup else "all resolve to trusted domains")
            + " (not scored)."
        )

    if "IP Addresses" in iocs and not _is_passive_markup:
        score += add("suspicious_ip", min(len(iocs["IP Addresses"]), 3))

    # ── PE / APIs ─────────────────────────────────────────────────────────────
    inject_apis = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                   "NtCreateThreadEx", "QueueUserAPC"}
    debug_apis  = {"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                   "NtQueryInformationProcess"}
    cred_apis   = {"CryptUnprotectData", "LsaRetrievePrivateData"}
    ransom_apis = {"CryptEncrypt", "BCryptEncrypt"}

    if any(a in inject_apis for a in result.suspicious_apis):
        score += add("process_injection_api", high_confidence=True)
    if any(a in debug_apis  for a in result.suspicious_apis):
        score += add("anti_debug")
    if any(a in cred_apis   for a in result.suspicious_apis):
        score += add("credential_api", high_confidence=True)
    if any(a in ransom_apis for a in result.suspicious_apis):
        score += add("ransomware_api", high_confidence=True)
    # Generic API hit — only if not already counted by a specific category
    other_apis = [a for a in result.suspicious_apis
                  if a not in inject_apis | debug_apis | cred_apis | ransom_apis]
    if other_apis:
        score += add("suspicious_api")

    # ── Script findings ───────────────────────────────────────────────────────
    sf = result.script_findings
    if any(s == "Invoke-Expression" or s.endswith("] Invoke-Expression") for s in sf): score += add("iex_usage",   high_confidence=True)
    if any("Obfuscated Loader Pattern" in s for s in sf): score += add("obfuscated_loader_exec_pattern", high_confidence=True)
    if any(s == "AMSI Bypass" or s.endswith("] AMSI Bypass") for s in sf): score += add("amsi_bypass", high_confidence=True)
    if any(s == "UAC Bypass" or s.endswith("] UAC Bypass") for s in sf): score += add("uac_bypass",  high_confidence=True)
    if any(s == "Scheduled Task" or s.endswith("] Scheduled Task") for s in sf): score += add("scheduled_task")
    if any(s == "WMI Execution" or s.endswith("] WMI Execution") for s in sf): score += add("wmi_execution")
    if any(s == "Windows Persistence Mechanism" or s.endswith("] Windows Persistence Mechanism") for s in sf): score += add("windows_persistence_lotl", high_confidence=True)
    if any("PHP Shell Execution" in s for s in sf): score += add("obfuscated_loader_exec_pattern", high_confidence=True)
    if any("PHP Eval Obfuscation" in s for s in sf): score += add("obfuscated_loader_exec_pattern", high_confidence=True)
    if any("Shadow Copy Deletion" in s for s in sf): score += add("ransomware_api", high_confidence=True)
    if any("Dynamic Execution via Variable" in s for s in sf): score += add("dynamic_exec_var", high_confidence=True)
    if any("Dangerous COM Object" in s for s in sf): score += add("dangerous_com_objects", high_confidence=True)
    if any("LOLBin Abuse" in s for s in sf): score += add("lolbin_abuse", high_confidence=True)
    if any("Taint Flow" in s for s in sf): score += add("taint_staging_flow", high_confidence=True)
    if any("Deobfuscation" in s for s in sf): score += add("obfuscation_reconstructed", high_confidence=True)
    # ── New patterns added for universal extension support ─────────────────────
    if any("AutoRun INF Dropper" in s for s in sf): score += add("lolbin_abuse", high_confidence=True)
    if any("SQL Injection Pattern" in s for s in sf): score += add("suspicious_keyword", high_confidence=True)
    if any("VBE Encoded Script" in s for s in sf): score += add("obfuscation_reconstructed", high_confidence=True)
    if any("Persistence Registry Run Key" in s for s in sf): score += add("windows_persistence_lotl", high_confidence=True)
    if any("PowerShell Download Cradle" in s for s in sf): score += add("powershell_download", high_confidence=True)


    # ── VBA / OLE ─────────────────────────────────────────────────────────────
    _seen_office_keys: set = set()
    for of in result.office_findings:
        if of.severity == SEVERITY_INFO:
            continue
        if of.is_vba:
            cat = of.category
            if "AutoOpen" in cat or "AutoExec" in cat:
                k = "vba_auto_exec"
                if k not in _seen_office_keys:
                    score += add(k, high_confidence=True); _seen_office_keys.add(k)
            if "Shell Execution" in cat:
                k = "vba_shell"
                if k not in _seen_office_keys:
                    score += add(k, high_confidence=True); _seen_office_keys.add(k)
            if "Download" in cat:
                k = "vba_download"
                if k not in _seen_office_keys:
                    score += add(k, high_confidence=True); _seen_office_keys.add(k)
            if "Filesystem" in cat or "Write" in cat:
                k = "vba_write_fs"
                if k not in _seen_office_keys:
                    score += add(k); _seen_office_keys.add(k)
            if "PowerShell" in cat:
                k = "vba_powershell"
                if k not in _seen_office_keys:
                    score += add(k, high_confidence=True); _seen_office_keys.add(k)
            if "CMD" in cat or "cmd" in cat:
                k = "vba_cmd_exec"
                if k not in _seen_office_keys:
                    score += add(k, high_confidence=True); _seen_office_keys.add(k)
            if "CreateObject" in cat:
                k = "vba_create_object"
                if k not in _seen_office_keys:
                    score += add(k); _seen_office_keys.add(k)
            if "Encoded" in cat or "Obfuscated" in cat:
                k = "vba_encoded"
                if k not in _seen_office_keys:
                    score += add(k); _seen_office_keys.add(k)
            if "DDE" in cat:
                k = "vba_dde"
                if k not in _seen_office_keys:
                    score += add(k, high_confidence=True); _seen_office_keys.add(k)
        elif of.is_relation:
            if of.severity == SEVERITY_HIGH:
                k = "office_remote_template"
                if k not in _seen_office_keys:
                    score += add(k); _seen_office_keys.add(k)
            elif of.severity == SEVERITY_MEDIUM:
                k = "office_external_rel"
                if k not in _seen_office_keys:
                    score += add(k); _seen_office_keys.add(k)
            else:
                k = "office_ext_relationship"
                if k not in _seen_office_keys:
                    score += add(k); _seen_office_keys.add(k)
        else:
            if of.severity == SEVERITY_MEDIUM:
                k = "office_ext_relationship"
                if k not in _seen_office_keys:
                    score += add(k); _seen_office_keys.add(k)

    # VBA structural presence — only medium weight, not high confidence
    if result.has_vba_project and "has_vba_project" not in _seen_office_keys:
        score += add("suspicious_keyword"); _seen_office_keys.add("has_vba_project")
    if result.has_macrosheet and "has_macrosheet" not in _seen_office_keys:
        score += add("suspicious_keyword"); _seen_office_keys.add("has_macrosheet")

    # ── Archive ───────────────────────────────────────────────────────────────
    if result.password_protected:
        score += add("password_protected_zip")
    if result.nested_archives:
        score += add("nested_archive", min(result.nested_archives, 3))
    if result.archive_findings:
        score += add("suspicious_archive_entry", min(len(result.archive_findings), 3))

    # ── Req. 4 — Office document cap ─────────────────────────────────────────
    # A clean Office document (no macros, no scripts, no PE) must stay LOW.
    is_clean_office = (
        result.is_office_container
        and result.office_xml_validated
        and not result.has_vba_project
        and not result.has_macrosheet
        and not result.embedded_executables
        and not result.script_findings
        and not result.vba_findings
        and not result.packed
    )
    if is_clean_office:
        pre_cap = min(score, 100)
        if pre_cap > 15:
            score = 15
            breakdown["office_clean_doc_cap"] = -(pre_cap - 15)
            result.fp_notes.append(
                f"Score capped at 15 (LOW RISK): clean Office document — "
                f"no macros, scripts, or executable content. "
                f"Original score was {pre_cap}."
            )

    # ── Req. 6 — Reputation credits ───────────────────────────────────────────
    for wl_key in result.whitelist_credits:
        score += credit(wl_key)

    # ── Req. 3 — Correlation bonus ────────────────────────────────────────────
    # Weak indicators together push score up; strong ones are already high.
    # Correlation: PS download + obfuscation → bonus
    if result.ps_download_contextual and "Invoke-Expression" in result.script_findings:
        bonus = 15
        score += bonus
        breakdown["correlation_ps_download_iex"] = bonus
        result._co_indicators.append("correlation_ps_download_iex")

    # Correlation: encoded PS + download cradle → bonus
    if "PowerShell Encoded" in iocs and result.ps_download_contextual:
        bonus = 10
        score += bonus
        breakdown["correlation_enc_ps_download"] = bonus

    # Correlation: multiple API categories → process injection is more certain
    api_categories_hit = sum([
        any(a in inject_apis for a in result.suspicious_apis),
        any(a in debug_apis  for a in result.suspicious_apis),
        any(a in cred_apis   for a in result.suspicious_apis),
    ])
    if api_categories_hit >= 2:
        bonus = 12
        score += bonus
        breakdown["correlation_multi_api"] = bonus

    # ── Req. 7 — Confidence gate: Malicious requires ≥2 HC indicators ────────
    # EXCEPTION: certain single indicators are inherently definitive:
    #   • av_test_signature (EICAR)           — industry-standard malware marker
    #   • polyglot_file                       — structurally impossible to be innocent
    #   • appended_payload                    — data after EOF is never accidental
    #   • obfuscated_loader_exec_pattern      — exec/eval + base64/encoding loader routine
    # These bypass the ≥2 gate and always reach Malicious.
    SINGLE_INDICATOR_CRITICAL = {
        "av_test_signature", "polyglot_file", "appended_payload",
        "obfuscated_loader_exec_pattern", "windows_persistence_lotl",
        "dynamic_exec_var", "lolbin_abuse", "taint_staging_flow", "iex_usage"
    }
    is_single_critical = bool(set(result._hc_indicators) & SINGLE_INDICATOR_CRITICAL)

    if "obfuscated_loader_exec_pattern" in result._hc_indicators:
        score = max(score, 95)

    if "windows_persistence_lotl" in result._hc_indicators:
        score = max(score, 85)

    if "dynamic_exec_var" in result._hc_indicators or "lolbin_abuse" in result._hc_indicators or "taint_staging_flow" in result._hc_indicators:
        score = max(score, 85)

    if "iex_usage" in result._hc_indicators and "powershell_download" in result._hc_indicators:
        score = max(score, 95)
    elif "iex_usage" in result._hc_indicators:
        score = max(score, 85)

    raw_score = max(0, min(score, 100))
    if raw_score >= 75 and hc_count < 2 and not is_single_critical:
        score = max(raw_score - 15, 60)
        breakdown["insufficient_evidence"] = -(raw_score - score)
        result.fp_notes.append(
            "Score reduced: fewer than 2 high-confidence indicators — "
            "preventing false-positive Malicious verdict."
        )

    result.score           = max(0, min(score, 100))
    result.score_breakdown = breakdown

    # ── 5-Tier Classification thresholds ───────────────────────────────────
    # 0–15 = Benign, 16–35 = Low, 36–55 = Medium,
    # 56–80 = High, 81–100 = Critical
    s = result.score
    if s >= 81 and (hc_count >= 2 or is_single_critical):
        result.threat_level = "Critical"
        result.confidence   = min(90 + hc_count * 2, 99)
    elif s >= 56:
        result.threat_level = "High"
        result.confidence   = 75 + min(len(result._co_indicators) * 3, 20)
    elif s >= 36:
        result.threat_level = "Medium"
        result.confidence   = 60 + min(len(result.detections) * 2, 25)
    elif s >= 16:
        result.threat_level = "Low"
        result.confidence   = 45 + min(len(result.detections) * 4, 30)
    else:
        result.threat_level = "Benign"
        result.confidence   = max(92 - s * 3, 55)

    # Req. 7 — Confidence tier: quality of evidence, not raw score
    entropy_only = (
        result.entropy > 6.8
        and not result._co_indicators
        and not result.vba_findings
        and not result.script_findings
        and not result.embedded_executables
    )
    if entropy_only:
        result.confidence      = min(result.confidence, 40)
        result.confidence_tier = "LOW"
        result.fp_notes.append(
            "Confidence capped: entropy is the only elevated indicator."
        )
    elif hc_count >= 2 or is_single_critical:
        result.confidence_tier = "HIGH"
    elif hc_count == 1 or len(result._co_indicators) >= 2:
        result.confidence_tier = "MEDIUM"
    else:
        result.confidence_tier = "LOW"

    # Req. 8 — Build structured detection summary
    result.detection_summary = _build_detection_summary(result)

    # Req. 8 — Human-readable explanation
    result.risk_explanation = _build_risk_explanation(result)
    result.final_verdict    = _build_final_verdict(result)

    if result.detections:
        top = result.detections[:3]
        result.explanation = (
            f"Threat level '{result.threat_level}' (score {result.score}/100, "
            f"confidence {result.confidence_tier}). "
            f"Top findings: {'; '.join(top)}."
        )
    elif result.fp_notes:
        result.explanation = (
            f"No significant threats (score {result.score}/100). "
            f"Note: {result.fp_notes[0]}"
        )
    else:
        result.explanation = "No significant threats detected. File appears benign."


def _build_risk_explanation(r: AdvancedHeuristicResult) -> str:
    """Req. 8 — Plain-English explanation strictly based on detected evidence."""
    parts: list[str] = []

    # Lead with critical detections if present
    critical_hits = [d for d in r.detections if any(k in d for k in ["Obfuscated Execution", "Code Execution", "EICAR", "Executable payload", "PowerShell download", "Polyglot", "Windows Persistence"])]
    if any("Windows Persistence" in d for d in r.detections):
        parts.append(
            "⚠️ CRITICAL: Windows persistence mechanisms detected. Includes Registry Run Key modification (reg add HKLM\\...\\Run) and Scheduled Task creation (schtasks). "
            "These are standard techniques used by malware to maintain access after reboot. Even if the file claims to be 'patterns only,' the commands are live and dangerous."
        )
    elif critical_hits:
        for hit in critical_hits[:2]:
            parts.append(f"[CRITICAL WARNING] {hit}.")

    if r.is_office_container and r.office_xml_validated:
        parts.append(
            f"File is a structurally valid {r.file_classification}."
        )
    elif r.is_office_container:
        parts.append(
            "File has an Office extension but failed structural validation."
        )

    # Threat findings FIRST so the explanation headline matches the verdict
    ds = r.detection_summary
    for key in ("av_signature", "embedded_exe", "vba_execution", "ps_download",
                "script_findings", "packing", "external_urls",
                "external_relationships", "vba_present"):
        if key in ds and not any(ds[key] in p for p in parts):
            parts.append(ds[key] + ".")

    # Safe / informational observations follow
    if "reputation" in ds:
        parts.append(ds["reputation"] + ".")
    if "office_structure" in ds:
        parts.append(ds["office_structure"] + ".")
    if "macros" in ds and r.threat_level in ("Benign", "Low Risk"):
        parts.append(ds["macros"] + ".")
    if "executable_payload" in ds and r.threat_level in ("Benign", "Low Risk") and not critical_hits:
        parts.append(ds["executable_payload"] + ".")
    if "scripts" in ds and r.threat_level in ("Benign", "Low Risk") and not critical_hits:
        parts.append(ds["scripts"] + ".")
    if "informational_hyperlinks" in ds:
        parts.append(ds["informational_hyperlinks"] + ".")

    if r.entropy_context:
        parts.append(f"Entropy: {r.entropy_context}")

    if not parts:
        if r.score < 16:
            parts.append("No suspicious indicators detected across all analysis stages.")
        else:
            parts.append(
                f"Some indicators found (score {r.score}/100) — no single definitive signal."
            )

    return " ".join(parts)


def _build_final_verdict(r: AdvancedHeuristicResult) -> str:
    """Req. 8 — One-liner verdict for the UI header."""
    classification = (
        r.file_classification or r.detected_type
        or r.claimed_extension.lstrip(".").upper() or "Unknown"
    )
    if r.is_office_container or r.claimed_extension in INHERENTLY_COMPRESSED_EXTENSIONS:
        ent_note = f" | Entropy: {r.entropy} (Normal for {classification})"
    elif r.entropy > 7.0:
        ent_note = f" | Entropy: {r.entropy} ({_entropy_zone_label(r.entropy)})"
    else:
        ent_note = f" | Entropy: {r.entropy} (Normal)"

    return (
        f"File Type: {classification} | "
        f"Container: {r.container_type or 'N/A'}"
        f"{ent_note} | "
        f"Risk: {r.threat_level} | "
        f"Confidence: {r.confidence_tier}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def run_advanced_heuristics(file_path: str, file_bytes: bytes) -> dict:
    """
    Main entry point.  Returns a plain dict for JSON serialisation and DB storage.
    RULE 10 — all signal categories always run; verdict is multi-signal.
    """
    result = AdvancedHeuristicResult()
    ext    = os.path.splitext(file_path)[1].lower()

    stages = [
        ("file_type",        lambda: analyze_file_type(file_path, file_bytes, result)),
        ("embedded_content", lambda: analyze_embedded_content(file_bytes, result)),
        ("strings",          lambda: analyze_strings(file_bytes, result)),
        # entropy runs after PE/script so co-indicators are populated
        ("pe",               lambda: analyze_pe(file_bytes, result)),
        ("script",           lambda: analyze_script(file_path, file_bytes, result)),
        ("office",           lambda: analyze_office(file_path, file_bytes, result)),
        ("entropy",          lambda: analyze_entropy(file_bytes, ext, result)),
        ("archive",          lambda: analyze_archive(file_bytes, result)),
    ]

    for name, fn in stages:
        try:
            fn()
        except Exception as exc:
            logger.warning("advanced_heuristics stage '%s' error: %s", name, exc)

    calculate_score(result, file_bytes)

    return {
        # File type / classification (RULE 7)
        "detected_type":          result.detected_type,
        "file_classification":    result.file_classification,
        "container_type":         result.container_type,
        "claimed_extension":      result.claimed_extension,
        "type_mismatch":          result.type_mismatch,
        "fake_extension":         result.fake_extension,
        "double_extension":       result.double_extension,
        "renamed_executable":     result.renamed_executable,
        "is_office_container":    result.is_office_container,
        "is_ole_office":          result.is_ole_office,
        "office_xml_validated":   result.office_xml_validated,   # RULE 5

        # Embedded / polyglot
        "embedded_executables":   result.embedded_executables,
        "candidate_pes":          result.candidate_pes,
        "embedded_archives":      result.embedded_archives,
        "appended_payload":       result.appended_payload,
        "polyglot":               result.polyglot,

        # IOCs (RULE 3)
        "iocs":                        result.iocs,
        "ps_download_contextual":      result.ps_download_contextual,

        # PE
        "suspicious_apis":        result.suspicious_apis,
        "script_findings":        result.script_findings,
        "section_entropies":      result.section_entropies,
        "imports":                result.imports,
        "entry_point_anomaly":    result.entry_point_anomaly,

        # VBA / OLE — structured findings (v4) + legacy compat list
        "vba_findings":           result.vba_findings,
        "ole_objects":            result.ole_objects,
        "has_vba_project":        result.has_vba_project,
        "has_macrosheet":         result.has_macrosheet,
        # RULE 9 — enriched structured findings for template rendering
        "office_findings": [
            {
                "severity":    f.severity,
                "category":    f.category,
                "source_file": f.source_file,
                "detail":      f.detail,
                "confidence":  f.confidence,
                "is_vba":      f.is_vba,
                "is_relation": f.is_relation,
            }
            for f in result.office_findings
        ],

        # Entropy (RULE 4 / 7)
        "entropy":                result.entropy,
        "entropy_context":        result.entropy_context,
        "entropy_explanation":    result.entropy_explanation,
        "entropy_co_indicator":   bool(result._co_indicators),
        "packed":                 result.packed,

        # Archive
        "archive_findings":       result.archive_findings,
        "nested_archives":        result.nested_archives,
        "password_protected":     result.password_protected,

        # Score / verdict (RULE 6 & 10)
        "score":                  result.score,
        "score_breakdown":        result.score_breakdown,
        "threat_level":           result.threat_level,
        "confidence":             result.confidence,
        "confidence_tier":        result.confidence_tier,
        "explanation":            result.explanation,
        "risk_explanation":       result.risk_explanation,   # RULE 7
        "final_verdict":          result.final_verdict,      # RULE 7

        # Detections / FP notes
        "detections":             result.detections,
        "fp_notes":               result.fp_notes,
        "hc_indicators":          result._hc_indicators,
        "co_indicators":          result._co_indicators,

        # Req. 6 — reputation
        "trusted_vendor":         result.trusted_vendor,
        "reputation_credits":     result.reputation_credits,

        # Whitelist credits applied
        "whitelist_credits":      result.whitelist_credits,

        # Req. 8 — structured detection summary
        "detection_summary":      result.detection_summary,

        # Depth control & grounding
        "encoding_layers":        result.encoding_layers,
        "decoded_size":           result.decoded_size,
        "decoded_detections":     result.decoded_detections,
        "intent_classification":  result.intent_classification,
        "indicator_grounding":    result.indicator_grounding,
    }