"""
ai_analysis.py — Smart Malware Analysis Engine using Google Gemini API
Falls back to a local heuristic rule-based engine if the API key is not configured or fails.
"""
import os
import requests
import json
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

def analyze_file_ai(entropy, patterns, imports, risk_score):
    """
    Analyze a file using Google Gemini API. Falls back to local rules if not set or offline.
    """
    if GEMINI_API_KEY:
        try:
            # Clean inputs
            ent_val = float(entropy or 0)
            risk_val = int(risk_score or 0)
            pat_val = str(patterns or "")
            imp_val = str(imports or "")

            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash:generateContent?key={GEMINI_API_KEY}"
            
            prompt = (
                f"Analyze this file for potential malware threats based on static analysis metadata:\n\n"
                f"Metadata:\n"
                f"- File Entropy: {ent_val:.2f}/8.0 (measure of randomness; packed/encrypted files usually have high entropy > 7.2)\n"
                f"- Detected Suspicious Patterns: {pat_val}\n"
                f"- Risky/Dangerous Imports: {imp_val}\n"
                f"- Heuristic Risk Score: {risk_val}/100\n\n"
                f"Please provide a concise 3-4 sentence security assessment. Specify the overall threat verdict "
                f"(Clean, Low Risk, Medium Risk, High Risk, or Critical Risk), the risk score, key findings (e.g. suspicious behavior, "
                f"obfuscated entropy, dangerous imports), likely malware family classification if suspicious, and a final recommendation "
                f"(e.g. safe, run in sandbox, quarantine/delete). Keep the response compact, highly professional, and technical."
            )

            payload = {
                "contents": [
                    {
                        "parts": [
                            {
                                "text": prompt
                            }
                        ]
                    }
                ],
                "generationConfig": {
                    "temperature": 0.2,
                    "maxOutputTokens": 2048
                }
            }

            headers = {"Content-Type": "application/json"}
            response = requests.post(url, json=payload, headers=headers, timeout=10)
            
            if response.status_code == 200:
                res_data = response.json()
                # Extract text response from Gemini's JSON structure
                candidates = res_data.get("candidates", [])
                if candidates:
                    text_content = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                    if text_content.strip():
                        return text_content.strip()
        except Exception:
            # Fall back to local analysis on error
            pass

    return analyze_file_ai_local(entropy, patterns, imports, risk_score)


def analyze_file_ai_local(entropy, patterns, imports, risk_score):
    """
    Analyze a file using local rule-based intelligence.
    Returns a multi-sentence assessment string.
    """
    try:
        entropy    = float(entropy or 0)
        risk_score = int(risk_score or 0)
        patterns   = str(patterns or "").lower()
        imports    = str(imports or "").lower()

        findings       = []
        threat_classes = []

        # ── Risk level ────────────────────────────────────────────────────────
        if risk_score >= 70:
            verdict     = "highly malicious"
            risk_label  = "CRITICAL RISK"
        elif risk_score >= 50:
            verdict     = "likely malicious"
            risk_label  = "HIGH RISK"
        elif risk_score >= 30:
            verdict     = "suspicious"
            risk_label  = "MEDIUM RISK"
        elif risk_score >= 10:
            verdict     = "potentially unwanted"
            risk_label  = "LOW RISK"
        else:
            verdict     = "likely safe"
            risk_label  = "CLEAN"

        # ── Entropy analysis ──────────────────────────────────────────────────
        if entropy >= 7.5:
            findings.append(
                f"very high entropy ({entropy:.2f}/8.0) strongly indicates packed, "
                "encrypted, or obfuscated content — a hallmark of advanced malware"
            )
        elif entropy >= 7.0:
            findings.append(
                f"elevated entropy ({entropy:.2f}/8.0) suggests obfuscation or "
                "compression commonly used to evade static analysis"
            )
        elif entropy >= 6.0:
            findings.append(
                f"moderately elevated entropy ({entropy:.2f}/8.0) may indicate "
                "partial encoding or embedded encrypted data"
            )

        # ── Pattern-based detections ──────────────────────────────────────────
        if "code execution" in patterns or "eval" in patterns or "exec" in patterns:
            findings.append("dynamic code execution patterns detected (eval/exec)")
            threat_classes.append("code injection")

        if "system command" in patterns or "cmd" in patterns or "powershell" in patterns:
            findings.append("system command execution capability found")
            threat_classes.append("command execution")

        if "process spawn" in patterns or "subprocess" in patterns:
            findings.append("process spawning behavior identified")
            threat_classes.append("process injection")

        if "network" in patterns or "socket" in patterns or "http" in patterns:
            findings.append("network communication capability present")
            threat_classes.append("network communication")

        if "exfiltration" in patterns or "webhook" in patterns or "pastebin" in patterns:
            findings.append("data exfiltration indicators found (webhook/pastebin/remote upload)")
            threat_classes.append("data exfiltration")

        if "reverse shell" in patterns:
            findings.append("reverse shell pattern detected — critical indicator of remote access trojan (RAT)")
            threat_classes.append("remote access trojan (RAT)")

        if "persistence" in patterns or "startup" in patterns or "registry" in patterns or "schtasks" in patterns:
            findings.append("persistence mechanism detected (registry/scheduled task/startup)")
            threat_classes.append("persistence")

        if "obfuscated" in patterns or "base64" in patterns or "encoding" in patterns:
            findings.append("obfuscation/encoding routines detected, suggesting payload concealment")
            threat_classes.append("obfuscation")

        if "batch abuse" in patterns or "taskkill" in patterns or "shutdown" in patterns:
            findings.append("system disruption commands found (taskkill/shutdown/del)")
            threat_classes.append("system disruption")

        if "file access" in patterns or "delete" in patterns or "remove" in patterns:
            findings.append("aggressive file system operations detected")

        # ── Import-based detections ───────────────────────────────────────────
        risky_import_map = {
            "subprocess": ("subprocess module", "process spawning and command execution"),
            "socket":     ("socket module",     "raw network communication"),
            "os":         ("os module",          "operating system access and file manipulation"),
            "sys":        ("sys module",          "interpreter-level system access"),
            "requests":   ("requests module",    "HTTP-based network communication"),
            "ctypes":     ("ctypes module",      "low-level Windows API calls"),
            "winreg":     ("winreg module",      "Windows registry manipulation"),
            "shutil":     ("shutil module",      "file copying and deletion"),
        }
        found_imports = []
        for key, (label, desc) in risky_import_map.items():
            if key in imports:
                found_imports.append(f"{label} ({desc})")
        if found_imports:
            findings.append(
                f"uses potentially dangerous modules: {', '.join(found_imports)}"
            )

        # ── Classify malware family ───────────────────────────────────────────
        malware_family = _classify_malware_family(threat_classes, risk_score, entropy)

        # ── Compose the analysis report ───────────────────────────────────────
        lines = []

        # Sentence 1: Verdict
        if findings:
            lines.append(
                f"[{risk_label}] This file is {verdict} (risk score: {risk_score}/100). "
                f"The analysis identified {len(findings)} indicator(s) of compromise."
            )
        else:
            lines.append(
                f"[{risk_label}] This file appears {verdict} (risk score: {risk_score}/100) "
                f"with no significant behavioral indicators detected."
            )

        # Sentence 2: Key findings
        if findings:
            key = findings[:3]  # Top 3 most important findings
            lines.append("Key findings: " + "; ".join(key) + ".")

        # Sentence 3: Malware classification
        if malware_family:
            lines.append(
                f"Threat classification: this file exhibits characteristics consistent "
                f"with {malware_family}."
            )
        elif risk_score < 10:
            lines.append(
                "No malicious patterns, suspicious imports, or anomalous entropy were "
                "detected. This file is likely benign."
            )

        # Sentence 4: Recommendation
        if risk_score >= 50:
            lines.append(
                "Recommendation: QUARANTINE or DELETE this file immediately. "
                "Do not execute it on any system."
            )
        elif risk_score >= 30:
            lines.append(
                "Recommendation: treat with caution. Investigate further before executing. "
                "Consider running in an isolated sandbox environment."
            )
        elif risk_score >= 10:
            lines.append(
                "Recommendation: this file appears low-risk but review it manually "
                "if it came from an untrusted source."
            )
        else:
            lines.append(
                "Recommendation: file appears SAFE. No action required."
            )

        return " ".join(lines)

    except Exception as exc:
        return f"Local analysis engine encountered an error: {exc}"


def _classify_malware_family(threat_classes: list, risk_score: int, entropy: float) -> str:
    """Infer the most likely malware category from collected threat indicators."""
    tc = set(threat_classes)

    if "remote access trojan (RAT)" in tc:
        return "a Remote Access Trojan (RAT) capable of full system compromise"
    if "data exfiltration" in tc and "network communication" in tc:
        return "an information stealer or spyware designed to exfiltrate sensitive data"
    if "persistence" in tc and "command execution" in tc:
        return "a backdoor or dropper with persistent access capabilities"
    if "obfuscation" in tc and entropy >= 7.0 and risk_score >= 50:
        return "a packed or crypted malware sample designed to evade antivirus detection"
    if "process injection" in tc and "command execution" in tc:
        return "a process injector or trojan loader"
    if "system disruption" in tc:
        return "a potentially destructive tool (wiper, killswitch, or sabotage script)"
    if "command execution" in tc and risk_score >= 40:
        return "a command-and-control (C2) agent or exploitation script"
    if "network communication" in tc and risk_score >= 30:
        return "a network-aware script that may be used for scanning or C2 beaconing"
    if "code injection" in tc:
        return "a script with dynamic code execution, often used in droppers or loaders"
    if risk_score >= 60:
        return "an unclassified high-risk threat requiring immediate investigation"

    return ""