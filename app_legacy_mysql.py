from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import SubmitField
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os
import hashlib
import math
import re
import json
import threading
import logging
from datetime import datetime, timedelta
from api.malware_api import check_hash_api, smart_virustotal_scan
from api.ai_analysis import analyze_file_ai

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:@localhost:3306/capstone1'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'rencelpogi'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['AUTO_START_MONITOR'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --------------------- MODELS --------------------- #
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False, unique=True)
    email = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)

class UploadedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(255), nullable=False)
    upload_time = db.Column(db.DateTime, server_default=db.func.current_timestamp())
    status = db.Column(db.String(50), default="Pending")
    hash = db.Column(db.String(255))
    entropy = db.Column(db.Float)
    pattern_result = db.Column(db.String(255))
    signature_status = db.Column(db.String(255))
    threat_level = db.Column(db.String(50))
    risk_score = db.Column(db.Integer)
    risky_imports = db.Column(db.String(255))
    ai_analysis = db.Column(db.Text)
    size = db.Column(db.String(50))
    explanation = db.Column(db.Text)
    threat_ratio = db.Column(db.Integer)

class UserSettings(db.Model):
    __tablename__ = 'user_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    auto_scan_enabled = db.Column(db.Boolean, default=True)
    auto_scan_mode = db.Column(db.String(20), default='single')
    default_scan_types = db.Column(db.String(100), default='heuristic')
    notify_on_threat = db.Column(db.Boolean, default=True)
    theme = db.Column(db.String(20), default='dark')
    auto_quarantine = db.Column(db.Boolean, default=True)
    max_file_size_mb = db.Column(db.Integer, default=100)
    alert_sound = db.Column(db.Boolean, default=True)
    notify_safe = db.Column(db.Boolean, default=False)
    
    user = db.relationship('User', backref='settings', uselist=False)

class VTCache(db.Model):
    __tablename__ = 'vt_cache'
    
    id = db.Column(db.Integer, primary_key=True)
    file_hash = db.Column(db.String(255), unique=True, nullable=False)
    positives = db.Column(db.Integer, default=0)
    total_engines = db.Column(db.Integer, default=0)
    scan_date = db.Column(db.DateTime, default=db.func.current_timestamp())

# --------------------- FORMS --------------------- #
class UploadFileForm(FlaskForm):
    file = FileField('Upload File', validators=[FileRequired()])
    submit = SubmitField('Upload')

# --------------------- ROUTES --------------------- #
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()

        if not username or not email or not password:
            flash("Please fill out all fields")
            return redirect(url_for('signup'))

        if User.query.filter_by(email=email).first():
            flash("Email already exists!")
            return redirect(url_for('signup'))

        if User.query.filter_by(username=username).first():
            flash("Username already exists!")
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully!")
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))

        flash("Invalid login")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    files = UploadedFile.query.order_by(UploadedFile.upload_time.desc()).all()
    user_settings = UserSettings.query.filter_by(user_id=current_user.id).first()

    total_scans = len(files)
    safe_files = 0
    low_threat = 0
    medium_threat = 0
    high_threat = 0
    critical_threat = 0
    pending = 0

    for file in files:
        risk = file.risk_score or 0

        if os.path.exists(file.filepath):
            size = os.path.getsize(file.filepath)
            file.size = f"{round(size/1024, 2)} KB"
        else:
            file.size = "N/A"

        if file.status == "Pending":
            pending += 1

        if risk >= 70:
            file.threat_level = "Critical"
            critical_threat += 1
        elif risk >= 50:
            file.threat_level = "High"
            high_threat += 1
        elif risk >= 30:
            file.threat_level = "Medium"
            medium_threat += 1
        elif risk < 30 and file.status != "Pending":
            file.threat_level = "Low"
            low_threat += 1
        else:
            file.threat_level = "-"
            safe_files += 1

        explanation = []
        if risk >= 70:
            explanation.append("High risk file")
        elif risk >= 50:
            explanation.append("Moderate risk")
        elif risk >= 30:
            explanation.append("Low risk")
        else:
            explanation.append("Safe")

        file.explanation = " | ".join(explanation)
        file.threat_ratio = risk

    return render_template(
        'dashboard.html',
        files=files,
        total_scans=total_scans,
        safe_files=safe_files,
        low_threat=low_threat,
        medium_threat=medium_threat,
        high_threat=high_threat,
        critical_threat=critical_threat,
        pending=pending,
        settings=user_settings
    )

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def uploadfiles():
    form = UploadFileForm()

    if form.validate_on_submit():
        f = form.file.data

        if not f or f.filename == '':
            flash('No file uploaded. Please upload your file.', 'error')
            return redirect(request.url)

        filename = secure_filename(f.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        f.save(path)

        new_file = UploadedFile(filename=filename, filepath=path)
        db.session.add(new_file)
        db.session.commit()

        flash('File uploaded successfully!', 'success')
        return redirect(url_for('scan_page', file_id=new_file.id))

    return render_template('uploadfiles.html', form=form)

# --------------------- HELPERS --------------------- #
def calculate_entropy(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        if not data:
            return 0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        entropy = -sum((c/len(data)) * math.log2(c/len(data)) for c in counts if c > 0)
        return round(entropy, 2)
    except:
        return 0

def get_file_type_entropy_threshold(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    
    if ext in ['.py', '.js', '.vbs', '.ps1', '.bat', '.txt', '.html', '.css']:
        return 5.8
    elif ext in ['.exe', '.dll', '.bin', '.dat']:
        return 7.0
    else:
        return 6.5

def run_accurate_heuristics(file_path):
    findings = []
    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()

        if re.search(r'requests\.(post|get).*?(webhook|pastebin|ngrok|token|password|cookie)', content, re.I):
            findings.append("Data Exfiltration")
        if re.search(r'base64.*(decode|b64decode).*eval\s*\(', content, re.I):
            findings.append("Obfuscated Execution")
        if re.search(r'socket\.socket.*connect.*subprocess', content, re.I):
            findings.append("Reverse Shell")
        if re.search(r'(winreg|HKEY_|schtasks|Startup)', content, re.I):
            findings.append("Persistence Mechanism")
    except:
        pass
    return findings

def check_suspicious_strings(file_path):
    patterns = {
        "Code Execution": r'\b(eval|exec)\s*\(',
        "System Command": r'\b(os\.system|cmd\.exe|powershell)\b',
        "Process Spawn": r'\b(subprocess\.(Popen|call|run)|start)\b',
        "Infinite Loop": r'(:\w+.*goto\s+\w+)|(while\s+true)',
        "Network": r'\b(requests\.(get|post)|socket|http|ftp)\b',
        "Encoding": r'\b(base64|b64decode|hex|encode|decode)\b',
        "Script Engine": r'\b(wscript|cscript|powershell)\b',
        "File Access": r'\b(open|write|delete|remove|mkdir)\b',
        "Batch Abuse": r'\b(start|taskkill|shutdown|del)\b'
    }

    findings = []
    risk_score = 0

    try:
        with open(file_path, "r", errors="ignore") as file:
            content = file.read().lower()
            for label, pattern in patterns.items():
                if re.findall(pattern, content):
                    findings.append(f"{label} detected")
                    if label in ["Code Execution", "Process Spawn"]:
                        risk_score += 20
                    elif label in ["Infinite Loop", "Batch Abuse"]:
                        risk_score += 30
                    else:
                        risk_score += 10
    except Exception as e:
        findings.append(f"Error reading file: {e}")

    return findings, risk_score

def detect_risky_imports(file_path):
    DANGEROUS_IMPORTS = ["os", "sys", "subprocess", "socket", "requests"]
    found = []
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
        for imp in DANGEROUS_IMPORTS:
            if re.search(rf'\bimport {imp}\b|\bfrom {imp} import', content):
                found.append(imp)
    except:
        pass
    return found

def enhanced_scan(file_path):
    data = b""
    file_hash = ""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        file_hash = hashlib.sha256(data).hexdigest()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return {
            "hash": "",
            "entropy": 0,
            "heuristics": [],
            "suspicious_functions": [],
            "risky_imports": [],
            "risk_score": 0
        }
    
    filename = os.path.basename(file_path).lower()
    dangerous_ext = ['.exe', '.bat', '.cmd', '.vbs', '.js', '.ps1', '.py']
    file_type_risk = any(filename.endswith(ext) for ext in dangerous_ext)
    
    entropy = calculate_entropy(file_path)
    heuristics = run_accurate_heuristics(file_path)
    suspicious_functions, sig_risk = check_suspicious_strings(file_path)
    risky_imports = detect_risky_imports(file_path)
    entropy_threshold = get_file_type_entropy_threshold(file_path)
    
    risk_score = 0
    
    if entropy > entropy_threshold + 1.5:
        risk_score += 30
        heuristics.append(f"Very high entropy ({entropy}) for this file type")
    elif entropy > entropy_threshold + 0.8:
        risk_score += 20
        heuristics.append(f"High entropy ({entropy}) - possible obfuscation")
    elif entropy > entropy_threshold:
        risk_score += 10
    
    if entropy < 2.0 and any(filename.endswith(ext) for ext in ['.exe', '.dll', '.bin']):
        risk_score += 10
        heuristics.append("Unusually low entropy - possible packing or disguise")
    
    for heuristic in heuristics:
        if "Exfiltration" in heuristic:
            risk_score += 25
        elif "Reverse Shell" in heuristic:
            risk_score += 30
        elif "Persistence" in heuristic:
            risk_score += 20
        elif "Obfuscated" in heuristic:
            risk_score += 15
        else:
            risk_score += 10
    
    for sig in suspicious_functions:
        if "Code Execution" in sig or "Process Spawn" in sig:
            risk_score += 15
        elif "System Command" in sig or "Batch Abuse" in sig:
            risk_score += 12
        elif "Network" in sig or "Encoding" in sig:
            risk_score += 8
        elif "Script Engine" in sig:
            risk_score += 10
        elif "File Access" in sig:
            risk_score += 5
        else:
            risk_score += 5
    
    for imp in risky_imports:
        if imp in ["subprocess", "socket"]:
            risk_score += 15
        elif imp in ["os", "sys"]:
            risk_score += 10
        elif imp == "requests":
            risk_score += 8
    
    if file_type_risk:
        risk_score += 10
    
    detection_count = len(heuristics) + len(suspicious_functions) + len(risky_imports)
    if detection_count >= 5:
        risk_score += 15
    elif detection_count >= 3:
        risk_score += 8
    elif detection_count >= 1:
        risk_score += 3
    
    risk_score = min(risk_score, 100)
    
    if len(suspicious_functions) > 0 and risk_score < 30:
        risk_score = 30
    if len(risky_imports) > 0 and risk_score < 20:
        risk_score = 20

    return {
        "hash": file_hash,
        "entropy": entropy,
        "heuristics": heuristics,
        "suspicious_functions": suspicious_functions,
        "risky_imports": risky_imports,
        "risk_score": risk_score
    }

def generate_explanation(file):
    reasons = []

    if file.pattern_result and file.pattern_result != "Clean":
        reasons.append(f"it exhibits {file.pattern_result.lower()} behavior")
    if file.signature_status and file.signature_status != "None":
        reasons.append(f"it performs suspicious actions such as {file.signature_status.lower()}")
    if file.risky_imports and file.risky_imports != "None":
        reasons.append(f"it uses risky modules like {file.risky_imports}")
    if file.entropy and file.entropy > 7.5:
        reasons.append("it has high entropy, which may indicate obfuscation or hidden malicious code")

    if file.risk_score >= 70:
        level = "a critical threat"
        explanation_intro = "This file is very dangerous"
    elif file.risk_score >= 50:
        level = "a high-risk threat"
        explanation_intro = "This file is potentially harmful"
    elif file.risk_score >= 30:
        level = "a moderately suspicious file"
        explanation_intro = "This file shows some suspicious behavior"
    else:
        level = "low-risk"
        explanation_intro = "This file appears mostly safe"

    if reasons:
        return f"{explanation_intro} ({level}) because " + ", ".join(reasons) + "."
    else:
        if file.risk_score < 30:
            return f"{explanation_intro}. No significant suspicious behavior detected."
        else:
            return f"This file is classified as {level} but no specific suspicious behavior was detected."

# --------------------- SCAN ROUTES --------------------- #
@app.route('/scan/<int:file_id>', methods=['GET', 'POST'], endpoint='scan_page')
@login_required
def scan(file_id):
    file = UploadedFile.query.get_or_404(file_id)
    auto_scan = request.args.get('auto_scan', 'false')

    if request.method == 'POST':
        scan_mode = request.form.get('scan_mode', 'single')
        selected_scans = request.form.getlist('scan_types')
        
        if scan_mode == 'multiple' and selected_scans:
            return redirect(url_for('multiple_scan', file_id=file.id, scans=','.join(selected_scans)))
        
        offline_result = enhanced_scan(file.filepath)
        file.hash = offline_result["hash"]

        try:
            vt_result = smart_virustotal_scan(file.filepath, file.hash)
            if vt_result and vt_result.get("positives", 0) >= 0:
                detected = vt_result.get("positives", 0)
                total = vt_result.get("engine_count", 0)
                online_risk = int((detected / total) * 100) if total > 0 else 0
            else:
                online_risk = 0
        except Exception as e:
            print(f"VirusTotal error: {e}")
            online_risk = 0

        final_risk = max(offline_result["risk_score"], online_risk)
        file.entropy = offline_result["entropy"]

        if offline_result["suspicious_functions"]:
            file.pattern_result = ", ".join(offline_result["suspicious_functions"][:3])
        elif offline_result["heuristics"]:
            file.pattern_result = ", ".join(offline_result["heuristics"])
        else:
            file.pattern_result = "No suspicious patterns"

        if offline_result["heuristics"]:
            file.signature_status = ", ".join(offline_result["heuristics"])
        elif offline_result["suspicious_functions"]:
            file.signature_status = ", ".join(offline_result["suspicious_functions"][:3])
        else:
            file.signature_status = "No signatures detected"

        if offline_result["risky_imports"]:
            file.risky_imports = ", ".join(offline_result["risky_imports"])
        else:
            file.risky_imports = "None"

        file.risk_score = final_risk

        ai_result = analyze_file_ai(
            entropy=offline_result["entropy"],
            patterns=file.pattern_result,
            imports=file.risky_imports,
            risk_score=final_risk
        )
        file.ai_analysis = ai_result

        heuristics_str = " ".join(offline_result["heuristics"]).lower()
        suspicious_str = " ".join(offline_result["suspicious_functions"]).lower()
        imports_str = " ".join(offline_result["risky_imports"]).lower()
        all_detections = heuristics_str + " " + suspicious_str
        
        if "reverse shell" in all_detections:
            file.threat_level = "Critical"
        elif "data exfiltration" in all_detections:
            file.threat_level = "High"
        elif "persistence" in all_detections:
            file.threat_level = "Medium"
        elif "obfuscated" in all_detections:
            file.threat_level = "Medium"
        elif "code execution" in all_detections:
            file.threat_level = "Medium"
        elif "process spawn" in all_detections:
            file.threat_level = "Medium"
        elif "network" in all_detections:
            file.threat_level = "Low"
        elif "encoding" in all_detections:
            file.threat_level = "Low"
        else:
            if "subprocess" in imports_str and "socket" in imports_str:
                file.threat_level = "High"
            elif "os" in imports_str or "sys" in imports_str:
                file.threat_level = "Medium"
            else:
                if final_risk >= 70:
                    file.threat_level = "Critical"
                elif final_risk >= 50:
                    file.threat_level = "High"
                elif final_risk >= 30:
                    file.threat_level = "Medium"
                else:
                    file.threat_level = "Low"
        
        if file.threat_level in ["Critical", "High", "Medium"]:
            file.status = "Threat"
        else:
            file.status = "Safe"

        file.explanation = generate_explanation(file)
        db.session.commit()
        
        return render_template('scan.html', file=file, result=True, scan_mode='single')

    return render_template('scan.html', file=file, result=False, auto_scan=auto_scan)

@app.route('/multiple_scan/<int:file_id>', methods=['GET', 'POST'])
@login_required
def multiple_scan(file_id):
    file = UploadedFile.query.get_or_404(file_id)
    scan_types = request.args.get('scans', '')
    
    if request.method == 'POST':
        if not scan_types:
            scan_types = request.form.getlist('scan_types')
            if isinstance(scan_types, list):
                scan_types = ','.join(scan_types)
        
        scan_list = scan_types.split(',') if scan_types else []
        results = {}
        
        file_hash = ""
        try:
            with open(file.filepath, "rb") as f:
                file_data = f.read()
            file_hash = hashlib.sha256(file_data).hexdigest()
        except Exception as e:
            flash(f"Error reading file: {str(e)}", 'error')
            return redirect(url_for('dashboard'))
        
        for scan_type in scan_list:
            if scan_type == 'heuristic':
                results['heuristic'] = enhanced_scan(file.filepath)
            elif scan_type == 'virustotal':
                try:
                    vt_result = smart_virustotal_scan(file.filepath, file_hash)
                    results['virustotal'] = vt_result
                except Exception as e:
                    results['virustotal'] = {"error": str(e), "positives": 0, "engine_count": 0, "method": "error"}
            elif scan_type == 'ai_analysis':
                offline = enhanced_scan(file.filepath)
                patterns = "None"
                if offline.get("suspicious_functions"):
                    patterns = ", ".join(offline["suspicious_functions"][:3])
                elif offline.get("heuristics"):
                    patterns = ", ".join(offline["heuristics"])
                imports = "None"
                if offline.get("risky_imports"):
                    imports = ", ".join(offline["risky_imports"])
                ai_result = analyze_file_ai(
                    entropy=offline.get("entropy", 0),
                    patterns=patterns,
                    imports=imports,
                    risk_score=offline.get("risk_score", 0)
                )
                results['ai_analysis'] = ai_result
        
        final_risk = 0
        detection_details = []
        
        if 'heuristic' in results:
            heuristic_data = results['heuristic']
            final_risk = max(final_risk, heuristic_data.get('risk_score', 0))
            file.entropy = heuristic_data.get('entropy', 0)
            file.hash = heuristic_data.get('hash', file_hash)
            
            if heuristic_data.get('suspicious_functions'):
                file.pattern_result = ", ".join(heuristic_data['suspicious_functions'][:3])
                detection_details.extend(heuristic_data['suspicious_functions'])
            else:
                file.pattern_result = "No suspicious patterns"
                
            if heuristic_data.get('heuristics'):
                file.signature_status = ", ".join(heuristic_data['heuristics'])
                detection_details.extend(heuristic_data['heuristics'])
            else:
                file.signature_status = "No signatures detected"
                
            if heuristic_data.get('risky_imports'):
                file.risky_imports = ", ".join(heuristic_data['risky_imports'])
            else:
                file.risky_imports = "None"
        
        if 'virustotal' in results:
            vt_data = results['virustotal']
            if isinstance(vt_data, dict) and 'error' not in vt_data:
                positives = vt_data.get('positives', 0)
                total = vt_data.get('engine_count', 0)
                if total > 0:
                    vt_risk = int((positives / total) * 100)
                    final_risk = max(final_risk, vt_risk)
                    if positives > 0:
                        detection_details.append(f"VirusTotal: {positives}/{total} engines detected threat")
        
        if 'ai_analysis' in results:
            file.ai_analysis = results['ai_analysis']
        
        file.risk_score = min(final_risk, 100)
        
        all_detections = " ".join(detection_details).lower()
        
        if "reverse shell" in all_detections:
            file.threat_level = "Critical"
        elif final_risk >= 70:
            file.threat_level = "Critical"
        elif final_risk >= 50:
            file.threat_level = "High"
        elif final_risk >= 30:
            file.threat_level = "Medium"
        else:
            file.threat_level = "Low"
        
        file.status = "Threat" if file.threat_level in ["Critical", "High", "Medium"] else "Safe"
        file.explanation = generate_explanation(file)
        
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f"Error saving results: {str(e)}", 'error')
        
        return render_template('scan.html', file=file, result=True, scan_mode='multiple', results=results)
    
    return render_template('scan.html', file=file, result=False, scan_mode='multiple', scan_types=scan_types.split(',') if scan_types else [])

# --------------------- API ENDPOINTS FOR MONITOR --------------------- #
from file_monitor import start_system_monitor, stop_system_monitor, get_monitor

# Global monitor reference
system_monitor = None

@app.route('/api/start_monitor', methods=['POST'])
@login_required
def start_monitor_api():
    global system_monitor
    try:
        settings = get_user_monitor_settings(current_user.id)
        
        def start_monitor_thread():
            global system_monitor
            api_url = request.url_root.rstrip('/')
            system_monitor = start_system_monitor(api_url, settings, save_scan_to_db)
        
        thread = threading.Thread(target=start_monitor_thread, daemon=True)
        thread.start()
        
        return jsonify({'success': True, 'message': 'System monitor started'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stop_monitor', methods=['POST'])
@login_required
def stop_monitor_api():
    global system_monitor
    try:
        if system_monitor:
            stop_system_monitor()
        return jsonify({'success': True, 'message': 'System monitor stopped'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/monitor_status')
@login_required
def monitor_status_api():
    monitor = get_monitor()
    if monitor and monitor.running:
        status = monitor.get_status()
    else:
        status = {'running': False}
    
    user_settings = UserSettings.query.filter_by(user_id=current_user.id).first()
    
    return jsonify({
        'running': status.get('running', False),
        'monitored_locations': status.get('monitored_paths', 0),
        'enabled': status.get('running', False),
        'settings': {
            'auto_quarantine': user_settings.auto_quarantine if user_settings else True,
            'max_file_size_mb': getattr(user_settings, 'max_file_size_mb', 100),
            'notify_on_threat': user_settings.notify_on_threat if user_settings else True,
        } if user_settings else {}
    }), 200

@app.route('/api/realtime_detections')
@login_required
def realtime_detections_api():
    detections_file = os.path.join(os.path.expanduser("~"), "Desktop", "TrustFile_Detections.json")
    
    detections = []
    if os.path.exists(detections_file):
        try:
            with open(detections_file, 'r') as f:
                detections = json.load(f)
        except:
            pass
    
    recent_scans = UploadedFile.query.order_by(UploadedFile.upload_time.desc()).limit(10).all()
    
    recent_data = []
    for scan in recent_scans:
        if scan.status != "Pending":
            recent_data.append({
                'timestamp': scan.upload_time.isoformat(),
                'filename': scan.filename,
                'threat_level': scan.threat_level,
                'risk_score': scan.risk_score,
                'status': scan.status,
                'ai_analysis': scan.ai_analysis[:100] if scan.ai_analysis else None
            })
    
    return jsonify({
        'realtime': detections[:20],
        'recent_scans': recent_data
    }), 200

@app.route('/api/auto_scan', methods=['POST'])
def auto_scan_api():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        filename = secure_filename(file.filename)
        temp_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'auto_scans')
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)
        
        temp_path = os.path.join(temp_dir, filename)
        file.save(temp_path)
        
        scan_result = enhanced_scan(temp_path)
        
        with open(temp_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        vt_result = None
        try:
            vt_result = smart_virustotal_scan(temp_path, file_hash)
            if vt_result and vt_result.get("positives", 0) > 0:
                online_risk = int((vt_result["positives"] / vt_result["engine_count"]) * 100)
                scan_result["risk_score"] = max(scan_result["risk_score"], online_risk)
        except Exception as e:
            print(f"VirusTotal API error: {e}")
        
        patterns = ", ".join(scan_result.get("suspicious_functions", [])[:3]) or "No patterns"
        imports = ", ".join(scan_result.get("risky_imports", [])) or "None"
        
        ai_result = analyze_file_ai(
            entropy=scan_result.get("entropy", 0),
            patterns=patterns,
            imports=imports,
            risk_score=scan_result.get("risk_score", 0)
        )
        
        risk_score = scan_result.get("risk_score", 0)
        if risk_score >= 70:
            threat_level = "Critical"
            status = "Threat"
        elif risk_score >= 50:
            threat_level = "High"
            status = "Threat"
        elif risk_score >= 30:
            threat_level = "Medium"
            status = "Threat"
        else:
            threat_level = "Low"
            status = "Safe"
        
        try:
            os.remove(temp_path)
        except:
            pass
        
        return jsonify({
            'success': True,
            'filename': filename,
            'hash': file_hash,
            'entropy': scan_result.get("entropy", 0),
            'risk_score': scan_result.get("risk_score", 0),
            'threat_level': threat_level,
            'status': status,
            'patterns': scan_result.get("suspicious_functions", []),
            'heuristics': scan_result.get("heuristics", []),
            'risky_imports': scan_result.get("risky_imports", []),
            'ai_analysis': ai_result,
            'virustotal': vt_result
        }), 200
        
    except Exception as e:
        print(f"Auto-scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

def save_scan_to_db(filename, filepath, scan_result):
    with app.app_context():
        try:
            existing = UploadedFile.query.filter_by(filename=filename, filepath=filepath).first()
            if existing:
                return
            
            new_file = UploadedFile(
                filename=filename,
                filepath=filepath,
                status=scan_result.get('status', 'Safe'),
                threat_level=scan_result.get('threat_level', 'Low'),
                risk_score=scan_result.get('risk_score', 0),
                entropy=scan_result.get('entropy', 0),
                hash=scan_result.get('hash', ''),
                pattern_result=', '.join(scan_result.get('patterns', [])[:3]),
                signature_status=', '.join(scan_result.get('heuristics', [])[:3]),
                risky_imports=', '.join(scan_result.get('risky_imports', [])),
                ai_analysis=scan_result.get('ai_analysis', '')
            )
            db.session.add(new_file)
            db.session.commit()
            logger.info(f"Saved to database: {filename}")
        except Exception as e:
            logger.error(f"Failed to save to database: {e}")

def get_user_monitor_settings(user_id):
    settings = UserSettings.query.filter_by(user_id=user_id).first()
    return {
        'auto_quarantine': settings.auto_quarantine if settings else True,
        'max_file_size_mb': getattr(settings, 'max_file_size_mb', 100),
        'notify_on_threat': settings.notify_on_threat if settings else True,
        'notify_safe': getattr(settings, 'notify_safe', False),
        'alert_sound': getattr(settings, 'alert_sound', True),
    }

# --------------------- SETTINGS PAGE --------------------- #
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user_settings = UserSettings.query.filter_by(user_id=current_user.id).first()
    if not user_settings:
        user_settings = UserSettings(user_id=current_user.id)
        db.session.add(user_settings)
        db.session.commit()
    
    monitor_status = {'running': False, 'monitored_folder': 'Not running'}
    monitor = get_monitor()
    if monitor and monitor.running:
        monitor_status = {'running': True, 'monitored_folder': 'Multiple locations'}
    
    if request.method == 'POST':
        user_settings.auto_quarantine = request.form.get('auto_quarantine') == 'on'
        user_settings.max_file_size_mb = int(request.form.get('max_file_size_mb', 100))
        user_settings.notify_on_threat = request.form.get('notify_on_threat') == 'on'
        user_settings.auto_scan_mode = request.form.get('auto_scan_mode', 'single')
        user_settings.alert_sound = request.form.get('alert_sound') == 'on'
        user_settings.notify_safe = request.form.get('notify_safe') == 'on'
        
        scan_types = request.form.getlist('scan_types')
        user_settings.default_scan_types = ','.join(scan_types) if scan_types else 'heuristic'
        
        db.session.commit()
        flash('Settings saved successfully!', 'success')
        return redirect(url_for('settings'))
    
    settings_dict = {
        'auto_quarantine': user_settings.auto_quarantine,
        'max_file_size_mb': user_settings.max_file_size_mb,
        'notify_on_threat': user_settings.notify_on_threat,
        'auto_scan_mode': user_settings.auto_scan_mode,
        'alert_sound': getattr(user_settings, 'alert_sound', True),
        'notify_safe': getattr(user_settings, 'notify_safe', False),
        'scan_types': user_settings.default_scan_types.split(',') if user_settings.default_scan_types else ['heuristic'],
        'enabled': monitor_status.get('running', False),
        'monitored_folder': monitor_status.get('monitored_folder', ''),
        'delete_after_scan': False,
        'save_reports': True,
    }
    
    return render_template('settings.html', settings=settings_dict, monitor_status=monitor_status)

# --------------------- ADDITIONAL ROUTES --------------------- #
@app.route('/view_result/<int:file_id>')
@login_required
def view_result(file_id):
    file = UploadedFile.query.get_or_404(file_id)
    return render_template('scan.html', file=file, result=True)

@app.route('/api/save_theme', methods=['POST'])
@login_required
def save_theme_api():
    try:
        data = request.get_json()
        theme = data.get('theme', 'dark')
        
        if theme not in ['dark', 'light']:
            return jsonify({'error': 'Invalid theme'}), 400
        
        user_settings = UserSettings.query.filter_by(user_id=current_user.id).first()
        if user_settings:
            user_settings.theme = theme
            db.session.commit()
        
        return jsonify({'success': True, 'theme': theme}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/delete_file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file = UploadedFile.query.get_or_404(file_id)
    if os.path.exists(file.filepath):
        os.remove(file.filepath)
    db.session.delete(file)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/history')
@login_required
def history():
    files = UploadedFile.query.order_by(UploadedFile.upload_time.desc()).all()
    for file in files:
        if os.path.exists(file.filepath):
            size_bytes = os.path.getsize(file.filepath)
            if size_bytes < 1024:
                file.size = f"{size_bytes} B"
            elif size_bytes < 1024*1024:
                file.size = f"{size_bytes / 1024:.2f} KB"
            else:
                file.size = f"{size_bytes / (1024*1024):.2f} MB"
        else:
            file.size = "N/A"
        if not file.threat_level:
            file.threat_level = "Pending"
    return render_template('history.html', files=files)

@app.route('/reports')
@login_required
def reports():
    files = UploadedFile.query.order_by(UploadedFile.upload_time.desc()).all()

    total = len(files)
    safe = 0
    critical = 0
    high = 0
    medium = 0
    low = 0

    days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    safe_counts = [0] * 7
    threat_counts = [0] * 7

    for file in files:
        risk = file.risk_score or 0

        if file.status == "Safe":
            safe += 1

        if risk >= 70:
            critical += 1
        elif risk >= 50:
            high += 1
        elif risk >= 30:
            medium += 1
        else:
            low += 1

        day_index = file.upload_time.weekday()
        if file.status == "Safe":
            safe_counts[day_index] += 1
        else:
            threat_counts[day_index] += 1

    safe_percent = round((safe / total) * 100, 1) if total > 0 else 0
    threat_percent = round(100 - safe_percent, 1) if total > 0 else 0

    return render_template(
        'reports.html',
        safe_percent=safe_percent,
        threat_percent=threat_percent,
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        days=days,
        safe_counts=safe_counts,
        threat_counts=threat_counts
    )

@app.route('/reports/<int:file_id>')
@login_required
def report_detail(file_id):
    file = UploadedFile.query.get_or_404(file_id)
    file.explanation = generate_explanation(file)

    total_engines = 10
    detected = 0

    if file.entropy and file.entropy > 7.5:
        detected += 1
    if file.pattern_result and file.pattern_result != "Clean":
        detected += 1
    if file.signature_status and file.signature_status != "None":
        detected += 1
    if file.threat_level in ["High", "Critical"]:
        detected += 2
    elif file.threat_level == "Medium":
        detected += 1

    return render_template(
        'report_detail.html',
        file=file,
        detected=detected,
        total_engines=total_engines
    )

# --------------------- RUN --------------------- #
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    app.run(debug=True)