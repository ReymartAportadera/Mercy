from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os
import hashlib
import math
import re
from api.malware_api import check_hash_api
from api.ai_analysis import analyze_file_ai


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:@localhost:3306/capstone1'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'rencelpogi'
app.config['UPLOAD_FOLDER'] = 'static/uploads'

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

    ai_analysis =db.Column(db.Text)

# --------------------- FORMS --------------------- #
class UploadFileForm(FlaskForm):
    file = FileField("File")
    submit = SubmitField("Upload File")

# --------------------- ROUTES --------------------- #
@app.route('/')
def home():
    return render_template('home.html')

# --------------------- AUTH --------------------- #
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

# --------------------- DASHBOARD --------------------- #
@app.route('/dashboard')
@login_required
def dashboard():
    files = UploadedFile.query.order_by(UploadedFile.upload_time.desc()).all()

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
        pending=pending
    )


# --------------------- UPLOAD --------------------- #

from flask_wtf import FlaskForm
from wtforms import SubmitField
from flask_wtf.file import FileField, FileRequired

class UploadFileForm(FlaskForm):
    file = FileField('Upload File', validators=[FileRequired()])
    submit = SubmitField('Upload')

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def uploadfiles():
    form = UploadFileForm()

    if form.validate_on_submit():
        f = form.file.data

        # ✅ Check if no file selected
        if not f or f.filename == '':
            flash('No file uploaded. Please upload your file.', 'error')
            return redirect(request.url)

        filename = secure_filename(f.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        f.save(path)

        # Save to database
        new_file = UploadedFile(filename=filename, filepath=path)
        db.session.add(new_file)
        db.session.commit()

        flash('File uploaded successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('uploadfiles.html', form=form)
# --------------------- HELPERS --------------------- #
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

# ✅ ADD THIS FUNCTION HERE (right after calculate_entropy)
def get_file_type_entropy_threshold(file_path):
    """Returns appropriate entropy threshold based on file type"""
    ext = os.path.splitext(file_path)[1].lower()
    
    # Script files should have lower entropy thresholds
    if ext in ['.py', '.js', '.vbs', '.ps1', '.bat', '.txt', '.html', '.css']:
        return 5.8  # Anything above this is suspicious for scripts
    elif ext in ['.exe', '.dll', '.bin', '.dat']:
        return 7.0  # Binaries naturally have higher entropy
    else:
        return 6.5  # Default for unknown types

def run_accurate_heuristics(file_path):
    findings = []
    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()

        # Data Exfiltration (more precise)
        if re.search(r'requests\.(post|get).*?(webhook|pastebin|ngrok|token|password|cookie)', content, re.I):
            findings.append("Data Exfiltration")

        # Obfuscation + execution
        if re.search(r'base64.*(decode|b64decode).*eval\s*\(', content, re.I):
            findings.append("Obfuscated Execution")

        # Reverse shell behavior
        if re.search(r'socket\.socket.*connect.*subprocess', content, re.I):
            findings.append("Reverse Shell")

        # Persistence
        if re.search(r'(winreg|HKEY_|schtasks|Startup)', content, re.I):
            findings.append("Persistence Mechanism")

    except:
        pass

    return findings

def check_suspicious_strings(file_path):
    patterns = {
        #  Code Execution
        "Code Execution": r'\b(eval|exec)\s*\(',

        #  System Commands
        "System Command": r'\b(os\.system|cmd\.exe|powershell)\b',

        #  Subprocess / Process Spawn
        "Process Spawn": r'\b(subprocess\.(Popen|call|run)|start)\b',

        #  Infinite Loop / Logic Abuse
        "Infinite Loop": r'(:\w+.*goto\s+\w+)|(while\s+true)',

        #  Network Activity
        "Network": r'\b(requests\.(get|post)|socket|http|ftp)\b',

        #  Encoding / Obfuscation
        "Encoding": r'\b(base64|b64decode|hex|encode|decode)\b',

        # Script Engines
        "Script Engine": r'\b(wscript|cscript|powershell)\b',

        #  File/System Manipulation
        "File Access": r'\b(open|write|delete|remove|mkdir)\b',

        #  Windows Batch Dangerous Commands
        "Batch Abuse": r'\b(start|taskkill|shutdown|del)\b'
    }

    findings = []
    risk_score = 0

    try:
        with open(file_path, "r", errors="ignore") as file:
            content = file.read().lower()

            for label, pattern in patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    findings.append(f"{label} detected")
                    
                    # 🎯 Assign risk based on severity
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
# --------------------- ENHANCED SCAN --------------------- #
def enhanced_scan(file_path):
    # ---------------- READ FILE SAFELY ---------------- #
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
    
    # ---------------- GET FILE INFO ---------------- #
    filename = os.path.basename(file_path).lower()
    dangerous_ext = ['.exe', '.bat', '.cmd', '.vbs', '.js', '.ps1', '.py']
    file_type_risk = any(filename.endswith(ext) for ext in dangerous_ext)
    
    # ---------------- CALCULATIONS ---------------- #
    entropy = calculate_entropy(file_path)
    heuristics = run_accurate_heuristics(file_path)
    suspicious_functions, sig_risk = check_suspicious_strings(file_path)
    risky_imports = detect_risky_imports(file_path)
    
    # ---------------- GET ENTROPY THRESHOLD ---------------- #
    entropy_threshold = get_file_type_entropy_threshold(file_path)
    
    # ---------------- IMPROVED RISK SCORING ---------------- #
    risk_score = 0
    
    # ========== 1. ENTROPY SCORING (Context-Aware) ==========
    if entropy > entropy_threshold + 1.5:
        risk_score += 30
        heuristics.append(f"Very high entropy ({entropy}) for this file type")
    elif entropy > entropy_threshold + 0.8:
        risk_score += 20
        heuristics.append(f"High entropy ({entropy}) - possible obfuscation")
    elif entropy > entropy_threshold:
        risk_score += 10
    
    # Check for unusually low entropy in binaries
    if entropy < 2.0 and any(filename.endswith(ext) for ext in ['.exe', '.dll', '.bin']):
        risk_score += 10
        heuristics.append("Unusually low entropy - possible packing or disguise")
    
    # ========== 2. HEURISTICS SCORING ==========
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
    
    # ========== 3. SIGNATURE-BASED SCORING ==========
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
    
    # ========== 4. RISKY IMPORTS SCORING ==========
    for imp in risky_imports:
        if imp in ["subprocess", "socket"]:
            risk_score += 15
        elif imp in ["os", "sys"]:
            risk_score += 10
        elif imp == "requests":
            risk_score += 8
    
    # ========== 5. FILE TYPE BONUS ==========
    if file_type_risk:
        risk_score += 10
    
    # ========== 6. MULTIPLE DETECTION BONUS ==========
    detection_count = len(heuristics) + len(suspicious_functions) + len(risky_imports)
    if detection_count >= 5:
        risk_score += 15
    elif detection_count >= 3:
        risk_score += 8
    elif detection_count >= 1:
        risk_score += 3
    
    # ========== 7. CAP AND ENSURE MINIMUM SCORES ==========
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

    # Determine threat level
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

    # Build the message
    if reasons:
        return f"{explanation_intro} ({level}) because " + ", ".join(reasons) + "."
    else:
        # Friendly message if no suspicious behavior
        if file.risk_score < 30:
            return f"{explanation_intro}. No significant suspicious behavior detected."
        else:
            return f"This file is classified as {level} but no specific suspicious behavior was detected."


@app.route('/scan/<int:file_id>', methods=['GET', 'POST'], endpoint='scan_page')
@login_required
def scan(file_id):
    file = UploadedFile.query.get_or_404(file_id)

    if request.method == 'POST':
        # ---------------- OFFLINE SCAN ---------------- #
        offline_result = enhanced_scan(file.filepath)
        file.hash = offline_result["hash"]

        # ---------------- ONLINE API ---------------- #
        try:
            api_result = check_hash_api(file.hash) or {}
            detected = api_result.get("positives", 0)
            total = api_result.get("engine_count", 0)
            online_risk = int((detected / total) * 100) if total > 0 else 0
        except:
            online_risk = 0

        # ---------------- FINAL RISK ---------------- #
        final_risk = max(offline_result["risk_score"], online_risk)

        # ---------------- SAVE RESULTS FIRST ---------------- #
        file.entropy = offline_result["entropy"]

        # Store suspicious_functions in pattern_result
        if offline_result["suspicious_functions"]:
            file.pattern_result = ", ".join(offline_result["suspicious_functions"][:3])
        elif offline_result["heuristics"]:
            file.pattern_result = ", ".join(offline_result["heuristics"])
        else:
            file.pattern_result = "No suspicious patterns"

        # Store heuristics in signature_status
        if offline_result["heuristics"]:
            file.signature_status = ", ".join(offline_result["heuristics"])
        elif offline_result["suspicious_functions"]:
            file.signature_status = ", ".join(offline_result["suspicious_functions"][:3])
        else:
            file.signature_status = "No signatures detected"

        # Store risky imports
        if offline_result["risky_imports"]:
            file.risky_imports = ", ".join(offline_result["risky_imports"])
        else:
            file.risky_imports = "None"

        file.risk_score = final_risk

        # ---------------- AI ANALYSIS (ONLY ONCE, USING ACTUAL PATTERNS) ---------------- #
        ai_result = analyze_file_ai(
            entropy=offline_result["entropy"],
            patterns=file.pattern_result,  # ← Use the actual patterns, not empty heuristics
            imports=file.risky_imports,
            risk_score=final_risk
        )
        file.ai_analysis = ai_result

        # ---------------- THREAT LEVEL ---------------- #
        if final_risk >= 70:
            file.threat_level = "Critical"
        elif final_risk >= 50:
            file.threat_level = "High"
        elif final_risk >= 30:
            file.threat_level = "Medium"
        else:
            file.threat_level = "Low"

        file.status = "Threat" if final_risk >= 30 else "Safe"

        # ---------------- EXPLANATION ---------------- #
        file.explanation = generate_explanation(file)

        db.session.commit()
        return render_template('scan.html', file=file, result=True)

    # ---------------- GET REQUEST ---------------- #
    return render_template('scan.html', file=file, result=False)


#view at history
@app.route('/view_result/<int:file_id>')
@login_required
def view_result(file_id):
    file = UploadedFile.query.get_or_404(file_id)
    return render_template('scan.html', file=file, result=True)





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

# --------------------- REPORTS --------------------- #
from datetime import datetime, timedelta

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

    # timeline (last 7 days)
    days = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]
    safe_counts = [0]*7
    threat_counts = [0]*7

    for file in files:
        risk = file.risk_score or 0

        # safe count
        if file.status == "Safe":
            safe += 1

        # severity
        if risk >= 70:
            critical += 1
        elif risk >= 50:
            high += 1
        elif risk >= 30:
            medium += 1
        else:
            low += 1

        # timeline grouping
        day_index = file.upload_time.weekday()  # 0=Mon
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

    # ✅ Generate explanation (FIX)
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
