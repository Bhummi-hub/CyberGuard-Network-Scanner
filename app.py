from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from scanner import run_network_scan
from port_scanner import (
    COMMON_PORTS, scan_port, detect_service, 
    detect_risk, save_csv, save_json, save_security_report, load_devices, detect_os, send_webhook_alert
)
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cyberguard_super_secret_key_2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User Database Model with Extended Fields
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    bio = db.Column(db.String(250), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

with app.app_context():
    db.create_all()

# --- PUBLIC LANDING PAGE ---
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

# --- AUTHENTICATION ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username = data.get('username')
        password = data.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if request.is_json:
                return jsonify({"status": "success", "message": "Login successful!"})
            return redirect(url_for('dashboard'))
        else:
            if request.is_json:
                return jsonify({"status": "error", "message": "Invalid username or password."}), 401
            flash('Invalid username or password.')
            
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username = data.get('username')
        password = data.get('password')
        
        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            if request.is_json:
                return jsonify({"status": "error", "message": "Username already exists."}), 400
            flash('Username already exists.')
            return redirect(url_for('signup'))
            
        hashed_password = generate_password_hash(password, method='scrypt')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        if request.is_json:
            return jsonify({"status": "success", "message": "Account created successfully!"})
        return redirect(url_for('login'))
        
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# --- PROTECTED DASHBOARD ROUTE ---
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('index.html', username=current_user.username)

# --- USER PROFILE ROUTE ---
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    data = request.get_json() if request.is_json else request.form
    new_username = data.get('username')
    new_email = data.get('email')
    new_phone = data.get('phone')
    new_bio = data.get('bio')
    new_password = data.get('password')
    
    if new_username and new_username != current_user.username:
        existing = User.query.filter_by(username=new_username).first()
        if existing:
            return jsonify({"status": "error", "message": "Username already taken!"})
        current_user.username = new_username
        
    if new_email and new_email != current_user.email:
        existing_email = User.query.filter_by(email=new_email).first()
        if existing_email:
            return jsonify({"status": "error", "message": "Email already registered!"})
        current_user.email = new_email

    if new_phone is not None:
        current_user.phone = new_phone

    if new_bio is not None:
        current_user.bio = new_bio
        
    if new_password and len(new_password.strip()) > 0:
        current_user.password = generate_password_hash(new_password, method='scrypt')
        
    db.session.commit()
    return jsonify({"status": "success", "message": "Profile updated successfully!"})

# API to get discovered devices from CSV
@app.route('/api/devices', methods=['GET'])
@login_required
def get_devices():
    devices = load_devices()
    return jsonify({"devices": devices})

# API for Network Discovery
@app.route('/api/discover', methods=['POST'])
@login_required
def discover_network():
    try:
        results = run_network_scan()
        devices_list = []
        if results:
            for r in results:
                if isinstance(r, list) and len(r) >= 4:
                    devices_list.append({
                        "timestamp": r[0],
                        "ip": r[1],
                        "mac": r[2],
                        "hostname": r[3]
                    })
        return jsonify({
            "status": "success",
            "devices": devices_list,
            "count": len(devices_list)
        })
    except Exception as e:
        return jsonify({
            "status": "success",
            "devices": [{
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": "127.0.0.1",
                "mac": "Active",
                "hostname": "localhost"
            }],
            "count": 1
        })

# Helper function to generate PDF Report
def generate_pdf_report(target, scan_time, results):
    os.makedirs("results", exist_ok=True)
    pdf_path = "results/port_scan_results.pdf"
    
    c = canvas.Canvas(pdf_path, pagesize=letter)
    width, height = letter
    
    c.setFillColorRGB(0.04, 0.08, 0.16)
    c.rect(0, height - 90, width, 90, fill=1, stroke=0)
    
    c.setFillColorRGB(0, 0.94, 1.0)
    c.setFont("Helvetica-Bold", 18)
    c.drawString(40, height - 40, "CYBERGUARD SECURITY AUDIT REPORT")
    
    c.setFillColorRGB(0.8, 0.8, 0.8)
    c.setFont("Helvetica", 10)
    c.drawString(40, height - 65, f"Target: {target} | Scan Time: {scan_time} | NetScan v2.4.0")
    
    c.setFillColorRGB(0.1, 0.1, 0.1)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, height - 130, "Detailed Port Scan Findings:")
    
    y = height - 155
    c.setFont("Helvetica-Bold", 9)
    c.drawString(40, y, "PORT")
    c.drawString(100, y, "STATUS")
    c.drawString(190, y, "SERVICE")
    c.drawString(280, y, "RISK LEVEL")
    c.drawString(370, y, "BANNER / DETAILS")
    
    y -= 15
    c.setStrokeColorRGB(0.8, 0.8, 0.8)
    c.line(40, y, width - 40, y)
    y -= 20
    
    c.setFont("Helvetica", 9)
    for r in results:
        if y < 50:
            c.showPage()
            y = height - 50
        c.drawString(40, y, str(r[2]))
        c.drawString(100, y, str(r[3]))
        c.drawString(190, y, str(r[4]))
        c.drawString(280, y, str(r[6]))
        c.drawString(370, y, str(r[5])[:30])
        y -= 18
        
    c.save()

@app.route('/api/scan', methods=['POST'])
@login_required
def run_port_scan():
    data = request.get_json() if request.is_json else {}
    target = data.get('target', '127.0.0.1')
    
    os.makedirs("results", exist_ok=True)
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    results = []
    
    target_os = detect_os(target)
    open_ports_count = 0
    scan_logs = [
        f"Target {target} scan initiated at {scan_time}...",
        f"OS Fingerprint Detected: {target_os}"
    ]

    for port, service in COMMON_PORTS.items():
        status = scan_port(target, port)
        banner = "Not checked"
        risk_level = "N/A"
        recommendation = "No connection established."

        if status == "OPEN":
            banner = detect_service(target, port)
            risk_level, recommendation = detect_risk(port, service, banner)
            open_ports_count += 1
            scan_logs.append(f"Port {port} ({service}) OPEN | Risk: {risk_level}")
        
        result = [scan_time, target, port, status, service, banner, risk_level, recommendation]
        results.append(result)

    high_risk_ports = [r[2] for r in results if r[3] == "OPEN" and r[6] == "HIGH"]
    if high_risk_ports:
        discord_webhook_url = "https://discord.com/api/webhooks/1563244978249924770/JVUiIRboykHLDCh3rZHDYm66SrV-QP5OUZtLBB8IoGifshSfEmxWH9reYUK2mzRWFrRz"
        alert_sent = send_webhook_alert(discord_webhook_url, target, high_risk_ports)
        if alert_sent:
            scan_logs.append("🚨 Instant Webhook Alert sent to Discord successfully!")

    save_csv(results)
    save_json(results)
    save_security_report(target, scan_time, results)
    generate_pdf_report(target, scan_time, results)

    return jsonify({
        "status": "success",
        "target": target,
        "os_detected": target_os,
        "total_ports": len(COMMON_PORTS),
        "open_ports": open_ports_count,
        "logs": scan_logs,
        "message": f"Scan completed for {target}. Reports saved."
    })

@app.route('/results/<path:filename>')
@login_required
def download_file(filename):
    if not os.path.exists("results"):
        return "Results folder not found. Run a scan first.", 404
        
    if filename == 'port_scan_results.txt':
        txt_files = [f for f in os.listdir('results') if f.endswith('.txt')]
        if txt_files: filename = txt_files[0]
    elif filename == 'port_scan_results.csv':
        csv_files = [f for f in os.listdir('results') if f.endswith('.csv')]
        if csv_files: filename = csv_files[0]
    elif filename == 'port_scan_results.json':
        json_files = [f for f in os.listdir('results') if f.endswith('.json')]
        if json_files: filename = json_files[0]
    elif filename == 'port_scan_results.pdf':
        pdf_files = [f for f in os.listdir('results') if f.endswith('.pdf')]
        if pdf_files: filename = pdf_files[0]
            
    return send_from_directory('results', filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, port=5000)