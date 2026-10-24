Markdown
# 🛡️ CyberGuard - Advanced Network Security & SaaS Intelligence Platform

CyberGuard is a next-generation, multi-route web-based network intelligence and vulnerability scanner built with **Flask**, **SQLAlchemy**, **Tailwind CSS**, **Chart.js**, and **ReportLab**. It provides real-time subnet device discovery, socket port inspections, automated Discord webhook alerts, and professional PDF security audit reports.

---

## 🚀 Key Features

* **Authentication & User Profiles:** Secure user registration, login powered by Flask-Login, and editable user profiles (Username, Email, Phone, Bio, and Password management).
* **Active Subnet Discovery:** Scans the local network/subnet using Scapy to detect active devices with real-time IP, MAC address, and hostname mapping.
* **Socket Port Inspector:** Scans common TCP ports, detects running services, extracts banners, and categorizes vulnerabilities by precise risk levels (High, Medium, Low).
* **Instant Webhook Alerts:** Automatically triggers instant security alerts to a Discord webhook channel when high-risk open ports are discovered.
* **Interactive Dashboard & Charts:** Real-time metrics, activity timelines, and dynamic risk distribution charts powered by Chart.js.
* **Professional Audit Reports:** Generates and exports downloadable security findings in **PDF**, **CSV**, **JSON**, and **TXT** formats.

---

## 🛠️ Tech Stack

* **Backend:** Python, Flask, Flask-SQLAlchemy, Flask-Login, Scapy, Socket
* **Frontend:** Tailwind CSS, HTML5, JavaScript, Chart.js
* **Reporting:** ReportLab (PDF Generation)
* **Database:** SQLite

---

## ⚙️ Installation & Setup Locally

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/Bhummi-hub/CyberGuard-Network-Scanner.git](https://github.com/Bhummi-hub/CyberGuard-Network-Scanner.git)
   cd CyberGuard-Network-Scanner
Create and activate a virtual environment:

Bash
python -m venv venv
# On Windows:
venv\Scripts\activate
Install dependencies:

Bash
pip install flask flask-sqlalchemy flask-login scapy reportlab werkzeug
Run the application:

Bash
python app.py
Open your browser and navigate to: http://127.0.0.1:5000

📸 Screenshots & Usage
Landing Page: Public-facing overview with fast access to login/signup.

Dashboard: Secured control panel with live graphs and device analytics.

Port Scanner: Terminal-based live logging and risk analysis.

📄 License
This project is developed as an advanced network security portfolio project. Feel free to use and modify for educational purposes.
