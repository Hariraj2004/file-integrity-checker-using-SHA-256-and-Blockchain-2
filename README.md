# Enhanced File Integrity Monitoring System with RBAC and Client Identity Tracking

## 📖 Project Overview
This project is an upgraded, SOC-style File Integrity Checker designed for real-world cybersecurity practices. The system monitors file integrity using SHA-256 hashing and detects unauthorized modifications in real-time.

It features **client identity tracking** (MAC, IP, Timestamp, Hostname) and **role-based access control (RBAC)**, driven by a Flask backend and a modern glassmorphism frontend dashboard.

## 🎯 Features
- **Real-time File Monitoring** (Watchdog)
- **SHA-256 Hash Verification**
- **Client Identity Tracking** (Logs MAC address, IP, hostname, and timestamp per action)
- **Role-Based Access Control (RBAC):**
  - **Admin (`admin / admin123`)**: Full access. Can view all users, global activity logs, and monitor all files.
  - **User (`user / user123`)**: Restricted access. Can only view their own activity logs.
- **Secure File Upload & Manual Verify UI**
- **Tamper Detection Alerts**
- **Modern SOC-Style Dashboard** (Responsive Glassmorphism UI)

## 🛠️ Technologies Used
- **Backend:** Python, Flask, SQLite, Watchdog, Werkzeug (for password hashing)
- **Frontend:** HTML5, CSS3, Vanilla JavaScript
- **Styling:** Custom CSS (Glassmorphism), FontAwesome icons, Google Fonts

---

## 🚀 How to Run in Kali Linux

Since modern versions of Kali Linux (and other Debian-based distros) enforce PEP 668 ("externally managed environments"), you should use a Python Virtual Environment (`venv`) to run the project safely.

### 1. Open your terminal and navigate to the project directory:
```bash
cd "/home/kali/Desktop/16 night"  # (Or wherever you placed the folder)
```

### 2. Create and activate a Virtual Environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies:
```bash
pip install -r backend/requirements.txt
```

### 4. Start the Application:
The backend and frontend are tightly integrated. The Flask backend automatically serves the frontend dashboard, so you only need to run **one command**:
```bash
python3 -m backend.app
```

### 5. Access the Dashboard:
Open your web browser and go to:
👉 **http://127.0.0.1:5000**

- **Default Admin Login:** `admin` / `admin123`
- **Default User Login:** `user` / `user123`

---

## 📂 Folder Structure
```text
16 night/
│
├── backend/
│   ├── __init__.py
│   ├── app.py             # Flask server & Auth routes
│   ├── auth.py            # RBAC decorators & password validation
│   ├── database.py        # SQLite initialization (users, files, activity_log)
│   ├── hash_utils.py      # SHA-256 file hashing
│   ├── monitor.py         # Watchdog real-time file monitor
│   ├── system_info.py     # MAC, IP, and Hostname retriever
│   ├── requirements.txt   # Python dependencies
│   └── logs/
│       └── tamper_logs.json
│
├── frontend/
│   ├── index.html         # Main dashboard & Login modal
│   ├── style.css          # Glassmorphism UI styling
│   └── script.js          # Auth handling & API logic
│
├── monitored_files/       # Files placed here are monitored in real-time
├── screenshots/           # reserved for documentation
├── docs/                  # reserved for documentation
└── README.md
```
