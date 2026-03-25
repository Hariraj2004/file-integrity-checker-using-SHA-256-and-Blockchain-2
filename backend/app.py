import os
import sqlite3
from flask import Flask, jsonify, request, send_from_directory, session
from flask_cors import CORS
from werkzeug.utils import secure_filename
from flask_cors import CORS

from backend.database import init_db, get_tamper_logs, DB_PATH, log_activity, get_activity_logs
from backend.monitor import start_monitoring
from backend.system_info import get_system_identity
from backend.hash_utils import sha256_file
from backend.auth import login_required, admin_required, authenticate_user, get_all_users
from datetime import datetime

app = Flask(__name__, static_folder="../frontend")
app.secret_key = os.environ.get("SECRET_KEY", "file-integrity-monitor-secret-2026")
CORS(app, supports_credentials=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RENDER_DISK_PATH = "/data"

# Use Render persistent disk if it exists, otherwise use local directory
STORAGE_DIR = RENDER_DISK_PATH if os.path.exists(RENDER_DISK_PATH) else os.path.dirname(BASE_DIR)

MONITORED_DIR = os.path.join(STORAGE_DIR, "monitored_files")

os.makedirs(MONITORED_DIR, exist_ok=True)
init_db()

def sync_monitored_files():
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        for filename in os.listdir(MONITORED_DIR):
            file_path = os.path.join(MONITORED_DIR, filename)
            if os.path.isfile(file_path):
                file_hash = sha256_file(file_path)
                if not file_hash: continue
                file_size = os.path.getsize(file_path)
                existing = db.execute("SELECT * FROM files WHERE original_name=?", (filename,)).fetchone()
                if not existing:
                    db.execute("""
                        INSERT INTO files (filename, original_name, size, sha256, status, registered, last_check)
                        VALUES (?, ?, ?, ?, 'ok', ?, ?)
                    """, (filename, filename, file_size, file_hash, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ""))
        db.commit()

observer = start_monitoring(MONITORED_DIR)
sync_monitored_files()

# ─── STATIC FILES ─────────────────────────────────────────────
@app.route("/")
def serve_index():
    return send_from_directory("../frontend", "index.html")

@app.route("/<path:path>")
def serve_static(path):
    return send_from_directory("../frontend", path)

# ─── AUTH ROUTES ──────────────────────────────────────────────
@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    user = authenticate_user(username, password)
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    session["username"] = user["username"]
    session["role"] = user["role"]

    # Log login activity with client IP
    client_ip = request.remote_addr or "unknown"
    log_activity(username, "login", ip_address=client_ip)

    return jsonify({
        "success": True,
        "username": user["username"],
        "role": user["role"]
    })

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    username = session.get("username", "unknown")
    client_ip = request.remote_addr or "unknown"
    log_activity(username, "logout", ip_address=client_ip)
    session.clear()
    return jsonify({"success": True})

@app.route("/api/auth/status", methods=["GET"])
def auth_status():
    if session.get("username"):
        return jsonify({
            "logged_in": True,
            "username": session["username"],
            "role": session["role"]
        })
    return jsonify({"logged_in": False})

# ─── SYSTEM INFO ──────────────────────────────────────────────
@app.route("/api/system", methods=["GET"])
@login_required
def get_system():
    return jsonify(get_system_identity())

# ─── STATS ────────────────────────────────────────────────────
@app.route("/api/stats", methods=["GET"])
@login_required
def get_stats():
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        total = db.execute("SELECT COUNT(*) as c FROM files").fetchone()["c"]
        tampered = db.execute("SELECT COUNT(*) as c FROM files WHERE status='tampered'").fetchone()["c"]

    return jsonify({
        "total_files": total,
        "safe_files": total - tampered,
        "tampered_files": tampered
    })

# ─── TAMPER LOGS ──────────────────────────────────────────────
@app.route("/api/logs", methods=["GET"])
@login_required
def get_logs():
    return jsonify(get_tamper_logs())

# ─── FILES ────────────────────────────────────────────────────
@app.route("/api/files", methods=["GET"])
@login_required
def list_files():
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute("SELECT * FROM files ORDER BY id DESC").fetchall()
        return jsonify([dict(r) for r in rows])

@app.route("/api/files/upload", methods=["POST"])
@login_required
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
        
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
        
    filename = secure_filename(file.filename)
    file_path = os.path.join(MONITORED_DIR, filename)
    
    file.save(file_path)
    
    # Calculate hash and add to DB
    file_hash = sha256_file(file_path)
    file_size = os.path.getsize(file_path)
    
    with sqlite3.connect(DB_PATH) as db:
        existing = db.execute("SELECT * FROM files WHERE original_name=?", (filename,)).fetchone()
        if existing:
             db.execute("UPDATE files SET size=?, sha256=?, last_check=?, status='ok' WHERE id=?", 
                       (file_size, file_hash, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), existing[0]))
        else:
            db.execute("""
                INSERT INTO files (filename, original_name, size, sha256, status, registered, last_check)
                VALUES (?, ?, ?, ?, 'ok', ?, ?)
            """, (filename, filename, file_size, file_hash, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ""))
        db.commit()
        
    # Log activity
    client_ip = request.remote_addr or "unknown"
    log_activity(session["username"], "upload", file_name=filename, file_hash=file_hash, ip_address=client_ip)
    
    return jsonify({"success": True, "message": f"File {filename} uploaded and added to registry."})

@app.route("/api/files/verify", methods=["POST"])
@login_required
def verify_file():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
        
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
        
    # Calculate hash of uploaded file
    file_data = file.read()
    from backend.hash_utils import sha256_bytes
    uploaded_hash = sha256_bytes(file_data)
    filename = file.filename
    
    client_ip = request.remote_addr or "unknown"
    status_msg = "Success"
    
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        existing = db.execute("SELECT * FROM files WHERE original_name=?", (filename,)).fetchone()
        
        if existing:
            stored_hash = existing["sha256"]
            if uploaded_hash == stored_hash:
                result = {"status": "ok", "message": f"Integrity verified! Hash matches exactly.", "hash": uploaded_hash}
            else:
                result = {"status": "tampered", "message": f"TAMPER DETECTED! Hash does not match the registry.", "expected": stored_hash, "computed": uploaded_hash}
                status_msg = "Tampered"
        else:
            result = {"status": "unknown", "message": f"File not found in the monitored registry.", "hash": uploaded_hash}
            status_msg = "Unknown File"
            
    # Log the verification attempt
    log_activity(session["username"], "verify", file_name=filename, file_hash=uploaded_hash, ip_address=client_ip, status=status_msg)
    
    return jsonify(result)

# ─── ACTIVITY LOG (RBAC) ─────────────────────────────────────
@app.route("/api/activity", methods=["GET"])
@login_required
def get_activity():
    username = session.get("username")
    role = session.get("role")

    if role == "admin":
        logs = get_activity_logs()  # All users
    else:
        logs = get_activity_logs(username=username)  # Own only

    return jsonify(logs)

# ─── USERS LIST (ADMIN ONLY) ─────────────────────────────────
@app.route("/api/users", methods=["GET"])
@admin_required
def list_users():
    return jsonify(get_all_users())

# ─── ENTRY POINT ─────────────────────────────────────────────
if __name__ == "__main__":
    print(f"\n{'═' * 60}")
    print(f"  FILE INTEGRITY MONITOR — Enhanced Backend")
    print(f"  RBAC + Identity Tracking | Flask + SQLite")
    print(f"{'═' * 60}")
    print(f"  Dashboard → http://127.0.0.1:5000")
    print(f"  Monitoring → {MONITORED_DIR}")
    print(f"  Default Admin → admin / admin123")
    print(f"  Default User  → user  / user123")
    print(f"{'═' * 60}\n")
    try:
        app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
    except KeyboardInterrupt:
        observer.stop()
        observer.join()
