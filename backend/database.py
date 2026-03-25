import os
import json
import sqlite3
import threading
from datetime import datetime
from werkzeug.security import generate_password_hash
from backend.system_info import get_system_identity

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RENDER_DISK_PATH = "/data"

# Use Render persistent disk if it exists, otherwise use local directory
STORAGE_DIR = RENDER_DISK_PATH if os.path.exists(RENDER_DISK_PATH) else BASE_DIR

DB_PATH = os.path.join(STORAGE_DIR, "integrity.db")
LOGS_DIR = os.path.join(STORAGE_DIR, "logs")
TAMPER_LOG_FILE = os.path.join(LOGS_DIR, "tamper_logs.json")

os.makedirs(LOGS_DIR, exist_ok=True)
_db_lock = threading.Lock()

def now_display():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_db():
    db = sqlite3.connect(DB_PATH, check_same_thread=False)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        db.executescript("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                original_name TEXT NOT NULL,
                size INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ok',
                registered TEXT NOT NULL,
                last_check TEXT
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                action_type TEXT NOT NULL,
                file_name TEXT,
                file_hash TEXT,
                mac_address TEXT,
                ip_address TEXT,
                hostname TEXT,
                timestamp TEXT NOT NULL,
                status TEXT DEFAULT 'Success'
            );
        """)
        db.commit()

        # Seed default users if not present
        existing = db.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
        if existing == 0:
            admin_hash = generate_password_hash("admin123")
            user_hash = generate_password_hash("user123")
            now = now_display()
            db.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                       ("admin", admin_hash, "admin", now))
            db.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                       ("user", user_hash, "user", now))
            db.commit()

def log_activity(username, action_type, file_name=None, file_hash=None, ip_address=None, status="Success"):
    identity = get_system_identity()
    with _db_lock:
        with sqlite3.connect(DB_PATH) as db:
            db.execute("""
                INSERT INTO activity_log (username, action_type, file_name, file_hash, mac_address, ip_address, hostname, timestamp, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (username, action_type, file_name, file_hash,
                  identity["mac_address"], ip_address or identity["ip_address"],
                  identity["hostname"], now_display(), status))
            db.commit()

def get_activity_logs(username=None):
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        if username:
            rows = db.execute("SELECT * FROM activity_log WHERE username=? ORDER BY id DESC LIMIT 100", (username,)).fetchall()
        else:
            rows = db.execute("SELECT * FROM activity_log ORDER BY id DESC LIMIT 100").fetchall()
        return [dict(r) for r in rows]

def log_tamper_event(event_type, file_path, old_hash, new_hash, status="Tampered"):
    identity = get_system_identity()

    log_entry = {
        "timestamp": now_display(),
        "event_type": event_type,
        "file_path": file_path,
        "old_hash": old_hash,
        "new_hash": new_hash,
        "mac_address": identity["mac_address"],
        "ip_address": identity["ip_address"],
        "hostname": identity["hostname"],
        "status": status
    }

    with _db_lock:
        logs = []
        if os.path.exists(TAMPER_LOG_FILE):
            try:
                with open(TAMPER_LOG_FILE, "r") as f:
                    logs = json.load(f)
            except json.JSONDecodeError:
                logs = []

        logs.insert(0, log_entry)

        with open(TAMPER_LOG_FILE, "w") as f:
            json.dump(logs, f, indent=2)

    return log_entry

def get_tamper_logs():
    if not os.path.exists(TAMPER_LOG_FILE):
        return []
    try:
        with open(TAMPER_LOG_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []
