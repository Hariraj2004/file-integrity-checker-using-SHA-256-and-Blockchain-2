import sqlite3
from functools import wraps
from flask import request, jsonify, session
from werkzeug.security import check_password_hash
from backend.database import DB_PATH, log_activity

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("username"):
            return jsonify({"error": "Unauthorized — please login"}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("username"):
            return jsonify({"error": "Unauthorized — please login"}), 401
        if session.get("role") != "admin":
            return jsonify({"error": "Forbidden — admin access required"}), 403
        return f(*args, **kwargs)
    return decorated

def authenticate_user(username, password):
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            return dict(user)
    return None

def get_all_users():
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute("SELECT id, username, role, created_at FROM users ORDER BY id").fetchall()
        return [dict(r) for r in rows]
