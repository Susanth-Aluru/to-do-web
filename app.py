# app.py
"""
Simple Flask backend for the Beautiful To-Do app (file-backed).
- users.json  : list of users { username, password_hash, createdAt }
- todos.json  : dict mapping username -> [ tasks ]
- sessions.json: dict mapping token -> { username, createdAt }

NOT FOR PRODUCTION — demo only. For production use a proper DB, HTTPS, secure session handling, rate-limiting, CSRF, input validation, etc.
"""
import os
import json
import time
import secrets
from pathlib import Path
from functools import wraps
from datetime import datetime
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

BASE = Path(__file__).parent

USERS_FILE = BASE / "users.json"
TODOS_FILE = BASE / "todos.json"
SESSIONS_FILE = BASE / "sessions.json"

# Initialize files if missing
if not USERS_FILE.exists():
    USERS_FILE.write_text("[]", encoding="utf-8")
if not TODOS_FILE.exists():
    TODOS_FILE.write_text("{}", encoding="utf-8")
if not SESSIONS_FILE.exists():
    SESSIONS_FILE.write_text("{}", encoding="utf-8")

app = Flask(__name__, static_folder=".", static_url_path="")
CORS(app, supports_credentials=True)

# ---------- simple file helpers ----------
def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        # return sensible default depending on file type
        if path == SESSIONS_FILE or path == TODOS_FILE:
            return {}
        return []

def write_json(path, data):
    tmp = str(path) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)

def load_users():
    return read_json(USERS_FILE) or []

def save_users(users):
    write_json(USERS_FILE, users)

def load_todos_map():
    return read_json(TODOS_FILE) or {}

def save_todos_map(m):
    write_json(TODOS_FILE, m)

def load_sessions():
    return read_json(SESSIONS_FILE) or {}

def save_sessions(s):
    write_json(SESSIONS_FILE, s)

# ---------- auth helpers ----------
def create_token(username):
    sessions = load_sessions()
    token = secrets.token_urlsafe(32)
    sessions[token] = {"username": username, "createdAt": datetime.utcnow().isoformat()}
    save_sessions(sessions)
    return token

def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify({"error": "missing token"}), 401
        token = header.split(" ", 1)[1]
        sessions = load_sessions()
        s = sessions.get(token)
        if not s:
            return jsonify({"error": "invalid token"}), 401
        request.current_user = s["username"]
        return f(*args, **kwargs)
    return wrapper

# ---------- routes ----------
@app.route("/")
def index():
    # serve index.html (frontend) from same folder
    return send_from_directory(".", "index.html")

@app.route("/api/ping")
def ping():
    return jsonify({"ok": True, "now": datetime.utcnow().isoformat()})

@app.route("/api/signup", methods=["POST"])
def api_signup():
    body = request.get_json() or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    users = load_users()
    if any(u.get("username") == username for u in users):
        return jsonify({"error": "username exists"}), 400

    password_hash = generate_password_hash(password)
    meta = {"username": username, "password_hash": password_hash, "createdAt": datetime.utcnow().isoformat()}
    users.append(meta)
    save_users(users)

    # initialize empty todos for this user
    todos_map = load_todos_map()
    todos_map.setdefault(username, [])
    save_todos_map(todos_map)

    return jsonify({"ok": True, "user": {"username": username, "createdAt": meta["createdAt"]}}), 201

@app.route("/api/login", methods=["POST"])
def api_login():
    body = request.get_json() or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    users = load_users()
    user = next((u for u in users if u.get("username") == username), None)
    if not user or not check_password_hash(user.get("password_hash", ""), password):
        return jsonify({"error": "invalid credentials"}), 401

    token = create_token(username)
    return jsonify({"ok": True, "token": token, "user": {"username": username, "createdAt": user.get("createdAt")}})

@app.route("/api/logout", methods=["POST"])
@token_required
def api_logout():
    header = request.headers.get("Authorization", "")
    token = header.split(" ", 1)[1]
    sessions = load_sessions()
    if token in sessions:
        del sessions[token]
        save_sessions(sessions)
    return jsonify({"ok": True})

@app.route("/api/tasks", methods=["GET"])
@token_required
def api_get_tasks():
    username = request.current_user
    todos_map = load_todos_map()
    return jsonify({"todos": todos_map.get(username, [])})

@app.route("/api/tasks", methods=["POST"])
@token_required
def api_create_task():
    username = request.current_user
    body = request.get_json() or {}
    title = (body.get("title") or "").strip()
    if not title:
        return jsonify({"error": "title required"}), 400

    task_id = "id_" + str(int(time.time()*1000)) + "_" + secrets.token_hex(4)
    task = {
        "id": task_id,
        "title": title,
        "done": bool(body.get("done", False)),
        "important": bool(body.get("important", False)),
        "createdAt": datetime.utcnow().isoformat()
    }
    todos_map = load_todos_map()
    lst = todos_map.get(username, [])
    lst.insert(0, task)
    todos_map[username] = lst
    save_todos_map(todos_map)
    return jsonify({"ok": True, "task": task}), 201

@app.route("/api/tasks/<task_id>", methods=["PUT"])
@token_required
def api_update_task(task_id):
    username = request.current_user
    body = request.get_json() or {}
    todos_map = load_todos_map()
    lst = todos_map.get(username, [])
    for t in lst:
        if t.get("id") == task_id:
            # update allowed fields
            if "title" in body:
                t["title"] = body.get("title", t.get("title"))
            if "done" in body:
                t["done"] = bool(body.get("done"))
            if "important" in body:
                t["important"] = bool(body.get("important"))
            save_todos_map(todos_map)
            return jsonify({"ok": True, "task": t})
    return jsonify({"error": "task not found"}), 404

@app.route("/api/tasks/<task_id>", methods=["DELETE"])
@token_required
def api_delete_task(task_id):
    username = request.current_user
    todos_map = load_todos_map()
    lst = todos_map.get(username, [])
    newlst = [t for t in lst if t.get("id") != task_id]
    todos_map[username] = newlst
    save_todos_map(todos_map)
    return jsonify({"ok": True})

@app.route("/api/tasks/reorder", methods=["POST"])
@token_required
def api_reorder():
    username = request.current_user
    body = request.get_json() or {}
    order = body.get("order")
    if not isinstance(order, list):
        return jsonify({"error": "order must be list of ids"}), 400
    todos_map = load_todos_map()
    lst = todos_map.get(username, [])
    id_to_task = {t["id"]: t for t in lst}
    newlst = [id_to_task[i] for i in order if i in id_to_task]
    todos_map[username] = newlst
    save_todos_map(todos_map)
    return jsonify({"ok": True})

@app.route("/api/export", methods=["GET"])
@token_required
def api_export():
    username = request.current_user
    todos_map = load_todos_map()
    return jsonify({"meta": {"user": username, "exportedAt": datetime.utcnow().isoformat()}, "todos": todos_map.get(username, [])})

@app.route("/api/import", methods=["POST"])
@token_required
def api_import():
    username = request.current_user
    body = request.get_json() or {}
    todos = body.get("todos")
    if not isinstance(todos, list):
        return jsonify({"error": "invalid payload"}), 400
    todos_map = load_todos_map()
    todos_map[username] = todos
    save_todos_map(todos_map)
    return jsonify({"ok": True})

@app.route("/api/info")
def api_info():
    return jsonify({
        "users_file": str(USERS_FILE),
        "todos_file": str(TODOS_FILE),
        "sessions_file": str(SESSIONS_FILE),
        "now": datetime.utcnow().isoformat()
    })

if __name__ == "__main__":
    # debug=True for local development; set to False in production
    app.run(host="0.0.0.0", port=5000, debug=True)
