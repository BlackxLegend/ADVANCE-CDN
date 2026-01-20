import os
import time
import json
import uuid
import psutil
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import (
    Flask, request, redirect, url_for, session, render_template,
    send_from_directory, jsonify, abort, flash
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

# =========================
# Config
# =========================
APP_TZ = timezone.utc

SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-please-long-random")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin123")

# Render: if you attach a Persistent Disk, set DATA_DIR to its mount path (e.g. /var/data)
DATA_DIR = os.environ.get("DATA_DIR", "./data")

MEDIA_DIR = Path(DATA_DIR) / "media"
DB_PATH = Path(DATA_DIR) / "db.json"

MAX_CONTENT_MB = int(os.environ.get("MAX_CONTENT_MB", "250"))  # hard cap for request body
MAX_CONTENT_BYTES = MAX_CONTENT_MB * 1024 * 1024

# Tier rules (you can change)
TIER_A_MAX_MB = 50
TIER_B_MAX_MB = 100
TIER_C_MAX_MB = 200

# Auto delete TTLs
TTL_A_DAYS = 30
TTL_B_DAYS = 15
TTL_C_HOURS = 42  # for 100-200MB, default 42h

# For 50-100MB, you can set a TTL too if you want (default: 15 days already)
# For <=50MB, 30 days

# =========================
# App init
# =========================
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_BYTES

MEDIA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# =========================
# In-memory counters
# =========================
_lock = threading.Lock()
_rps_window = []   # timestamps of requests (float seconds)
_active_requests = 0

def now_utc():
    return datetime.now(APP_TZ)

def iso(dt: datetime) -> str:
    return dt.astimezone(APP_TZ).isoformat()

def parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s).astimezone(APP_TZ)

# =========================
# DB helpers
# =========================
def _default_db():
    return {
        "files": [],  # list of dict
        "traffic": {
            "total_upload_bytes": 0,
            "total_download_bytes": 0
        }
    }

def load_db():
    if not DB_PATH.exists():
        return _default_db()
    try:
        return json.loads(DB_PATH.read_text(encoding="utf-8"))
    except Exception:
        return _default_db()

def save_db(db):
    DB_PATH.write_text(json.dumps(db, indent=2), encoding="utf-8")

def get_disk_usage_bytes():
    # disk usage of DATA_DIR mount
    try:
        usage = psutil.disk_usage(str(Path(DATA_DIR).resolve()))
        return usage.used, usage.total
    except Exception:
        return 0, 0

def choose_tier(size_mb: float) -> str:
    if size_mb <= TIER_A_MAX_MB:
        return "A"
    if size_mb <= TIER_B_MAX_MB:
        return "B"
    if size_mb <= TIER_C_MAX_MB:
        return "C"
    return "X"

def ttl_for_tier(tier: str) -> timedelta:
    if tier == "A":
        return timedelta(days=TTL_A_DAYS)
    if tier == "B":
        return timedelta(days=TTL_B_DAYS)
    if tier == "C":
        return timedelta(hours=TTL_C_HOURS)
    # if >200MB not allowed by default; but if it exists, clean fast:
    return timedelta(hours=6)

def is_logged_in():
    return session.get("logged_in") is True

def require_login():
    if not is_logged_in():
        return redirect(url_for("login", next=request.path))
    return None

# =========================
# Request tracking (RPS/Connections)
# =========================
@app.before_request
def _before():
    global _active_requests
    with _lock:
        _active_requests += 1
        _rps_window.append(time.time())

@app.after_request
def _after(resp):
    global _active_requests
    with _lock:
        _active_requests = max(0, _active_requests - 1)
        # keep last 5 seconds for RPS
        cutoff = time.time() - 5.0
        while _rps_window and _rps_window[0] < cutoff:
            _rps_window.pop(0)
    return resp

# =========================
# Auth routes
# =========================
@app.route("/", methods=["GET"])
def home():
    # send user to dashboard if logged, else login
    if is_logged_in():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    nxt = request.args.get("next") or url_for("dashboard")
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if u == ADMIN_USER and p == ADMIN_PASS:
            session["logged_in"] = True
            return redirect(nxt)
        flash("Invalid login", "error")
    return render_template("login.html", next=nxt)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# =========================
# Dashboard
# =========================
@app.route("/dashboard")
def dashboard():
    gate = require_login()
    if gate:
        return gate
    return render_template("dashboard.html")

# =========================
# API: stats + files
# =========================
@app.route("/api/stats")
def api_stats():
    gate = require_login()
    if gate:
        return abort(401)

    db = load_db()

    cpu = psutil.cpu_percent(interval=0.1)
    ram = psutil.virtual_memory().percent

    with _lock:
        # RPS approximate = requests in last 5 seconds / 5
        rps = round(len(_rps_window) / 5.0, 2)
        conns = _active_requests

    # disk usage
    used_b, total_b = get_disk_usage_bytes()

    # media folder size
    media_bytes = 0
    try:
        for p in MEDIA_DIR.glob("*"):
            if p.is_file():
                media_bytes += p.stat().st_size
    except Exception:
        media_bytes = 0

    total_upload = db["traffic"].get("total_upload_bytes", 0)
    total_download = db["traffic"].get("total_download_bytes", 0)

    # files count (existing ones only)
    files = db.get("files", [])
    existing = [f for f in files if (MEDIA_DIR / f.get("stored_name", "")).exists()]
    img_count = sum(1 for f in existing if f.get("type") == "image")
    vid_count = sum(1 for f in existing if f.get("type") == "video")

    # top viewed
    top = None
    if existing:
        top = max(existing, key=lambda x: int(x.get("views", 0)))
    top_name = top["original_name"] if top else None
    top_views = int(top.get("views", 0)) if top else 0

    base_url = request.host_url.rstrip("/")
    media_base = f"{base_url}/media"

    # These are placeholders; on Render you won’t have iptables/auth.log by default.
    iptables_drops = 0
    ssh_fails = 0

    return jsonify({
        "cpu": cpu,
        "ram": ram,
        "rps": rps,
        "connections": conns,
        "iptables_drops": iptables_drops,
        "ssh_fails": ssh_fails,
        "upload_speed_mbps": 0,
        "download_speed_mbps": 0,
        "bandwidth_total_gb": round((total_upload + total_download) / (1024**3), 3),
        "disk_used_gb": round(used_b / (1024**3), 2),
        "disk_total_gb": round(total_b / (1024**3), 2),
        "media_folder_mb": round(media_bytes / (1024**2), 2),
        "total_images": img_count,
        "total_videos": vid_count,
        "storage_left_mb": round(max(0, (total_b - used_b)) / (1024**2), 0) if total_b else None,
        "top_viewed_file": top_name,
        "top_viewed_count": top_views,
        "media_base": media_base,
    })

@app.route("/api/files")
def api_files():
    gate = require_login()
    if gate:
        return abort(401)

    db = load_db()
    files = db.get("files", [])
    out = []

    for f in files:
        stored = f.get("stored_name", "")
        fp = MEDIA_DIR / stored
        if not fp.exists():
            continue

        uploaded_at = parse_iso(f["uploaded_at"])
        ttl = ttl_for_tier(f["tier"])
        delete_at = uploaded_at + ttl
        left = delete_at - now_utc()

        out.append({
            "original": f.get("original_name"),
            "stored": stored,
            "tier": f.get("tier"),
            "size_mb": round(float(f.get("size_bytes", 0)) / (1024**2), 2),
            "uploaded_at": f.get("uploaded_at"),
            "delete_at": iso(delete_at),
            "left_h": max(0, round(left.total_seconds() / 3600, 1)),
            "views": int(f.get("views", 0)),
            "url": f"{request.host_url.rstrip('/')}/media/{stored}",
        })

    # sort by uploaded newest
    out.sort(key=lambda x: x["uploaded_at"], reverse=True)
    return jsonify(out)

# =========================
# Upload + Serve media
# =========================
def guess_type(filename: str) -> str:
    fn = filename.lower()
    if fn.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp")):
        return "image"
    if fn.endswith((".mp4", ".mov", ".mkv", ".webm", ".avi")):
        return "video"
    return "file"

@app.route("/media", methods=["POST"])
def upload_media():
    gate = require_login()
    if gate:
        return abort(401)

    allow_big = request.form.get("allow_big") == "1"

    if "file" not in request.files:
        return jsonify({"ok": False, "error": "No file field"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"ok": False, "error": "No filename"}), 400

    original = secure_filename(f.filename)

    # Save to temp first to know size
    tmp_name = f"tmp_{uuid.uuid4().hex}"
    tmp_path = MEDIA_DIR / tmp_name
    f.save(tmp_path)

    size_bytes = tmp_path.stat().st_size
    size_mb = size_bytes / (1024**2)

    tier = choose_tier(size_mb)

    # Enforce limits
    if tier == "X":
        tmp_path.unlink(missing_ok=True)
        return jsonify({"ok": False, "error": "File too large (>200MB)"}), 413

    if tier == "C" and not allow_big:
        tmp_path.unlink(missing_ok=True)
        return jsonify({"ok": False, "error": "100-200MB upload blocked. Enable allow_big."}), 403

    # final stored name
    ext = Path(original).suffix.lower()
    stored = f"{uuid.uuid4().hex}{ext}"
    final_path = MEDIA_DIR / stored
    tmp_path.replace(final_path)

    db = load_db()
    db["traffic"]["total_upload_bytes"] = int(db["traffic"].get("total_upload_bytes", 0)) + int(size_bytes)

    db["files"].append({
        "original_name": original,
        "stored_name": stored,
        "size_bytes": int(size_bytes),
        "tier": tier,
        "type": guess_type(original),
        "uploaded_at": iso(now_utc()),
        "views": 0,
    })

    save_db(db)

    return jsonify({
        "ok": True,
        "tier": tier,
        "stored": stored,
        "url": f"{request.host_url.rstrip('/')}/media/{stored}"
    })

@app.route("/media/<path:filename>", methods=["GET", "HEAD"])
def serve_media(filename):
    # Public access: allow viewing/downloading directly
    fp = MEDIA_DIR / filename
    if not fp.exists() or not fp.is_file():
        abort(404)

    # track views/download bytes (only count on GET)
    if request.method == "GET":
        try:
            db = load_db()
            for item in db.get("files", []):
                if item.get("stored_name") == filename:
                    item["views"] = int(item.get("views", 0)) + 1
                    break
            db["traffic"]["total_download_bytes"] = int(db["traffic"].get("total_download_bytes", 0)) + int(fp.stat().st_size)
            save_db(db)
        except Exception:
            pass

    # send
    return send_from_directory(str(MEDIA_DIR), filename, as_attachment=False)

# =========================
# Auto-delete worker
# =========================
def cleanup_loop():
    while True:
        try:
            db = load_db()
            changed = False
            keep = []
            for item in db.get("files", []):
                stored = item.get("stored_name", "")
                fp = MEDIA_DIR / stored
                if not fp.exists():
                    changed = True
                    continue

                uploaded_at = parse_iso(item["uploaded_at"])
                delete_at = uploaded_at + ttl_for_tier(item.get("tier", "A"))

                if now_utc() >= delete_at:
                    fp.unlink(missing_ok=True)
                    changed = True
                    continue

                keep.append(item)

            if changed:
                db["files"] = keep
                save_db(db)
        except Exception:
            pass

        time.sleep(60)  # every minute

threading.Thread(target=cleanup_loop, daemon=True).start()

# =========================
# Local run (Render uses gunicorn)
# =========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
