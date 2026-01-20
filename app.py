#!/usr/bin/env python3
import os
import time
import json
import socket
import subprocess
import threading
from datetime import datetime
from collections import deque, OrderedDict, defaultdict
from urllib.parse import unquote

import psutil
from flask import (
    Flask, request, redirect, session, jsonify,
    send_from_directory, render_template
)

try:
    import geoip2.database
except Exception:
    geoip2 = None

# =========================
# CONFIG
# =========================
APP_SECRET = "CHANGE_THIS_SECRET"
ADMIN_PASSWORD = "admin123"

HOST = "0.0.0.0"
PORT = 5000

# DDoS thresholds
RPS_THRESHOLD = 40
CONN_THRESHOLD = 150
RECOVERY_DELAY = 15
MITIGATION_DELAY = 0.06

# Memory limits
METRICS_INTERVAL = 1.0
REQUEST_LOG_MAX = 4000
ATTACKERS_MAX = 2000
TOP_IPS_RETURN = 15

MEDIA_DIR = "media"
SNAPSHOT_DIR = "snapshots"
GEOIP_DB = "geoip/GeoLite2-Country.mmdb"

MEDIA_PAGE_SIZE_DEFAULT = 30
MEDIA_PAGE_SIZE_MAX = 100

# Storage limit for MEDIA folder
MAX_MEDIA_STORAGE_GB = 8.0

# Image limit
MAX_IMAGE_MB = 24

# Video tiers
TIER_A_MAX_MB = 50
TIER_A_TTL_SEC = 30 * 24 * 3600    # 30 days
TIER_A_MAX_ACTIVE = 60

TIER_B_MAX_MB = 100
TIER_B_TTL_SEC = 15 * 24 * 3600   # 15 days
TIER_B_MAX_ACTIVE = 40

TIER_C_MAX_MB = 200
TIER_C_TTL_SEC = 42 * 3600        # 42 hours
TIER_C_MAX_ACTIVE = 20
TIER_C_AGREE_REQUIRED = True

# Persistence
META_DB = "media_meta.json"
VIEWS_DB = "media_views.json"

# =========================
# INIT
# =========================
app = Flask(__name__)
app.secret_key = APP_SECRET

os.makedirs(MEDIA_DIR, exist_ok=True)
os.makedirs(SNAPSHOT_DIR, exist_ok=True)

REQUEST_LOG = deque(maxlen=REQUEST_LOG_MAX)
ATTACKERS = OrderedDict()  # ip -> count
ATTACK_TIMELINE = deque(maxlen=500)
GRAPH = {k: deque(maxlen=120) for k in ["cpu", "ram", "rps", "conn", "drop"]}

DDOS_ACTIVE = False
MITIGATION = False
DDOS_REASON = ""
LAST_ATTACK_TIME = 0

TOTAL_UPLOAD_BYTES = 0
TOTAL_DOWNLOAD_BYTES = 0
LAST_UPLOAD = {"name": None, "size": 0, "time": 0}

_last_net_sent = 0
_last_net_recv = 0
_last_speed_ts = time.time()

CACHED = {
    "cpu": 0.0,
    "ram": 0.0,
    "connections": 0,
    "drops": 0,
    "auth_failures": 0,

    "net_up_mbps": 0.0,
    "net_down_mbps": 0.0,
    "bandwidth_total_gb": 0.0,

    "disk_used_percent": 0.0,
    "disk_used_gb": 0.0,
    "disk_total_gb": 0.0,

    "media_size_bytes": 0,
    "media_size_label": "0 MB",
    "media_files_total": 0,
    "media_images": 0,
    "media_videos": 0,
}

# GeoIP optional
GEO = None
if geoip2 is not None and os.path.exists(GEOIP_DB):
    try:
        GEO = geoip2.database.Reader(GEOIP_DB)
    except Exception:
        GEO = None

# State
_lock = threading.Lock()
MEDIA_VIEWS = {}  # filename -> views
MEDIA_META = {}   # filename -> meta dict

# =========================
# BASIC UTILS
# =========================
def now_ts() -> int:
    return int(time.time())

def bytes_to_mb(b: int) -> float:
    return round(b / (1024**2), 2)

def bytes_to_gb(b: int) -> float:
    return round(b / (1024**3), 3)

def human_media_size(b: int) -> str:
    mb = b / (1024**2)
    if mb < 1024:
        return f"{round(mb,2)} MB"
    return f"{round(mb/1024,3)} GB"

def fmt_ts(ts: int) -> str:
    if not ts:
        return "N/A"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")

def local_ip(v6: bool = False) -> str:
    try:
        fam = socket.AF_INET6 if v6 else socket.AF_INET
        target = ("2001:4860:4860::8888", 80) if v6 else ("8.8.8.8", 80)
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.connect(target)
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "N/A"

def rps(interval: int = 5) -> float:
    now = time.time()
    cnt = 0
    for t in REQUEST_LOG:
        if now - t <= interval:
            cnt += 1
    return round(cnt / interval, 2)

def established_connections() -> int:
    try:
        out = subprocess.check_output(
            ["ss", "-Htan", "state", "established"],
            stderr=subprocess.DEVNULL,
            text=True
        )
        return len([ln for ln in out.splitlines() if ln.strip()])
    except Exception:
        return 0

def iptables_drops() -> int:
    try:
        out = subprocess.check_output(
            ["iptables", "-nvx", "-L", "INPUT"],
            stderr=subprocess.DEVNULL,
            text=True
        )
        drops = 0
        for line in out.splitlines():
            if "DROP" in line:
                parts = line.split()
                if parts and parts[0].isdigit():
                    drops += int(parts[0])
        return drops
    except Exception:
        return 0

def auth_failures() -> int:
    patterns = ["Failed password", "authentication failure"]
    paths = ["/var/log/auth.log", "/var/log/secure"]

    for p in paths:
        if os.path.exists(p):
            try:
                out = subprocess.check_output(
                    ["grep", "-E", "|".join(patterns), p],
                    stderr=subprocess.DEVNULL,
                    text=True
                )
                return len([ln for ln in out.splitlines() if ln.strip()])
            except Exception:
                pass

    try:
        out = subprocess.check_output(
            ["journalctl", "-u", "ssh", "--since", "24 hours ago", "--no-pager"],
            stderr=subprocess.DEVNULL,
            text=True
        )
        count = 0
        for ln in out.splitlines():
            if any(pat in ln for pat in patterns):
                count += 1
        return count
    except Exception:
        return 0

def geo_lookup_country(ip: str) -> str:
    if GEO is None:
        return "UN"
    try:
        res = GEO.country(ip)
        return res.country.iso_code or "UN"
    except Exception:
        return "UN"

def track_ip(ip: str):
    if ip in ATTACKERS:
        ATTACKERS[ip] += 1
        ATTACKERS.move_to_end(ip)
    else:
        ATTACKERS[ip] = 1
        if len(ATTACKERS) > ATTACKERS_MAX:
            ATTACKERS.popitem(last=False)

def get_top_ips(n=15):
    items = sorted(ATTACKERS.items(), key=lambda x: x[1], reverse=True)[:n]
    for ip, count in items:
        yield {"ip": ip, "count": count, "country": geo_lookup_country(ip)}

def file_kind(name: str) -> str:
    ext = name.lower().split(".")[-1] if "." in name else ""
    if ext in ["jpg", "jpeg", "png", "gif", "webp", "bmp"]:
        return "image"
    if ext in ["mp4", "webm", "mkv", "mov", "avi"]:
        return "video"
    return "other"

def is_allowed_file(name: str) -> bool:
    return file_kind(name) in ("image", "video")

def load_json(path: str, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path: str, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)

def load_state():
    global MEDIA_VIEWS, MEDIA_META
    with _lock:
        MEDIA_VIEWS = load_json(VIEWS_DB, {})
        MEDIA_META = load_json(META_DB, {})

def save_state():
    with _lock:
        save_json(VIEWS_DB, MEDIA_VIEWS)
        save_json(META_DB, MEDIA_META)

load_state()

# =========================
# POLICY HELPERS
# =========================
def media_scan_basic():
    total_bytes = 0
    total_files = 0
    images = 0
    videos = 0
    for fn in os.listdir(MEDIA_DIR):
        p = os.path.join(MEDIA_DIR, fn)
        if not os.path.isfile(p):
            continue
        total_files += 1
        k = file_kind(fn)
        if k == "image":
            images += 1
        elif k == "video":
            videos += 1
        try:
            total_bytes += os.path.getsize(p)
        except Exception:
            pass
    return total_bytes, total_files, images, videos

def disk_usage_info():
    try:
        return psutil.disk_usage(os.path.abspath(MEDIA_DIR))
    except Exception:
        return None

def projected_storage_ok(add_bytes: int) -> bool:
    projected_gb = bytes_to_gb(CACHED["media_size_bytes"] + add_bytes)
    return projected_gb <= MAX_MEDIA_STORAGE_GB

def get_video_tier(size_mb: float):
    if size_mb <= TIER_A_MAX_MB:
        return "A", TIER_A_TTL_SEC
    if size_mb <= TIER_B_MAX_MB:
        return "B", TIER_B_TTL_SEC
    if size_mb <= TIER_C_MAX_MB:
        return "C", TIER_C_TTL_SEC
    return None, None

def is_locked_autodelete(name: str) -> bool:
    with _lock:
        meta = MEDIA_META.get(name, {})
    return meta.get("kind") == "video" and meta.get("tier") in ("A", "B", "C")

def active_tier_counts():
    now = now_ts()
    a = b = c = 0
    with _lock:
        for name, m in MEDIA_META.items():
            if m.get("kind") != "video":
                continue
            path = os.path.join(MEDIA_DIR, name)
            if not os.path.isfile(path):
                continue
            delete_at = int(m.get("delete_at", 0) or 0)
            if delete_at <= now:
                continue
            tier = m.get("tier")
            if tier == "A":
                a += 1
            elif tier == "B":
                b += 1
            elif tier == "C":
                c += 1
    return a, b, c

def remaining_slots():
    a, b, c = active_tier_counts()
    return {
        "A_left": max(0, TIER_A_MAX_ACTIVE - a),
        "B_left": max(0, TIER_B_MAX_ACTIVE - b),
        "C_left": max(0, TIER_C_MAX_ACTIVE - c),
        "A_used": a, "B_used": b, "C_used": c
    }

def next_expiring(limit=12):
    now = now_ts()
    items = []
    with _lock:
        for name, m in MEDIA_META.items():
            path = os.path.join(MEDIA_DIR, name)
            if not os.path.isfile(path):
                continue
            delete_at = int(m.get("delete_at", 0) or 0)
            if delete_at <= now:
                continue
            items.append({
                "name": name,
                "kind": m.get("kind"),
                "tier": m.get("tier"),
                "size_mb": round((int(m.get("size_bytes", 0)) / (1024**2)), 2),
                "uploaded_at": int(m.get("uploaded_at", 0) or 0),
                "delete_at": delete_at,
                "left_sec": delete_at - now
            })
    items.sort(key=lambda x: x["delete_at"])
    return items[:limit]

# =========================
# DDOS + snapshot
# =========================
def snapshot_attack(reason: str):
    data = {
        "time": time.time(),
        "reason": reason,
        "cpu": CACHED["cpu"],
        "ram": CACHED["ram"],
        "rps": rps(),
        "connections_established": CACHED["connections"],
        "iptables_drops": CACHED["drops"],
        "auth_failures": CACHED["auth_failures"],
        "top_attackers": list(get_top_ips(50)),
        "total_upload_bytes": TOTAL_UPLOAD_BYTES,
        "total_download_bytes": TOTAL_DOWNLOAD_BYTES,
    }
    fname = os.path.join(SNAPSHOT_DIR, f"attack_{int(time.time())}.json")
    with open(fname, "w") as f:
        json.dump(data, f, indent=2)

def ddos_monitor():
    global DDOS_ACTIVE, MITIGATION, DDOS_REASON, LAST_ATTACK_TIME
    now = time.time()
    current_rps = rps()
    conn = CACHED["connections"]
    cpu = CACHED["cpu"]

    attack = False
    reason = ""

    if current_rps > RPS_THRESHOLD:
        attack, reason = True, "High RPS"
    elif conn > CONN_THRESHOLD:
        attack, reason = True, "Connection flood"
    elif cpu > 90:
        attack, reason = True, "CPU exhaustion"

    if attack:
        LAST_ATTACK_TIME = now
        if not DDOS_ACTIVE:
            DDOS_ACTIVE = True
            MITIGATION = True
            DDOS_REASON = reason
            ATTACK_TIMELINE.append({"event": "START", "time": now, "reason": reason})
            snapshot_attack(reason)
        else:
            DDOS_REASON = reason
    else:
        if DDOS_ACTIVE and (now - LAST_ATTACK_TIME) > RECOVERY_DELAY:
            DDOS_ACTIVE = False
            MITIGATION = False
            DDOS_REASON = ""
            ATTACK_TIMELINE.append({"event": "END", "time": now, "reason": "Normal"})

# =========================
# BACKGROUND: metrics + speed + auto delete
# =========================
def sampler_loop():
    global _last_net_sent, _last_net_recv, _last_speed_ts
    while True:
        try:
            CACHED["cpu"] = psutil.cpu_percent(interval=0.0)
            CACHED["ram"] = psutil.virtual_memory().percent
            CACHED["connections"] = established_connections()
            CACHED["drops"] = iptables_drops()
            CACHED["auth_failures"] = auth_failures()

            net = psutil.net_io_counters()
            sent = net.bytes_sent
            recv = net.bytes_recv

            now = time.time()
            dt = max(0.5, now - _last_speed_ts)
            ds = max(0, sent - _last_net_sent)
            dr = max(0, recv - _last_net_recv)

            CACHED["net_up_mbps"] = round((ds * 8) / (dt * 1_000_000), 3)
            CACHED["net_down_mbps"] = round((dr * 8) / (dt * 1_000_000), 3)

            _last_net_sent, _last_net_recv, _last_speed_ts = sent, recv, now
            CACHED["bandwidth_total_gb"] = round(bytes_to_gb(sent + recv), 3)

            du = disk_usage_info()
            if du:
                CACHED["disk_used_percent"] = du.percent
                CACHED["disk_used_gb"] = round(du.used / (1024**3), 2)
                CACHED["disk_total_gb"] = round(du.total / (1024**3), 2)

            total_bytes, total_files, images, videos = media_scan_basic()
            CACHED["media_size_bytes"] = total_bytes
            CACHED["media_size_label"] = human_media_size(total_bytes)
            CACHED["media_files_total"] = total_files
            CACHED["media_images"] = images
            CACHED["media_videos"] = videos

            GRAPH["cpu"].append(CACHED["cpu"])
            GRAPH["ram"].append(CACHED["ram"])
            GRAPH["rps"].append(rps())
            GRAPH["conn"].append(CACHED["connections"])
            GRAPH["drop"].append(CACHED["drops"])
        except Exception:
            pass
        time.sleep(METRICS_INTERVAL)

def delete_scheduler_loop():
    while True:
        try:
            now = now_ts()
            to_delete = []
            with _lock:
                for name, m in list(MEDIA_META.items()):
                    delete_at = int(m.get("delete_at", 0) or 0)
                    if delete_at and delete_at <= now:
                        to_delete.append(name)

            if to_delete:
                for name in to_delete:
                    safe = os.path.basename(name)
                    path = os.path.join(MEDIA_DIR, safe)
                    if os.path.isfile(path):
                        try:
                            os.remove(path)
                        except Exception:
                            pass
                    with _lock:
                        MEDIA_META.pop(safe, None)
                        MEDIA_VIEWS.pop(safe, None)
                save_state()
        except Exception:
            pass
        time.sleep(15)

threading.Thread(target=sampler_loop, daemon=True).start()
threading.Thread(target=delete_scheduler_loop, daemon=True).start()

# =========================
# REQUEST TRACKING + MITIGATION
# =========================
@app.before_request
def track_and_protect():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "UNKNOWN"
    REQUEST_LOG.append(time.time())
    track_ip(ip)

    ddos_monitor()

    if MITIGATION:
        time.sleep(MITIGATION_DELAY)
        if rps() > (RPS_THRESHOLD * 1.5):
            return "Mitigation active\n", 429

# =========================
# ROUTES
# =========================
@app.route("/")
def home():
    if session.get("admin"):
        return redirect("/dashboard")
    return redirect("/login-page")

@app.route("/login-page")
def login_page():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    pw = request.form.get("password", "")
    if pw == ADMIN_PASSWORD:
        session["admin"] = True
        return jsonify({"status": "ok"})
    return jsonify({"status": "fail"}), 403

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login-page")

@app.route("/dashboard")
def dashboard():
    if not session.get("admin"):
        return redirect("/login-page")
    v4 = f"http://{local_ip(False)}:{PORT}/media"
    v6ip = local_ip(True)
    v6 = f"http://[{v6ip}]:{PORT}/media" if v6ip != "N/A" else "N/A"
    return render_template("dashboard.html", v4=v4, v6=v6)

# =========================
# MEDIA SERVE (COUNT DOWNLOAD + VIEWS)
# =========================
@app.route("/media/<path:filename>")
def media(filename):
    global TOTAL_DOWNLOAD_BYTES
    safe = os.path.basename(filename)
    path = os.path.join(MEDIA_DIR, safe)

    if os.path.isfile(path):
        try:
            TOTAL_DOWNLOAD_BYTES += os.path.getsize(path)
        except Exception:
            pass

        with _lock:
            MEDIA_VIEWS[safe] = int(MEDIA_VIEWS.get(safe, 0)) + 1
        save_state()

    return send_from_directory(MEDIA_DIR, safe)

# =========================
# UPLOAD
# =========================
@app.route("/api/upload", methods=["POST"])
def upload():
    global TOTAL_UPLOAD_BYTES, LAST_UPLOAD

    if not session.get("admin"):
        return "Forbidden", 403

    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "no_file"}), 400

    name = os.path.basename(f.filename)
    if not is_allowed_file(name):
        return jsonify({"error": "filetype_not_allowed"}), 400

    kind = file_kind(name)
    tmp_name = f".upload_tmp_{int(time.time())}_{name}"
    tmp_path = os.path.join(MEDIA_DIR, tmp_name)
    f.save(tmp_path)

    try:
        size_bytes = os.path.getsize(tmp_path)
    except Exception:
        try: os.remove(tmp_path)
        except Exception: pass
        return jsonify({"error": "size_unknown"}), 400

    size_mb = size_bytes / (1024**2)
    uploaded_at = now_ts()

    if not projected_storage_ok(size_bytes):
        os.remove(tmp_path)
        return jsonify({"error": "storage_limit", "detail": f"Media storage would exceed {MAX_MEDIA_STORAGE_GB} GB"}), 400

    # Image
    if kind == "image":
        if size_mb > MAX_IMAGE_MB:
            os.remove(tmp_path)
            return jsonify({"error": "image_too_large", "limit_mb": MAX_IMAGE_MB}), 400

        final_path = os.path.join(MEDIA_DIR, name)
        os.replace(tmp_path, final_path)

        TOTAL_UPLOAD_BYTES += size_bytes
        LAST_UPLOAD = {"name": name, "size": size_bytes, "time": uploaded_at}

        with _lock:
            MEDIA_META[name] = {
                "kind": "image",
                "size_bytes": int(size_bytes),
                "uploaded_at": uploaded_at,
                "expire_at": 0,
                "delete_at": 0,
                "tier": ""
            }
        save_state()

        base = f"{request.scheme}://{request.host}"
        return jsonify({"ok": True, "filename": name, "url": f"{base}/media/{name}", "size_mb": round(size_mb,2)})

    # Video
    tier, ttl = get_video_tier(size_mb)
    if tier is None:
        os.remove(tmp_path)
        return jsonify({"error": "video_too_large", "limit_mb": TIER_C_MAX_MB}), 400

    slots = remaining_slots()
    if tier == "A" and slots["A_left"] <= 0:
        os.remove(tmp_path)
        return jsonify({"error": "tier_limit", "detail": "Tier A limit reached (<=50MB: 60 videos)"}), 400
    if tier == "B" and slots["B_left"] <= 0:
        os.remove(tmp_path)
        return jsonify({"error": "tier_limit", "detail": "Tier B limit reached (50-100MB: 40 videos)"}), 400
    if tier == "C" and slots["C_left"] <= 0:
        os.remove(tmp_path)
        return jsonify({"error": "tier_limit", "detail": "Tier C limit reached (100-200MB: 20 videos)"}), 400

    agree = (request.form.get("agree_autodelete", "0") == "1")
    if tier == "C" and TIER_C_AGREE_REQUIRED and not agree:
        os.remove(tmp_path)
        return jsonify({
            "error": "needs_autodelete_agree",
            "detail": "100–200MB videos require auto-delete after 42 hours (check the agree box)."
        }), 400

    final_path = os.path.join(MEDIA_DIR, name)
    os.replace(tmp_path, final_path)

    expire_at = uploaded_at + int(ttl)
    delete_at = expire_at

    with _lock:
        MEDIA_META[name] = {
            "kind": "video",
            "size_bytes": int(size_bytes),
            "uploaded_at": uploaded_at,
            "expire_at": expire_at,
            "delete_at": delete_at,
            "tier": tier
        }
    save_state()

    TOTAL_UPLOAD_BYTES += size_bytes
    LAST_UPLOAD = {"name": name, "size": size_bytes, "time": uploaded_at}

    base = f"{request.scheme}://{request.host}"
    return jsonify({
        "ok": True,
        "filename": name,
        "url": f"{base}/media/{name}",
        "size_mb": round(size_mb,2),
        "tier": tier,
        "delete_at": delete_at
    })

# =========================
# MEDIA LIST
# =========================
@app.route("/api/media/list")
def media_list():
    if not session.get("admin"):
        return jsonify({"error": "unauthorized"}), 401

    try: offset = int(request.args.get("offset", "0"))
    except Exception: offset = 0
    try: limit = int(request.args.get("limit", str(MEDIA_PAGE_SIZE_DEFAULT)))
    except Exception: limit = MEDIA_PAGE_SIZE_DEFAULT
    limit = max(1, min(limit, MEDIA_PAGE_SIZE_MAX))
    offset = max(0, offset)

    q = (request.args.get("q", "") or "").strip().lower()
    kind_filter = (request.args.get("kind", "") or "").strip().lower()
    sort_by = (request.args.get("sort", "mtime") or "mtime").strip().lower()
    order = (request.args.get("order", "desc") or "desc").strip().lower()

    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")

    def parse_day(s):
        try:
            return int(datetime.strptime(s, "%Y-%m-%d").timestamp())
        except Exception:
            return None

    df = parse_day(date_from) if date_from else None
    dt = parse_day(date_to) if date_to else None
    if dt is not None:
        dt += 24 * 3600

    base = f"{request.scheme}://{request.host}"
    items = []

    for name in os.listdir(MEDIA_DIR):
        path = os.path.join(MEDIA_DIR, name)
        if not os.path.isfile(path):
            continue

        k = file_kind(name)
        if kind_filter and k != kind_filter:
            continue
        if q and q not in name.lower():
            continue

        st = os.stat(path)
        mtime = int(st.st_mtime)
        if df is not None and mtime < df:
            continue
        if dt is not None and mtime > dt:
            continue

        with _lock:
            views = int(MEDIA_VIEWS.get(name, 0))
            meta = MEDIA_META.get(name, {})
            delete_at = int(meta.get("delete_at", 0) or 0)
            uploaded_at = int(meta.get("uploaded_at", 0) or 0)
            tier = meta.get("tier", "")

        items.append({
            "name": name,
            "kind": k,
            "size": int(st.st_size),
            "mtime": mtime,
            "views": views,
            "tier": tier,
            "uploaded_at": uploaded_at,
            "delete_at": delete_at,
            "locked_delete": (k == "video" and tier in ("A","B","C")),
            "url": f"{base}/media/{name}",
        })

    key_map = {
        "name": lambda x: x["name"].lower(),
        "size": lambda x: x["size"],
        "mtime": lambda x: x["mtime"],
        "views": lambda x: x["views"],
        "delete_at": lambda x: x["delete_at"] or 2**31
    }
    key_fn = key_map.get(sort_by, key_map["mtime"])
    reverse = (order != "asc")
    items.sort(key=key_fn, reverse=reverse)

    total = len(items)
    page = items[offset:offset + limit]
    return jsonify({"items": page, "total": total, "offset": offset, "limit": limit})

# =========================
# SCHEDULE DELETE
# =========================
@app.route("/api/media/schedule-delete", methods=["POST"])
def media_schedule_delete():
    if not session.get("admin"):
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    filename = unquote(str(data.get("name", "")))
    delete_ts = int(data.get("delete_ts", 0) or 0)

    safe = os.path.basename(filename)
    if not safe or safe != filename:
        return jsonify({"error": "invalid_filename"}), 400

    path = os.path.join(MEDIA_DIR, safe)
    if not os.path.isfile(path):
        return jsonify({"error": "not_found"}), 404

    with _lock:
        if safe not in MEDIA_META:
            MEDIA_META[safe] = {
                "kind": file_kind(safe),
                "size_bytes": os.path.getsize(path),
                "uploaded_at": now_ts(),
                "expire_at": 0,
                "delete_at": 0,
                "tier": ""
            }

        # cancel
        if delete_ts <= 0:
            if is_locked_autodelete(safe):
                return jsonify({
                    "error": "locked_autodelete",
                    "detail": "Auto delete cannot be canceled for restricted tier videos."
                }), 400

            MEDIA_META[safe]["delete_at"] = 0
            save_state()
            return jsonify({"ok": True, "scheduled": False})

        # minimum 1 min
        if delete_ts <= now_ts() + 60:
            return jsonify({"error": "too_soon", "detail": "Minimum 1 minute from now"}), 400

        # locked tier video: allow earlier only, not extension
        if is_locked_autodelete(safe):
            current = int(MEDIA_META[safe].get("delete_at", 0) or 0)
            if current and delete_ts > current:
                return jsonify({
                    "error": "locked_autodelete",
                    "detail": "Restricted tier videos can only be deleted earlier, not extended."
                }), 400

        MEDIA_META[safe]["delete_at"] = delete_ts
        save_state()
        return jsonify({"ok": True, "scheduled": True, "delete_at": delete_ts})

# =========================
# DELETE
# =========================
@app.route("/api/media/delete", methods=["POST"])
def media_delete():
    if not session.get("admin"):
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    filename = unquote(str(data.get("name", "")))
    safe = os.path.basename(filename)
    if not safe or safe != filename:
        return jsonify({"error": "invalid_filename"}), 400
    path = os.path.join(MEDIA_DIR, safe)
    if not os.path.isfile(path):
        return jsonify({"error": "not_found"}), 404
    os.remove(path)
    with _lock:
        MEDIA_META.pop(safe, None)
        MEDIA_VIEWS.pop(safe, None)
    save_state()
    return jsonify({"ok": True, "deleted": safe})

@app.route("/api/media/delete-bulk", methods=["POST"])
def media_delete_bulk():
    if not session.get("admin"):
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    names = data.get("names", [])
    if not isinstance(names, list):
        return jsonify({"error": "invalid"}), 400

    deleted, skipped = [], []
    for raw in names[:200]:
        filename = unquote(str(raw))
        safe = os.path.basename(filename)
        if not safe or safe != filename:
            skipped.append(filename); continue
        path = os.path.join(MEDIA_DIR, safe)
        if os.path.isfile(path):
            try:
                os.remove(path)
                deleted.append(safe)
            except Exception:
                skipped.append(safe)
        else:
            skipped.append(safe)

        with _lock:
            MEDIA_META.pop(safe, None)
            MEDIA_VIEWS.pop(safe, None)
    save_state()
    return jsonify({"ok": True, "deleted": deleted, "skipped": skipped})

# =========================
# STATS
# =========================
@app.route("/api/stats")
def api_stats():
    if not session.get("admin"):
        return jsonify({"error": "unauthorized"}), 401

    top_ips = list(get_top_ips(TOP_IPS_RETURN))
    geo_map = defaultdict(int)
    for item in top_ips:
        geo_map[item["country"]] += item["count"]

    with _lock:
        if MEDIA_VIEWS:
            name, views = max(MEDIA_VIEWS.items(), key=lambda x: int(x[1]))
            top_viewed = {"name": name, "views": int(views)}
        else:
            top_viewed = {"name": None, "views": 0}

    slots = remaining_slots()

    used_gb = bytes_to_gb(CACHED["media_size_bytes"])
    left_gb = max(0.0, MAX_MEDIA_STORAGE_GB - used_gb)
    left_mb = round(left_gb * 1024, 2)

    expiring = next_expiring(12)
    for e in expiring:
        e["uploaded_at_str"] = fmt_ts(e["uploaded_at"])
        e["delete_at_str"] = fmt_ts(e["delete_at"])
        hrs = e["left_sec"] / 3600
        e["left_str"] = f"{round(hrs/24,2)} days" if hrs >= 48 else f"{round(hrs,2)} hours"

    return jsonify({
        "cpu": CACHED["cpu"],
        "ram": CACHED["ram"],
        "rps": rps(),
        "connections": CACHED["connections"],
        "drops": CACHED["drops"],
        "auth_failures": CACHED["auth_failures"],

        "net_up_mbps": CACHED["net_up_mbps"],
        "net_down_mbps": CACHED["net_down_mbps"],
        "bandwidth_total_gb": CACHED["bandwidth_total_gb"],

        "disk_used_percent": CACHED["disk_used_percent"],
        "disk_used_gb": CACHED["disk_used_gb"],
        "disk_total_gb": CACHED["disk_total_gb"],

        "media_size_label": CACHED["media_size_label"],
        "media_files_total": CACHED["media_files_total"],
        "media_images": CACHED["media_images"],
        "media_videos": CACHED["media_videos"],

        "tierA_used": slots["A_used"], "tierA_left": slots["A_left"], "tierA_ttl_days": 30,
        "tierB_used": slots["B_used"], "tierB_left": slots["B_left"], "tierB_ttl_days": 15,
        "tierC_used": slots["C_used"], "tierC_left": slots["C_left"], "tierC_ttl_hours": 42,

        "storage_limit_gb": MAX_MEDIA_STORAGE_GB,
        "storage_used_gb": round(used_gb, 3),
        "storage_left_mb": left_mb,

        "total_upload_mb": round(bytes_to_mb(TOTAL_UPLOAD_BYTES), 2),
        "total_download_mb": round(bytes_to_mb(TOTAL_DOWNLOAD_BYTES), 2),
        "last_upload": LAST_UPLOAD,
        "top_viewed": top_viewed,

        "expiring": expiring,

        "ddos": DDOS_ACTIVE,
        "mitigation": MITIGATION,
        "reason": DDOS_REASON,
        "timeline": list(ATTACK_TIMELINE)[-20:],
        "graph": {k: list(v) for k, v in GRAPH.items()},

        "geo": dict(geo_map),
        "top_ips": top_ips,
        "geo_enabled": (GEO is not None),
    })

# =========================
# BACKGROUND THREADS STARTED ABOVE
# (sampler_loop + delete_scheduler_loop)
# =========================

# Need to define and start them here (since full file)
def sampler_loop():
    global _last_net_sent, _last_net_recv, _last_speed_ts
    while True:
        try:
            CACHED["cpu"] = psutil.cpu_percent(interval=0.0)
            CACHED["ram"] = psutil.virtual_memory().percent
            CACHED["connections"] = established_connections()
            CACHED["drops"] = iptables_drops()
            CACHED["auth_failures"] = auth_failures()

            net = psutil.net_io_counters()
            sent = net.bytes_sent
            recv = net.bytes_recv

            now = time.time()
            dt = max(0.5, now - _last_speed_ts)
            ds = max(0, sent - _last_net_sent)
            dr = max(0, recv - _last_net_recv)

            CACHED["net_up_mbps"] = round((ds * 8) / (dt * 1_000_000), 3)
            CACHED["net_down_mbps"] = round((dr * 8) / (dt * 1_000_000), 3)

            _last_net_sent, _last_net_recv, _last_speed_ts = sent, recv, now
            CACHED["bandwidth_total_gb"] = round(bytes_to_gb(sent + recv), 3)

            du = disk_usage_info()
            if du:
                CACHED["disk_used_percent"] = du.percent
                CACHED["disk_used_gb"] = round(du.used / (1024**3), 2)
                CACHED["disk_total_gb"] = round(du.total / (1024**3), 2)

            total_bytes, total_files, images, videos = media_scan_basic()
            CACHED["media_size_bytes"] = total_bytes
            CACHED["media_size_label"] = human_media_size(total_bytes)
            CACHED["media_files_total"] = total_files
            CACHED["media_images"] = images
            CACHED["media_videos"] = videos

            GRAPH["cpu"].append(CACHED["cpu"])
            GRAPH["ram"].append(CACHED["ram"])
            GRAPH["rps"].append(rps())
            GRAPH["conn"].append(CACHED["connections"])
            GRAPH["drop"].append(CACHED["drops"])
        except Exception:
            pass
        time.sleep(METRICS_INTERVAL)

def delete_scheduler_loop():
    while True:
        try:
            now = now_ts()
            to_delete = []
            with _lock:
                for name, m in list(MEDIA_META.items()):
                    delete_at = int(m.get("delete_at", 0) or 0)
                    if delete_at and delete_at <= now:
                        to_delete.append(name)

            if to_delete:
                for name in to_delete:
                    safe = os.path.basename(name)
                    path = os.path.join(MEDIA_DIR, safe)
                    if os.path.isfile(path):
                        try:
                            os.remove(path)
                        except Exception:
                            pass
                    with _lock:
                        MEDIA_META.pop(safe, None)
                        MEDIA_VIEWS.pop(safe, None)
                save_state()
        except Exception:
            pass
        time.sleep(15)

threading.Thread(target=sampler_loop, daemon=True).start()
threading.Thread(target=delete_scheduler_loop, daemon=True).start()

# =========================
# RUN
# =========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
