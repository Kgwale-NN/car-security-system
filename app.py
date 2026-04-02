import os
import re
import cv2
import numpy as np
import pickle
import hashlib
import sqlite3
from datetime import datetime

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

# ── Import the actual classes from car_security.py ─────────────────────────
from car_security import CarDatabase, SecurityManager, FaceEngine

app = FastAPI(title="BioCar Security API")

# ── Initialise singletons ───────────────────────────────────────────────────
security = SecurityManager()
db       = CarDatabase()

# ── Lazy-load FaceEngine (it downloads ~200MB models on first use) ──────────
_face_engine = None

def _get_face() -> FaceEngine:
    global _face_engine
    if _face_engine is None:
        _face_engine = FaceEngine()
    return _face_engine

# ── Static files & CORS ─────────────────────────────────────────────────────
app.mount("/app_frontend", StaticFiles(directory="app_frontend"), name="frontend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return RedirectResponse(url="/app_frontend/login.html")

# ═══════════════════════════════════════════════════════════════════════════
#  1. LOGIN  — PIN-based (face handled by /api/verify-face)
# ═══════════════════════════════════════════════════════════════════════════
@app.post("/api/login")
async def login(password: str = Form(...)):
    pin = password.strip()
    if not pin:
        return {"status": "error", "message": "PIN required"}

    # Check emergency PIN first (raw PBKDF2 check in CarDatabase)
    if db.verify_pin(pin):
        db.log_access(None, "Emergency", "pin_login", "granted", "Emergency PIN used")
        return {"status": "success", "user": "Emergency Access", "role": "owner", "username": ""}

    # Check all users — PBKDF2 with per-user salt
    conn = db.get_conn()
    c    = conn.cursor()
    c.execute("SELECT id, username, password_hash, salt, full_name, role FROM users")
    rows = c.fetchall()
    conn.close()

    for uid, uname, pw_hash, salt, full_name, role in rows:
        if not pw_hash or not salt:
            continue
        computed = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), 100000).hex()
        if computed == pw_hash:
            db.log_access(uid, uname, "pin_login", "granted", f"role={role}")
            return {"status": "success", "user": full_name, "role": role, "username": uname}

    db.log_access(None, "Unknown", "pin_login", "denied", "Wrong PIN")
    return {"status": "error", "message": "Invalid PIN"}


# ═══════════════════════════════════════════════════════════════════════════
#  2. FACE VERIFY  (login.html face tab + verify.html)
# ═══════════════════════════════════════════════════════════════════════════
@app.post("/api/verify-face")
async def verify_face(face_image: UploadFile = File(...)):
    contents = await face_image.read()
    nparr    = np.frombuffer(contents, np.uint8)
    img_bgr  = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

    if img_bgr is None:
        raise HTTPException(status_code=400, detail="Could not decode image")

    face       = _get_face()
    _, _, thr  = db.get_settings()
    registered = db.all_embeddings()

    if not registered:
        return {"status": "DENIED", "message": "No registered users"}

    faces_detected = face.app.get(img_bgr)
    if not faces_detected:
        db.log_access(None, "Unknown", "face_verify", "denied", "No face in frame")
        return {"status": "DENIED", "message": "No face detected"}

    det  = max(faces_detected, key=lambda f: (f.bbox[2]-f.bbox[0])*(f.bbox[3]-f.bbox[1]))
    emb  = det.embedding
    norm = emb / np.linalg.norm(emb)

    best_dist = 9.9
    best_uid  = None
    best_name = None
    best_role = None

    for uid, stored, name, role in registered:
        s_norm = stored / np.linalg.norm(stored)
        dist   = float(1.0 - np.dot(norm, s_norm))
        if dist < best_dist:
            best_dist = dist
            best_uid  = uid
            best_name = name
            best_role = role

    best_uname = ""
    if best_uid:
        conn = db.get_conn(); c = conn.cursor()
        c.execute("SELECT username FROM users WHERE id=?", (best_uid,))
        row = c.fetchone(); conn.close()
        best_uname = row[0] if row else ""

    match_pct = max(0, round((1 - best_dist / 2) * 100, 1))

    if best_uid and best_dist <= thr:
        db.log_access(best_uid, best_name, "face_verify", "granted", f"dist={best_dist:.4f}")
        return {"status": "GRANTED", "user": best_name, "role": best_role,
                "username": best_uname, "match": match_pct}

    db.log_access(None, "Unknown", "face_verify", "denied", f"best_dist={best_dist:.4f}")
    return {"status": "DENIED", "match": match_pct}


# ═══════════════════════════════════════════════════════════════════════════
#  3. IGNITION VERIFY  — 1:1 check before engine start (verify.html)
# ═══════════════════════════════════════════════════════════════════════════
@app.post("/api/verify-ignition")
async def verify_ignition(face_image: UploadFile = File(...), username: str = Form(...)):
    conn = db.get_conn(); c = conn.cursor()
    c.execute("SELECT id, full_name, role, face_embedding FROM users WHERE username=?", (username,))
    row = c.fetchone(); conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    uid, full_name, role, face_blob = row

    if not face_blob:
        raise HTTPException(status_code=400, detail="No face data registered for this user")

    stored_emb = pickle.loads(security.decrypt_data(face_blob))

    contents = await face_image.read()
    nparr    = np.frombuffer(contents, np.uint8)
    img_bgr  = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img_bgr is None:
        raise HTTPException(status_code=400, detail="Invalid image")

    face       = _get_face()
    _, _, thr  = db.get_settings()

    faces_detected = face.app.get(img_bgr)
    if not faces_detected:
        db.log_access(uid, username, "ignition_verify", "denied", "No face in frame")
        return {"status": "DENIED", "message": "No face detected"}

    det  = max(faces_detected, key=lambda f: (f.bbox[2]-f.bbox[0])*(f.bbox[3]-f.bbox[1]))
    emb  = det.embedding
    norm = emb / np.linalg.norm(emb)
    s_n  = stored_emb / np.linalg.norm(stored_emb)
    dist = float(1.0 - np.dot(norm, s_n))

    match_pct = max(0, round((1 - dist / 2) * 100, 1))

    if dist <= thr:
        db.log_access(uid, username, "ignition_verify", "granted", f"dist={dist:.4f}")
        return {"status": "GRANTED", "user": full_name, "match": match_pct}

    db.log_access(uid, username, "ignition_verify", "denied", f"dist={dist:.4f}")
    return {"status": "DENIED", "match": match_pct}


# ═══════════════════════════════════════════════════════════════════════════
#  4. STATS
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/api/stats")
async def get_stats():
    conn = db.get_conn(); c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM access_logs"); total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM access_logs WHERE status='granted'"); granted = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM access_logs WHERE status='denied'"); denied = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM users"); total_users = c.fetchone()[0]
    conn.close()
    return {"total_accesses": total, "granted": granted, "denied": denied,
            "total_users": total_users, "status": "LIVE"}


# ═══════════════════════════════════════════════════════════════════════════
#  5. ACCESS LOGS
# ═══════════════════════════════════════════════════════════════════════════
def _map_method(action: str) -> str:
    """Map raw action strings from both car_security.py and app.py to FACE/PIN."""
    a = (action or "").lower()
    # Face-based actions
    if a in ("vehicle_start", "face_verify", "ignition_verify"):
        return "FACE"
    # PIN-based actions
    if a in ("pin_start", "pin_login"):
        return "PIN"
    # Fallback: scan for keywords
    if "face" in a or "ignition" in a:
        return "FACE"
    if "pin" in a:
        return "PIN"
    return a.upper()

def _parse_match_score(action: str, details: str) -> "int | None":
    """Extract cosine-distance match score from details and convert to 0-100%."""
    m = re.search(r"dist=([\d.]+)", details or "")
    if m:
        dist = float(m.group(1))
        # cosine dist 0.0 = identical (100%), 2.0 = opposite (0%)
        pct = max(0, round((1.0 - dist / 2.0) * 100))
        return pct
    return None

@app.get("/api/logs")
async def get_logs(limit: int = 50):
    conn = db.get_conn()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(
        "SELECT id, timestamp, user_id, username, action, status, details "
        "FROM access_logs ORDER BY timestamp DESC LIMIT ?",
        (min(limit, 500),)
    )
    rows = c.fetchall()

    # Build a quick user_id → username lookup so we can resolve
    # logs written by car_security.py (which store full_name as username)
    c.execute("SELECT id, username, full_name FROM users")
    uid_map = {r["id"]: r["username"] for r in c.fetchall()}

    # Build GPS lookup: for each log entry, find the closest GPS point in time
    # Load all GPS points once and match by timestamp proximity
    gps_by_uid: dict = {}
    try:
        c.execute(
            "SELECT user_id, username, latitude, longitude, timestamp "
            "FROM gps_log ORDER BY timestamp DESC"
        )
        gps_rows = c.fetchall()
        # Group last known position per user_id (most recent first, so first = latest)
        for g in gps_rows:
            key = g["user_id"] if g["user_id"] else g["username"]
            if key not in gps_by_uid:
                gps_by_uid[key] = (g["latitude"], g["longitude"])
    except Exception:
        pass  # gps_log table may not have entries yet

    conn.close()

    logs = []
    for r in rows:
        action  = r["action"] or ""
        details = r["details"] or ""
        status_raw = (r["status"] or "").lower()
        status  = "GRANTED" if status_raw == "granted" else "DENIED" if status_raw == "denied" else status_raw.upper()

        # Resolve canonical username
        uid = r["user_id"]
        if uid and uid in uid_map:
            display_user = uid_map[uid]
        else:
            display_user = r["username"] or "Unknown"

        # Find GPS location for this log entry
        gps_coords = None
        if uid and uid in gps_by_uid:
            lat, lon = gps_by_uid[uid]
            gps_coords = f"{lat:.5f}, {lon:.5f}"
        elif display_user in gps_by_uid:
            lat, lon = gps_by_uid[display_user]
            gps_coords = f"{lat:.5f}, {lon:.5f}"

        logs.append({
            "timestamp":     r["timestamp"],
            "user":          display_user,
            "method":        _map_method(action),
            "status":        status,
            "details":       details,
            "match_score":   _parse_match_score(action, details),
            "gps_location":  gps_coords,
            "engine_status": "ENABLED" if status == "GRANTED" else "LOCKED",
        })
    return {"logs": logs}


# ═══════════════════════════════════════════════════════════════════════════
#  6. USERS — JOIN on user_id (not username) to handle full_name vs username mismatch
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/api/users")
async def get_users():
    conn = db.get_conn()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(
        """SELECT u.id, u.username, u.full_name, u.role, u.created_date,
                  (u.face_embedding IS NOT NULL) AS has_face,
                  COUNT(a.id)      AS total_accesses,
                  MAX(a.timestamp) AS last_access
           FROM users u
           LEFT JOIN access_logs a ON a.user_id = u.id
           GROUP BY u.id
           ORDER BY u.role DESC, u.full_name"""
    )
    rows = c.fetchall(); conn.close()
    return {"users": [
        {
            "id":                   r["id"],
            "driver_id":            r["username"],
            "name":                 r["full_name"],
            "role":                 r["role"],
            "status":               "ACTIVE",
            "has_face_image":       bool(r["has_face"]),
            "total_accesses":       r["total_accesses"],
            "last_access":          r["last_access"],
            "registered_date":      r["created_date"],
            "phone":                "—",
            "vehicle_registration": "—",
        } for r in rows
    ]}


@app.delete("/api/users/{username}")
async def delete_user(username: str):
    conn = db.get_conn(); c = conn.cursor()
    c.execute("SELECT id, full_name, role FROM users WHERE username=?", (username,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    uid, name, role = row
    c.execute("DELETE FROM users WHERE id=?", (uid,))
    conn.commit(); conn.close()
    db.log_event("USER_DELETED", "INFO", f"Deleted {role}: {name} (@{username})")
    return {"status": "success", "message": f"{name} deleted"}


# ═══════════════════════════════════════════════════════════════════════════
#  7. USER FACE AVATAR
#     InsightFace stores embeddings, not pixel images.
#     We return a 404 so the dashboard falls back to a silhouette icon.
#     If you later store actual photos, replace this endpoint.
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/api/users/{username}/image")
async def get_user_image(username: str):
    raise HTTPException(status_code=404, detail="Pixel image not available — embedding only")


# ═══════════════════════════════════════════════════════════════════════════
#  8. REGISTER DRIVER
# ═══════════════════════════════════════════════════════════════════════════
@app.post("/api/register")
async def register_driver(
    name:        str        = Form(...),
    driver_id:   str        = Form(...),
    pin:         str        = Form(...),
    phone:       str        = Form(""),
    vehicle_reg: str        = Form(""),
    face_image:  UploadFile = File(...),
):
    if db.username_taken(driver_id):
        raise HTTPException(status_code=400, detail="Driver ID already in use")
    if db.name_taken(name):
        raise HTTPException(status_code=400, detail=f"A user named '{name}' is already registered")

    contents = await face_image.read()
    nparr    = np.frombuffer(contents, np.uint8)
    img_bgr  = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img_bgr is None:
        raise HTTPException(status_code=400, detail="Invalid face image")

    face = _get_face()
    faces_detected = face.app.get(img_bgr)
    if not faces_detected:
        raise HTTPException(status_code=400, detail="No face detected — use better lighting")

    det = max(faces_detected, key=lambda f: (f.bbox[2]-f.bbox[0])*(f.bbox[3]-f.bbox[1]))
    emb = det.embedding

    existing = db.all_embeddings()
    if existing:
        is_dup, dist, dup_name = face.is_duplicate(emb, existing)
        if is_dup:
            raise HTTPException(
                status_code=400,
                detail=f"Face already registered as '{dup_name}' (dist={dist:.3f})"
            )

    salt    = os.urandom(32).hex()
    pw_hash = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), 100000).hex()
    blob    = security.encrypt_data(pickle.dumps(emb))

    if not db.add_user(driver_id, pw_hash, salt, "driver", name, blob):
        raise HTTPException(status_code=500, detail="Database error")

    db.log_event("DRIVER_REGISTERED", "INFO", f"{name} registered via web")
    return {"status": "success", "message": "Driver registered successfully"}


# ═══════════════════════════════════════════════════════════════════════════
#  9. GPS
# ═══════════════════════════════════════════════════════════════════════════
class GpsLog(BaseModel):
    latitude:  float
    longitude: float
    username:  str = ""

def _ensure_gps_table():
    conn = db.get_conn(); c = conn.cursor()
    c.execute(
        """CREATE TABLE IF NOT EXISTS gps_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id   INTEGER,
            username  TEXT,
            latitude  REAL,
            longitude REAL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    conn.commit(); conn.close()

_ensure_gps_table()


@app.post("/api/log-gps")
async def log_gps_position(data: GpsLog):
    conn = db.get_conn(); c = conn.cursor()
    uid = None
    if data.username:
        c.execute("SELECT id FROM users WHERE username=?", (data.username,))
        row = c.fetchone()
        uid = row[0] if row else None
    c.execute(
        "INSERT INTO gps_log (user_id, username, latitude, longitude) VALUES (?,?,?,?)",
        (uid, data.username, data.latitude, data.longitude)
    )
    conn.commit(); conn.close()
    return {"status": "success"}


@app.get("/api/gps-history")
async def get_gps_history(username: str = ""):
    conn = db.get_conn()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    if username:
        c.execute(
            "SELECT latitude, longitude, timestamp FROM gps_log "
            "WHERE username=? ORDER BY timestamp ASC LIMIT 1000",
            (username,)
        )
    else:
        c.execute(
            "SELECT latitude, longitude, timestamp FROM gps_log "
            "ORDER BY timestamp ASC LIMIT 1000"
        )
    rows = c.fetchall(); conn.close()
    return {"history": [dict(r) for r in rows]}


# ═══════════════════════════════════════════════════════════════════════════
#  10. SETTINGS
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/api/settings")
async def get_settings():
    sh, eh, thr = db.get_settings()
    return {"allowed_start_hour": sh, "allowed_end_hour": eh, "recognition_threshold": thr}


class HoursPayload(BaseModel):
    start_hour: int
    end_hour:   int

@app.post("/api/settings/hours")
async def update_hours(payload: HoursPayload):
    if not (0 <= payload.start_hour <= 23 and 0 <= payload.end_hour <= 23):
        raise HTTPException(status_code=400, detail="Hours must be 0-23")
    if payload.start_hour >= payload.end_hour:
        raise HTTPException(status_code=400, detail="Start must be before end")
    db.update_hours(payload.start_hour, payload.end_hour)
    return {"status": "success"}


class ThresholdPayload(BaseModel):
    threshold: float

@app.post("/api/settings/threshold")
async def update_threshold(payload: ThresholdPayload):
    if not (0.25 <= payload.threshold <= 0.60):
        raise HTTPException(status_code=400, detail="Threshold 0.25-0.60")
    db.update_threshold(payload.threshold)
    return {"status": "success"}


# ═══════════════════════════════════════════════════════════════════════════
#  11. SECURITY EVENTS
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/api/events")
async def get_events(limit: int = 50):
    conn = db.get_conn()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(
        "SELECT timestamp, event_type, severity, details "
        "FROM security_events ORDER BY timestamp DESC LIMIT ?",
        (min(limit, 200),)
    )
    rows = c.fetchall(); conn.close()
    return {"events": [dict(r) for r in rows]}