from fastapi.staticfiles import StaticFiles
import os
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.responses import RedirectResponse
import cv2
import numpy as np
import pickle
import hashlib
from datetime import datetime
import sqlite3

# Import your original classes from car_security_system.py
from car_security_system import CarDatabase, FaceRecognitionSystem

app = FastAPI()
db = CarDatabase()
face_system = FaceRecognitionSystem()

app.mount("/app_frontend", StaticFiles(directory="app_frontend"), name="app_frontend")

# Enable CORS so your HTML files can talk to this server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return RedirectResponse(url="/app_frontend/login.html")

# --- 1. LOGIN & AUTHENTICATION ---
def get_driver_by_username(db, username):
    conn = sqlite3.connect(db.db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT username, password_hash, full_name FROM users WHERE role = 'driver' AND username = ? AND is_active = 1", (username,))
    driver = cursor.fetchone()
    conn.close()
    return driver if driver else (None, None, None)

@app.post("/api/login")
async def login(username: str = Form(...), password: str = Form(...)):
    owner_user, stored_hash, full_name = db.get_owner_credentials()
    input_hash = hashlib.sha256(password.encode()).hexdigest()

    if username == owner_user and input_hash == stored_hash:
        return {"status": "success", "user": full_name, "role": "owner"}

    # Check for drivers if not owner
    driver_user, driver_hash, driver_full_name = get_driver_by_username(db, username)
    if driver_user and input_hash == driver_hash:
        return {"status": "success", "user": driver_full_name, "role": "driver"}
        
    return {"status": "error", "message": "Invalid credentials"}

# --- 2. FACE VERIFICATION (For verify.html) ---
def get_recognition_threshold(db):
    conn = sqlite3.connect(db.db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT recognition_threshold FROM settings WHERE id = 1")
    threshold = cursor.fetchone()
    conn.close()
    return threshold[0] if threshold else 0.75

@app.post("/api/verify-face")
async def verify_face(face_image: UploadFile = File(...)):
    # Convert uploaded web image to OpenCV format
    contents = await face_image.read()
    nparr = np.frombuffer(contents, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_GRAYSCALE)
    img_resized = cv2.resize(img, (100, 100))
    new_face_data = pickle.dumps(img_resized)

    # Get threshold from your database settings
    threshold = get_recognition_threshold(db)

    existing_faces = db.get_all_face_data()
    is_similar, similarity, _ = face_system.check_face_similarity(new_face_data, existing_faces, threshold)

    if is_similar:
        return {"status": "GRANTED", "match": round(similarity * 100, 1)}
    return {"status": "DENIED", "match": round(similarity * 100, 1)}

# --- 3. SYSTEM STATS (For dashboard.html) ---
def get_system_stats(db):
    conn = sqlite3.connect(db.db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM access_logs")
    total_accesses = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM access_logs WHERE status = 'success' OR status = 'GRANTED'")
    granted = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM access_logs WHERE status = 'failed' OR status = 'DENIED'")
    denied = cursor.fetchone()[0]
    total_users = db.get_user_count()
    conn.close()
    return {
        "total_accesses": total_accesses,
        "granted": granted,
        "denied": denied,
        "total_users": total_users
    }

@app.get("/api/stats")
async def get_stats():
    conn = sqlite3.connect(db.db_file)
    cursor = conn.cursor()
    
    # Count total attempts in the log
    cursor.execute("SELECT COUNT(*) FROM access_logs")
    total = cursor.fetchone()
    
    # Count successful entries (Matches 'success' or 'GRANTED')
    cursor.execute("SELECT COUNT(*) FROM access_logs WHERE status IN ('success', 'GRANTED')")
    granted = cursor.fetchone()
    
    # Count failed entries (Matches 'failed' or 'DENIED')
    cursor.execute("SELECT COUNT(*) FROM access_logs WHERE status IN ('failed', 'DENIED')")
    denied = cursor.fetchone()
    
    # Use your existing db method for user count
    total_users = db.get_user_count() 
    
    conn.close()
    return {
        "total_accesses": total,
        "granted": granted,
        "denied": denied,
        "total_users": total_users,
        "status": "LIVE" # This flag tells the UI to hide "Demo Data"
    }

# --- 4. ACCESS LOGS (For history.html) ---
@app.get("/api/logs")
async def get_logs(limit: int = 10):
    conn = sqlite3.connect(db.db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, username, action, status FROM access_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    logs = [{"timestamp": r[0], "user": r[1], "method": r[2], "status": r[3]} for r in cursor.fetchall()]
    conn.close()
    return {"logs": logs}