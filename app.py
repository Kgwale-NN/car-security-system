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

# -- login pin verification (for login.html) ---
@app.post("/api/login")
async def login(password: str = Form(...)):
    # In the web UI, the "password" is a PIN
    input_pin = password

    # 1. Check if it's the Emergency PIN from settings
    conn = sqlite3.connect(db.db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT emergency_pin FROM settings WHERE id = 1")
    emergency_pin = cursor.fetchone()
    conn.close()

    if emergency_pin and input_pin == emergency_pin[0]:
        # Log this specific event
        conn = sqlite3.connect(db.db_file)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO access_logs (username, action, status, details) VALUES (?, ?, ?, ?)",
                       ('System', 'login', 'success', 'Emergency PIN used'))
        conn.commit()
        conn.close()
        return {"status": "success", "user": "EMERGENCY ACCESS", "role": "owner"} # Grant owner role for full access

    # Hash the input for checking against user PINs
    input_hash = hashlib.sha256(input_pin.encode()).hexdigest()

    # 2. Check if it's the Owner's PIN
    owner_user, stored_hash, full_name = db.get_owner_credentials()
    if stored_hash and input_hash == stored_hash:
        return {"status": "success", "user": full_name, "role": "owner"}

    # 3. Check if it's a Driver's PIN
    conn = sqlite3.connect(db.db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT full_name, username FROM users WHERE password_hash = ? AND role = 'driver' AND is_active = 1", (input_hash,))
    driver = cursor.fetchone()
    conn.close()

    if driver:
        # The user's name is the first element, username is the second
        driver_name, driver_username = driver
        return {"status": "success", "user": driver_name, "role": "driver", "username": driver_username}

    return {"status": "error", "message": "Invalid PIN"}

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
    total_tuple = cursor.fetchone()
    total = total_tuple[0] if total_tuple else 0
    
    # Count successful entries (Matches 'success' or 'GRANTED')
    cursor.execute("SELECT COUNT(*) FROM access_logs WHERE status IN ('success', 'GRANTED')")
    granted_tuple = cursor.fetchone()
    granted = granted_tuple[0] if granted_tuple else 0
    
    # Count failed entries (Matches 'failed' or 'DENIED')
    cursor.execute("SELECT COUNT(*) FROM access_logs WHERE status IN ('failed', 'DENIED')")
    denied_tuple = cursor.fetchone()
    denied = denied_tuple[0] if denied_tuple else 0
    
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

# --- 5. DRIVER REGISTRATION (For register.html) ---
@app.post("/api/register")
async def register_driver(
    name: str = Form(...),
    driver_id: str = Form(...), # This is the username
    pin: str = Form(...),
    phone: str = Form(...),
    vehicle_reg: str = Form(...),
    face_image: UploadFile = File(...)
):
    # The frontend is sending the 'driver_id' field, which we'll use as the username.
    username = driver_id

    # Check if user already exists by username
    if db.check_user_exists_by_username(username):
        raise HTTPException(status_code=400, detail="Username (Driver ID) already exists.")

    # Check if user already exists by name (optional but good practice)
    if db.check_user_exists_by_name(name):
        raise HTTPException(status_code=400, detail=f"A user with the name '{name}' is already registered.")

    # Read the face image data
    contents = await face_image.read()
    img = cv2.imdecode(np.frombuffer(contents, np.uint8), cv2.IMREAD_GRAYSCALE)
    img_resized = cv2.resize(img, (100, 100))
    face_data = pickle.dumps(img_resized)

    # Check for face similarity
    existing_faces = db.get_all_face_data()
    if existing_faces:
        # Increase threshold to make it less likely to find a false positive match
        is_similar, similarity, _ = face_system.check_face_similarity(face_data, existing_faces, 0.85)
        if is_similar:
            raise HTTPException(status_code=400, detail=f"This face is too similar to an existing user (match: {similarity:.1%}). Each person can only be registered once.")

    # Register the driver using the new web-specific function
    user_id, error_message = db.register_driver_from_web(
        full_name=name,
        username=username,
        pin=pin,
        face_data=face_data,
        phone=phone,
        vehicle_reg=vehicle_reg
    )

    if error_message:
        raise HTTPException(status_code=500, detail=error_message)

    return {"status": "success", "message": "Driver registered successfully", "user_id": user_id}

# --- 6. USER MANAGEMENT (For manager.html) ---
@app.get("/api/users")
async def get_users():
    """
    Endpoint to retrieve all drivers with their access statistics for the manager dashboard.
    """
    users_data = db.get_all_users_with_stats()
    return {"users": users_data}

# --- 7. GPS TRACKING (For gps.html) ---
from pydantic import BaseModel

class GpsLog(BaseModel):
    latitude: float
    longitude: float

@app.post("/api/log-gps")
async def log_gps_position(data: GpsLog):
    # NOTE: In a real app, you would get the user_id from a session token.
    # For now, we'll hardcode it to the main owner/user for demonstration.
    user_id = 1 
    conn = sqlite3.connect(db.db_file)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO gps_log (user_id, latitude, longitude) VALUES (?, ?, ?)",
        (user_id, data.latitude, data.longitude)
    )
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Position logged"}

@app.get("/api/gps-history")
async def get_gps_history():
    conn = sqlite3.connect(db.db_file)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    # Fetching the last 1000 points for performance reasons
    cursor.execute("SELECT latitude, longitude, timestamp FROM gps_log ORDER BY timestamp ASC LIMIT 1000")
    history = cursor.fetchall()
    conn.close()
    return {"history": [dict(row) for row in history]}

@app.delete("/api/users/{username}")
async def delete_user(username: str):
    """
    Endpoint to permanently delete a user and their associated data.
    """
    success, message = db.delete_user_by_username(username)
    if not success:
        raise HTTPException(status_code=404, detail=message)
    return {"status": "success", "message": message}

from fastapi import Response

@app.get("/api/users/{username}/image")
async def get_user_image(username: str):
    """
    Endpoint to retrieve the face image for a specific user.
    """
    face_data_blob = db.get_face_image_by_username(username)

    if not face_data_blob:
        raise HTTPException(status_code=404, detail="User or image not found.")

    try:
        # Unpickle the data to get the numpy array
        img_array = pickle.loads(face_data_blob)
        
        # Encode the numpy array as a JPEG
        is_success, buffer = cv2.imencode(".jpg", img_array)
        if not is_success:
            raise HTTPException(status_code=500, detail="Failed to encode image.")
            
        # Return the image as a response
        return Response(content=buffer.tobytes(), media_type="image/jpeg")

    except Exception as e:
        # If unpickling or encoding fails
        raise HTTPException(status_code=500, detail=f"Error processing image: {e}")