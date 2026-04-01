import cv2
import numpy as np
import os
import sqlite3
import hashlib
import time
from datetime import datetime, timedelta
import pickle

print("🚗 CAR SECURITY SYSTEM - DEALERSHIP & DRIVER VERSION")
print("=" * 60)

# ============================================================================
# DATABASE
# ============================================================================

class CarDatabase:
    def __init__(self):
        self.db_file = "car_dealership_system.db"
        self.init_db()
    
    def init_db(self):
        """Initialize database with all required tables and ensure schema is up to date."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        # Check if users table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if not cursor.fetchone():
            # Create tables for the first time
            self._create_tables(cursor)
            print("✅ Database created - Ready for dealership setup")
        else:
            # The table exists, let's check and add columns if they are missing
            self._update_schema(cursor)

        conn.commit()
        conn.close()

    def _create_tables(self, cursor):
        """Creates all necessary tables for a fresh database."""
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password_hash TEXT,
                role TEXT CHECK(role IN ('owner', 'driver')),
                full_name TEXT,
                face_data BLOB,
                is_active INTEGER DEFAULT 1,
                created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                phone TEXT,
                vehicle_registration TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE settings (
                id INTEGER PRIMARY KEY,
                allowed_start_hour INTEGER DEFAULT 6,
                allowed_end_hour INTEGER DEFAULT 23,
                recognition_threshold REAL DEFAULT 0.75,
                emergency_pin TEXT DEFAULT '123456'
            )
        ''')
        cursor.execute('''
            CREATE TABLE access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                action TEXT,
                status TEXT,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE dealership_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT,
                user_affected TEXT,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE gps_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                latitude REAL NOT NULL,
                longitude REAL NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        # Insert default settings
        cursor.execute('INSERT INTO settings (id) VALUES (1)')

    def _update_schema(self, cursor):
        """Adds missing columns and tables to existing database."""
        cursor.execute("PRAGMA table_info(users)")
        columns = [info[1] for info in cursor.fetchall()]
        # Check for 'phone' column
        if 'phone' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN phone TEXT")
            print("🔧 Database schema updated: Added 'phone' column to users table.")
        # Check for 'vehicle_registration' column
        if 'vehicle_registration' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN vehicle_registration TEXT")
            print("🔧 Database schema updated: Added 'vehicle_registration' column to users table.")

        # Check for 'gps_log' table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='gps_log'")
        if not cursor.fetchone():
            cursor.execute('''
                CREATE TABLE gps_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    latitude REAL NOT NULL,
                    longitude REAL NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            print("🔧 Database schema updated: Created 'gps_log' table.")


    
    def get_owner_exists(self):
        """Check if owner is already registered"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'owner' AND is_active = 1")
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0
    
    def get_user_count(self):
        """Get total number of active users"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = 1")
        count = cursor.fetchone()[0]
        conn.close()
        return count
    
    def check_user_exists_by_name(self, full_name):
        """Check if a user is already registered (by name) - any role"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE LOWER(full_name) = LOWER(?) AND is_active = 1", (full_name,))
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0
    
    def check_user_exists_by_username(self, username):
        """Check if a user is already registered (by username)"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE LOWER(username) = LOWER(?) AND is_active = 1", (username,))
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0
    
    def get_all_face_data(self):
        """Get all face data from registered users"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT face_data FROM users WHERE is_active = 1 AND face_data IS NOT NULL")
        face_data_list = [row[0] for row in cursor.fetchall()]
        conn.close()
        return face_data_list
    
    def get_all_registered_persons(self):
        """Get all registered persons (active only)"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT id, full_name, role, username, face_data FROM users WHERE is_active = 1")
        users = cursor.fetchall()
        conn.close()
        return users
    
    def get_owner_credentials(self):
        """Get owner's credentials for verification"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT username, password_hash, full_name FROM users WHERE role = 'owner' AND is_active = 1 LIMIT 1")
        owner = cursor.fetchone()
        conn.close()
        return owner if owner else (None, None, None)

    def register_driver_from_web(self, full_name, username, pin, face_data, phone, vehicle_reg):
        """Registers a new driver from the web interface, including phone and vehicle info."""
        password_hash = hashlib.sha256(pin.encode()).hexdigest()
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (username, password_hash, role, full_name, face_data, phone, vehicle_registration)
                VALUES (?, ?, 'driver', ?, ?, ?, ?)
            ''', (username, password_hash, full_name, face_data, phone, vehicle_reg))
            conn.commit()
            user_id = cursor.lastrowid

            cursor.execute('''
                INSERT INTO dealership_logs (action, user_affected, details)
                VALUES (?, ?, ?)
            ''', ('register_driver_web', username, f'Registered driver via web: {full_name}'))
            conn.commit()

        except sqlite3.IntegrityError:
            conn.close()
            return None, "Username already exists."
        except Exception as e:
            conn.close()
            return None, str(e)
        finally:
            conn.close()

        return user_id, None

    def get_all_users_with_stats(self):
        """
        Fetches all active users and enriches them with access stats.
        This is for the manager dashboard.
        """
        conn = sqlite3.connect(self.db_file)
        # Use a dictionary factory to make it easier to work with columns by name
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Get all users first
        cursor.execute("SELECT id, username, full_name, role, phone, vehicle_registration, is_active, created_date FROM users WHERE role = 'driver'")
        users_result = cursor.fetchall()
        
        users_list = []
        for user_row in users_result:
            user_dict = dict(user_row)
            
            # Now, for each user, get their access stats
            cursor.execute("SELECT COUNT(*) FROM access_logs WHERE username = ?", (user_dict['username'],))
            total_accesses = cursor.fetchone()[0]
            
            cursor.execute("SELECT timestamp FROM access_logs WHERE username = ? ORDER BY timestamp DESC LIMIT 1", (user_dict['username'],))
            last_access_row = cursor.fetchone()
            last_access = last_access_row['timestamp'] if last_access_row else None
            
            # Build the final dictionary for the frontend
            users_list.append({
                "name": user_dict['full_name'],
                "driver_id": user_dict['username'],
                "phone": user_dict['phone'],
                "vehicle_registration": user_dict['vehicle_registration'],
                "status": "ACTIVE" if user_dict['is_active'] else "INACTIVE",
                "total_accesses": total_accesses,
                "last_access": last_access,
                "registered_date": user_dict['created_date'],
                "has_face_image": True if user_dict['face_data'] else False
            })

        conn.close()
        return users_list

    def get_face_image_by_username(self, username):
        """Retrieves the raw face_data blob for a given user."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        # Also retrieve user's full_name for context if needed
        cursor.execute("SELECT face_data, full_name FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None
    
    def delete_user_by_username(self, username):
        """
        Permanently deletes a user and all their associated logs.
        """
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        try:
            # First, get the user_id from the username
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            user_row = cursor.fetchone()
            if not user_row:
                return False, "User not found."

            user_id = user_row[0]

            # Delete from access_logs
            cursor.execute("DELETE FROM access_logs WHERE user_id = ?", (user_id,))
            
            # Delete from gps_log
            cursor.execute("DELETE FROM gps_log WHERE user_id = ?", (user_id,))

            # Delete the user from the users table
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))

            # Log this major action in the dealership log
            cursor.execute(
                "INSERT INTO dealership_logs (action, user_affected, details) VALUES (?, ?, ?)",
                ('delete_user', username, 'User permanently deleted from system.')
            )
            conn.commit()
            return True, "User deleted successfully."

        except Exception as e:
            conn.rollback()
            return False, str(e)
        finally:
            conn.close()
        
    def get_all_users_with_stats(self):
        """
        Fetches all active users and enriches them with access stats.
        This is for the manager dashboard.
        """
        conn = sqlite3.connect(self.db_file)
        # Use a dictionary factory to make it easier to work with columns by name
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Get all users first
        cursor.execute("SELECT id, username, full_name, role, phone, vehicle_registration, is_active, created_date, face_data FROM users WHERE role = 'driver'")
        users_result = cursor.fetchall()
        
        users_list = []
        for user_row in users_result:
            user_dict = dict(user_row)
            
            # Now, for each user, get their access stats
            cursor.execute("SELECT COUNT(*) FROM access_logs WHERE username = ?", (user_dict['username'],))
            total_accesses = cursor.fetchone()[0]
            
            cursor.execute("SELECT timestamp FROM access_logs WHERE username = ? ORDER BY timestamp DESC LIMIT 1", (user_dict['username'],))
            last_access_row = cursor.fetchone()
            last_access = last_access_row['timestamp'] if last_access_row else None
            
            # Build the final dictionary for the frontend
            users_list.append({
                "name": user_dict['full_name'],
                "driver_id": user_dict['username'],
                "phone": user_dict['phone'],
                "vehicle_registration": user_dict['vehicle_registration'],
                "status": "ACTIVE" if user_dict['is_active'] else "INACTIVE",
                "total_accesses": total_accesses,
                "last_access": last_access,
                "registered_date": user_dict['created_date'],
                "has_face_image": True if user_dict['face_data'] else False
            })

        conn.close()
        return users_list

    def delete_user_by_username(self, username):
        """
        Permanently deletes a user and all their associated logs.
        """
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        try:
            # First, get the user_id from the username
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            user_row = cursor.fetchone()
            if not user_row:
                return False, "User not found."

            user_id = user_row[0]

            # Delete from access_logs
            cursor.execute("DELETE FROM access_logs WHERE user_id = ?", (user_id,))
            
            # Delete from gps_log
            cursor.execute("DELETE FROM gps_log WHERE user_id = ?", (user_id,))

            # Delete the user from the users table
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))

            # Log this major action in the dealership log
            cursor.execute(
                "INSERT INTO dealership_logs (action, user_affected, details) VALUES (?, ?, ?)",
                ('delete_user', username, 'User permanently deleted from system.')
            )
            conn.commit()
            return True, "User deleted successfully."

        except Exception as e:
            conn.rollback()
            return False, str(e)
        finally:
            conn.close()

    def get_face_image_by_username(self, username):
        """Retrieves the raw face_data blob for a given user."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT face_data FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None





# ============================================================================
# FACE RECOGNITION
# ============================================================================

class FaceRecognitionSystem:
    def __init__(self):
        self.face_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
    
    def capture_face(self, person_name, role):
        """Capture face for registration"""
        print(f"\n📸 Face capture for {person_name} ({role})")
        print("Look straight at camera")
        print("Press SPACE to capture, Q to cancel")
        
        camera = cv2.VideoCapture(0)
        if not camera.isOpened():
            print("❌ Cannot access camera!")
            return None
        
        face_data = None
        
        while True:
            ret, frame = camera.read()
            if not ret:
                break
            
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = self.face_cascade.detectMultiScale(gray, 1.3, 5)
            
            for (x, y, w, h) in faces:
                cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 255, 0), 2)
            
            cv2.putText(frame, "SPACE = Capture | Q = Cancel", (10, 30),
                       cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2)
            cv2.putText(frame, "Ensure face is clear and well-lit", (10, 60),
                       cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
            
            cv2.imshow(f'Register {person_name}', frame)
            
            key = cv2.waitKey(1)
            if key == 32:  # SPACE
                if len(faces) > 0:
                    x, y, w, h = faces[0]
                    face_img = gray[y:y+h, x:x+w]
                    face_img = cv2.resize(face_img, (100, 100))
                    face_data = pickle.dumps(face_img)
                    print("✅ Face captured successfully!")
                    break
                else:
                    print("❌ No face detected! Try again")
            elif key == ord('q'):
                print("❌ Face capture cancelled")
                break
        
        camera.release()
        cv2.destroyAllWindows()
        return face_data
    
    def verify_face(self, stored_face_data, threshold=0.75):
        """Verify face against stored data"""
        if not stored_face_data:
            return 0.0
        
        stored_face = pickle.loads(stored_face_data)
        
        print("\n🔍 Face verification in progress...")
        print("Look at camera. Press Q to finish")
        
        camera = cv2.VideoCapture(0)
        best_match = 0.0
        
        for _ in range(50):  # Check 50 frames
            ret, frame = camera.read()
            if not ret:
                break
            
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = self.face_cascade.detectMultiScale(gray, 1.3, 5)
            
            for (x, y, w, h) in faces:
                face_img = gray[y:y+h, x:x+w]
                face_img = cv2.resize(face_img, (100, 100))
                
                # Calculate similarity
                difference = np.sum(np.abs(face_img.astype(float) - stored_face.astype(float)))
                similarity = 1 - (difference / (100 * 100 * 255))
                
                if similarity > best_match:
                    best_match = similarity
                
                # Visual feedback
                color = (0, 255, 0) if similarity >= threshold else (0, 0, 255)
                cv2.rectangle(frame, (x, y), (x+w, y+h), color, 2)
                cv2.putText(frame, f"Match: {similarity:.1%}", (x, y-10),
                           cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 2)
            
            cv2.putText(frame, f"Best match: {best_match:.1%}", (10, 30),
                       cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)
            cv2.putText(frame, "Press Q to finish", (10, 60),
                       cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 255), 2)
            
            cv2.imshow('Face Verification', frame)
            
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break
        
        camera.release()
        cv2.destroyAllWindows()
        return best_match
    
    def check_face_similarity(self, new_face_data, existing_face_data_list, threshold=0.7):
        """Check if new face is similar to any existing faces"""
        if not new_face_data or not existing_face_data_list:
            return False, 0.0, None
        
        new_face = pickle.loads(new_face_data)
        
        for existing_face_data in existing_face_data_list:
            if not existing_face_data:
                continue
                
            existing_face = pickle.loads(existing_face_data)
            
            # Calculate similarity
            difference = np.sum(np.abs(new_face.astype(float) - existing_face.astype(float)))
            similarity = 1 - (difference / (100 * 100 * 255))
            
            if similarity >= threshold:
                return True, similarity, existing_face
        
        return False, 0.0, None

# ============================================================================
# DEALERSHIP SYSTEM (FULL CONTROL)
# ============================================================================

class DealershipSystem:
    def __init__(self, db, face_system):
        self.db = db
        self.face_system = face_system
    
    def show_menu(self):
        """Display dealership menu"""
        while True:
            print("\n" + "=" * 60)
            print("🏢 DEALERSHIP MANAGEMENT SYSTEM")
            print("=" * 60)
            
            # Show statistics
            conn = sqlite3.connect(self.db.db_file)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'owner' AND is_active = 1")
            owner_count = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'driver' AND is_active = 1")
            driver_count = cursor.fetchone()[0]
            conn.close()
            
            print(f"\n📊 Current Status:")
            print(f"   Owners: {owner_count}")
            print(f"   Drivers: {driver_count}")
            
            # Show all registered persons
            all_persons = self.db.get_all_registered_persons()
            if all_persons:
                print(f"\n📋 Registered Persons:")
                for user_id, full_name, role, username, face_data in all_persons:
                    role_icon = "👑" if role == "owner" else "👤"
                    has_face = "✅" if face_data else "❌"
                    print(f"   {role_icon} {full_name} ({username}) - {role} {has_face}")
            
            print("\n📋 DEALERSHIP OPTIONS:")
            print("  1. 👑 Register Owner (One-time only)")
            print("  2. 👥 Register Driver")
            print("  3. 🔐 Change Emergency PIN")
            print("  4. 🆘 Reset Emergency PIN (Forgot PIN)")
            print("  5. 🔑 Change Owner Password")
            print("  6. 🆘 Reset Owner Password (Forgot Password)")
            print("  7. 🚫 Deregister User")
            print("  8. 🎯 Change Recognition Threshold")
            print("  9. 📊 View System Logs")
            print(" 10. 🚪 Exit to Main Menu")
            
            choice = input("\nSelect option (1-10): ").strip()
            
            if choice == "1":
                self.register_owner()
            elif choice == "2":
                self.register_driver()
            elif choice == "3":
                self.change_emergency_pin()
            elif choice == "4":
                self.reset_emergency_pin()
            elif choice == "5":
                self.change_owner_password()
            elif choice == "6":
                self.reset_owner_password()
            elif choice == "7":
                self.deregister_user()
            elif choice == "8":
                self.change_recognition_threshold()
            elif choice == "9":
                self.view_system_logs()
            elif choice == "10":
                print("\n👋 Returning to main menu...")
                break
            else:
                print("❌ Invalid option! Please select 1-10")
    
    def register_owner(self):
        """Register owner (ONE-TIME ONLY)"""
        print("\n" + "=" * 60)
        print("👑 REGISTER CAR OWNER")
        print("=" * 60)
        
        # Check if owner already exists
        if self.db.get_owner_exists():
            print("\n❌ Owner already registered!")
            print("Only one owner can be registered per car.")
            print("Use 'Deregister User' to remove current owner first.")
            input("\nPress Enter to continue...")
            return
        
        print("\n⚠️  IMPORTANT: Owner registration is ONE-TIME ONLY")
        print("A person can only be registered ONCE in the system.")
        print("Ensure all information is correct!\n")
        
        full_name = input("Owner's full legal name: ").strip()
        if not full_name:
            print("❌ Name cannot be empty!")
            return
        
        # ============================================================
        # STRICT DUPLICATE CHECK: Check if person already exists in ANY role
        # ============================================================
        if self.db.check_user_exists_by_name(full_name):
            print(f"\n❌ {full_name} is already registered in the system!")
            
            # Get details of existing registration
            conn = sqlite3.connect(self.db.db_file)
            cursor = conn.cursor()
            cursor.execute("SELECT role, username FROM users WHERE LOWER(full_name) = LOWER(?) AND is_active = 1", (full_name,))
            existing_user = cursor.fetchone()
            conn.close()
            
            if existing_user:
                role, username = existing_user
                print(f"This person is already registered as a {role} with username: {username}")
                print("A person CANNOT be registered multiple times, even with different names.")
                print("If you need to change their role, use 'Deregister User' first.")
            
            input("\nPress Enter to continue...")
            return
        
        username = input("Choose username: ").strip()
        if not username:
            print("❌ Username cannot be empty!")
            return
        
        # Check if username already exists
        if self.db.check_user_exists_by_username(username):
            print(f"\n❌ Username '{username}' is already taken!")
            print("Please choose a different username.")
            input("\nPress Enter to continue...")
            return
        
        password = input("Set password: ").strip()
        if len(password) < 4:
            print("❌ Password must be at least 4 characters!")
            return
        
        confirm_pass = input("Confirm password: ").strip()
        if password != confirm_pass:
            print("❌ Passwords don't match!")
            return
        
        print(f"\n📸 Capturing face for {full_name}...")
        face_data = self.face_system.capture_face(full_name, "owner")
        
        if not face_data:
            print("❌ Owner registration cancelled - no face captured")
            return
        
        # ============================================================
        # STRICT FACE DUPLICATE CHECK: Check if face already exists in system
        # ============================================================
        existing_faces = self.db.get_all_face_data()
        if existing_faces:
            is_similar, similarity, matched_face = self.face_system.check_face_similarity(face_data, existing_faces, 0.65)
            if is_similar:
                print(f"\n🚨 SECURITY ALERT: FACE ALREADY REGISTERED!")
                print(f"Face similarity detected: {similarity:.1%}")
                print("This person appears to be already registered in the system.")
                
                # Find which user has this face
                conn = sqlite3.connect(self.db.db_file)
                cursor = conn.cursor()
                cursor.execute("SELECT full_name, role, username FROM users WHERE is_active = 1 AND face_data IS NOT NULL")
                all_users = cursor.fetchall()
                conn.close()
                
                # Try to find the matching user
                for stored_name, stored_role, stored_username in all_users:
                    # Get their face data
                    conn = sqlite3.connect(self.db.db_file)
                    cursor = conn.cursor()
                    cursor.execute("SELECT face_data FROM users WHERE full_name = ?", (stored_name,))
                    stored_face_data = cursor.fetchone()
                    conn.close()
                    
                    if stored_face_data and stored_face_data[0]:
                        stored_face = pickle.loads(stored_face_data[0])
                        new_face = pickle.loads(face_data)
                        difference = np.sum(np.abs(new_face.astype(float) - stored_face.astype(float)))
                        stored_similarity = 1 - (difference / (100 * 100 * 255))
                        
                        if stored_similarity >= 0.65:
                            print(f"\n⚠️  This face matches: {stored_name} (Registered as {stored_role})")
                            print(f"   Username: {stored_username}")
                            print(f"   Face match: {stored_similarity:.1%}")
                            break
                
                print("\n🚫 REGISTRATION BLOCKED: One person, one registration only!")
                print("If this is an error, contact system administrator.")
                input("\nPress Enter to continue...")
                return
        
        # Save to database
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        conn = sqlite3.connect(self.db.db_file)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO users (username, password_hash, role, full_name, face_data)
                VALUES (?, ?, 'owner', ?, ?)
            ''', (username, password_hash, full_name, face_data))
            
            # Log the action
            cursor.execute('''
                INSERT INTO dealership_logs (action, user_affected, details)
                VALUES (?, ?, ?)
            ''', ('register_owner', username, f'Registered owner: {full_name} - ONE PERSON ONE REGISTRATION ENFORCED'))
            
            conn.commit()
            conn.close()
            
            print(f"\n✅ OWNER REGISTERED SUCCESSFULLY!")
            print(f"   Name: {full_name}")
            print(f"   Username: {username}")
            print("\n⚠️  Remember: This person cannot be registered again in any role!")
            print("⚠️  Give these credentials to the owner securely!")
            
        except sqlite3.IntegrityError as e:
            print(f"❌ Database error: {e}")
            print("This username may already exist. Try a different username.")
            conn.close()
        
        input("\nPress Enter to continue...")
    
    def register_driver(self):
        """Register a new driver"""
        print("\n" + "=" * 60)
        print("👥 REGISTER NEW DRIVER")
        print("=" * 60)
        
        # Check if owner exists first
        if not self.db.get_owner_exists():
            print("\n❌ No owner registered yet!")
            print("You must register an owner first.")
            input("\nPress Enter to continue...")
            return
        
        print("\n⚠️  IMPORTANT: One person, one registration only!")
        print("A person cannot be registered as both owner and driver.")
        print("A person cannot be registered multiple times.\n")
        
        full_name = input("Driver's full name: ").strip()
        if not full_name:
            print("❌ Name cannot be empty!")
            return
        
        # ============================================================
        # STRICT DUPLICATE CHECK: Check if person already exists in ANY role
        # ============================================================
        if self.db.check_user_exists_by_name(full_name):
            print(f"\n❌ {full_name} is already registered in the system!")
            
            # Get details of existing registration
            conn = sqlite3.connect(self.db.db_file)
            cursor = conn.cursor()
            cursor.execute("SELECT role, username FROM users WHERE LOWER(full_name) = LOWER(?) AND is_active = 1", (full_name,))
            existing_user = cursor.fetchone()
            conn.close()
            
            if existing_user:
                role, username = existing_user
                if role == 'owner':
                    print(f"\n🚫 This person is already registered as the OWNER!")
                    print(f"   Username: {username}")
                    print("\nA person cannot be both owner and driver.")
                    print("If you need to change their role, use 'Deregister User' first.")
                else:
                    print(f"\n🚫 This person is already registered as a DRIVER!")
                    print(f"   Username: {username}")
                    print("\nA person cannot be registered multiple times as a driver.")
                    print("If you need to update their information, use 'Deregister User' first.")
            
            input("\nPress Enter to continue...")
            return
        
        username = input("Choose username for driver: ").strip()
        if not username:
            print("❌ Username cannot be empty!")
            return
        
        # Check if username already exists
        if self.db.check_user_exists_by_username(username):
            print(f"\n❌ Username '{username}' is already taken!")
            print("Please choose a different username.")
            input("\nPress Enter to continue...")
            return
        
        # Generate simple password
        import random
        temp_password = str(random.randint(1000, 9999))
        print(f"\n📋 Generated password: {temp_password}")
        print("Driver should change this after first login")
        
        print(f"\n📸 Capturing face for {full_name}...")
        face_data = self.face_system.capture_face(full_name, "driver")
        
        if not face_data:
            print("❌ Driver registration cancelled")
            return
        
        # ============================================================
        # STRICT FACE DUPLICATE CHECK: Check if face already exists in system
        # ============================================================
        existing_faces = self.db.get_all_face_data()
        if existing_faces:
            is_similar, similarity, matched_face = self.face_system.check_face_similarity(face_data, existing_faces, 0.65)
            if is_similar:
                print(f"\n🚨 SECURITY ALERT: FACE ALREADY REGISTERED!")
                print(f"Face similarity detected: {similarity:.1%}")
                print("This person appears to be already registered in the system.")
                
                # Find which user has this face
                conn = sqlite3.connect(self.db.db_file)
                cursor = conn.cursor()
                cursor.execute("SELECT full_name, role, username FROM users WHERE is_active = 1 AND face_data IS NOT NULL")
                all_users = cursor.fetchall()
                conn.close()
                
                # Try to find the matching user
                for stored_name, stored_role, stored_username in all_users:
                    # Get their face data
                    conn = sqlite3.connect(self.db.db_file)
                    cursor = conn.cursor()
                    cursor.execute("SELECT face_data FROM users WHERE full_name = ?", (stored_name,))
                    stored_face_data = cursor.fetchone()
                    conn.close()
                    
                    if stored_face_data and stored_face_data[0]:
                        stored_face = pickle.loads(stored_face_data[0])
                        new_face = pickle.loads(face_data)
                        difference = np.sum(np.abs(new_face.astype(float) - stored_face.astype(float)))
                        stored_similarity = 1 - (difference / (100 * 100 * 255))
                        
                        if stored_similarity >= 0.65:
                            print(f"\n⚠️  This face matches: {stored_name} (Registered as {stored_role})")
                            print(f"   Username: {stored_username}")
                            print(f"   Face match: {stored_similarity:.1%}")
                            
                            if stored_role == 'owner':
                                print("\n🚫 BLOCKED: This person is already the OWNER!")
                                print("A person cannot be both owner and driver.")
                            else:
                                print("\n🚫 BLOCKED: This person is already a DRIVER!")
                                print("A person cannot be registered multiple times.")
                            
                            break
                
                print("\n🚫 REGISTRATION BLOCKED: One person, one registration only!")
                print("If this is an error, ensure the person looks directly at the camera.")
                input("\nPress Enter to continue...")
                return
        
        # Save to database
        password_hash = hashlib.sha256(temp_password.encode()).hexdigest()
        
        conn = sqlite3.connect(self.db.db_file)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO users (username, password_hash, role, full_name, face_data)
                VALUES (?, ?, 'driver', ?, ?)
            ''', (username, password_hash, full_name, face_data))
            
            # Log the action
            cursor.execute('''
                INSERT INTO dealership_logs (action, user_affected, details)
                VALUES (?, ?, ?)
            ''', ('register_driver', username, f'Registered driver: {full_name} - ONE PERSON ONE REGISTRATION ENFORCED'))
            
            conn.commit()
            conn.close()
            
            print(f"\n✅ DRIVER REGISTERED SUCCESSFULLY!")
            print(f"   Name: {full_name}")
            print(f"   Username: {username}")
            print(f"   Password: {temp_password}")
            print("\n⚠️  Remember: This person cannot be registered again in any role!")
            print("⚠️  Give these credentials to the driver!")
            
        except sqlite3.IntegrityError as e:
            print(f"❌ Database error: {e}")
            print("This username may already exist. Try a different username.")
            conn.close()
        
        input("\nPress Enter to continue...")
    
    def change_emergency_pin(self):
        """Change the emergency PIN"""
        print("\n" + "=" * 60)
        print("🔐 CHANGE EMERGENCY PIN")
        print("=" * 60)
        
        # Get current PIN
        conn = sqlite3.connect(self.db.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT emergency_pin FROM settings WHERE id = 1")
        current_pin = cursor.fetchone()[0]
        conn.close()
        
        # Step 1: Enter current PIN
        print("\nStep 1: Verify current PIN")
        attempts = 3
        while attempts > 0:
            entered_current = input(f"Enter current PIN ({attempts} attempts): ").strip()
            
            if entered_current == current_pin:
                break
            
            attempts -= 1
            if attempts > 0:
                print(f"❌ Wrong PIN! {attempts} attempts remaining")
            else:
                print("❌ Too many wrong attempts!")
                input("\nPress Enter to continue...")
                return
        
        # Step 2: Enter new PIN
        print("\nStep 2: Enter new PIN")
        while True:
            new_pin = input("New 6-digit PIN (numbers only): ").strip()
            
            if not new_pin.isdigit():
                print("❌ PIN must contain only numbers!")
                continue
            
            if len(new_pin) != 6:
                print("❌ PIN must be exactly 6 digits!")
                continue
            
            break
        
        # Step 3: Confirm new PIN
        print("\nStep 3: Confirm new PIN")
        confirm_pin = input("Confirm new 6-digit PIN: ").strip()
        
        if new_pin != confirm_pin:
            print("❌ PINs don't match!")
            input("\nPress Enter to continue...")
            return
        
        # Update PIN in database
        conn = sqlite3.connect(self.db.db_file)
        cursor = conn.cursor()
        cursor.execute("UPDATE settings SET emergency_pin = ? WHERE id = 1", (new_pin,))
        
        # Log the change
        cursor.execute('''
            INSERT INTO dealership_logs (action, details)
            VALUES (?, ?)
        ''', ('change_emergency_pin', f'PIN changed from {current_pin} to {new_pin}'))
        
        conn.commit()
        conn.close()
        
        print(f"\n✅ EMERGENCY PIN CHANGED SUCCESSFULLY!")
        print(f"   Old PIN: {current_pin}")
        print(f"   New PIN: {new_pin}")
        
        input("\nPress Enter to continue...")
    
    def reset_emergency_pin(self):
        """Reset emergency PIN when owner forgets it"""
        print("\n" + "=" * 60)
        print("🆘 RESET EMERGENCY PIN (FORGOT PIN)")
        print("=" * 60)
        
        print("\n⚠️  This feature is for when the owner forgets the emergency PIN.")
        print("It requires owner verification through face recognition.\n")
        
        # Check if owner exists
        if not self.db.get_owner_exists():
            print("❌ No owner registered yet!")
            print("Register an owner first to use this feature.")
            input("\nPress Enter to continue...")
            return
        
        # Get owner details
        conn = sqlite3.connect(self.db.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, username, full_name, face_data 
            FROM users 
            WHERE role = 'owner' AND is_active = 1
            LIMIT 1
        ''')
        
        owner = cursor.fetchone()
        if not owner:
            print("❌ No active owner found!")
            conn.close()
            input("\nPress Enter to continue...")
            return
        
        owner_id, owner_username, owner_name, face_data = owner
        conn.close()
        
        if not face_data:
            print(f"❌ Owner '{owner_name}' has no face data registered!")
            print("Please register face first in 'Register Owner' option.")
            input("\nPress Enter to continue...")
            return
        
        # Step 1: Verify owner's face
        print(f"\nStep 1: Verify {owner_name}'s identity")
        print("Owner must verify face to reset PIN")
        
        similarity = self.face_system.verify_face(face_data, 0.75)
        
        if similarity < 0.75:
            print(f"\n❌ Face verification failed! (Match: {similarity:.1%})")
            print("Only the registered owner can reset the PIN.")
            input("\nPress Enter to continue...")
            return
        
        print(f"\n✅ Owner verified: {owner_name}")
        print(f"   Face match: {similarity:.1%}")
        
        # Step 2: Get new PIN
        print("\nStep 2: Set new emergency PIN")
        while True:
            new_pin = input("New 6-digit PIN (numbers only): ").strip()
            
            if not new_pin.isdigit():
                print("❌ PIN must contain only numbers!")
                continue
            
            if len(new_pin) != 6:
                print("❌ PIN must be exactly 6 digits!")
                continue
            
            break
        
        # Step 3: Confirm new PIN
        print("\nStep 3: Confirm new PIN")
        confirm_pin = input("Confirm new 6-digit PIN: ").strip()
        
        if new_pin != confirm_pin:
            print("❌ PINs don't match!")
            input("\nPress Enter to continue...")
            return
        
        # Get current PIN for logging
        conn = sqlite3.connect(self.db.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT emergency_pin FROM settings WHERE id = 1")
        current_pin = cursor.fetchone()[0]
        
        # Update PIN in database
        cursor.execute("UPDATE settings SET emergency_pin = ? WHERE id = 1", (new_pin,))
        
        # Log the reset action
        cursor.execute('''
            INSERT INTO dealership_logs (action, user_affected, details)
            VALUES (?, ?, ?)
        ''', ('reset_emergency_pin', owner_username, 
              f'PIN reset from {current_pin} to {new_pin} via face verification (match: {similarity:.1%})'))
        
        conn.commit()
        conn.close()
        
        print(f"\n✅ EMERGENCY PIN RESET SUCCESSFULLY!")
        print(f"   Reset by: {owner_name}")
        print(f"   New PIN: {new_pin}")
        print("\n⚠️  Give the new PIN to the owner securely!")
        
        input("\nPress Enter to continue...")
    
    def change_owner_password(self):
        """Change owner password (requires current password)"""
        print("\n" + "=" * 60)
        print("🔑 CHANGE OWNER PASSWORD")
        print("=" * 60)
        
        # Get owner credentials
        owner_username, stored_hash, owner_name = self.db.get_owner_credentials()
        if not owner_username:
            print("❌ No owner registered yet!")
            input("\nPress Enter to continue...")
            return
        
        print(f"\n🔐 Password change for owner: {owner_name}")
        
        # Step 1: Enter current password
        print("\nStep 1: Verify current password")
        attempts = 3
        while attempts > 0:
            current_password = input(f"Enter current password ({attempts} attempts): ").strip()
            current_hash = hashlib.sha256(current_password.encode()).hexdigest()
            
            if current_hash == stored_hash:
                break
            
            attempts -= 1
            if attempts > 0:
                print(f"❌ Wrong password! {attempts} attempts remaining")
            else:
                print("❌ Too many wrong attempts!")
                input("\nPress Enter to continue...")
                return
        
        # Step 2: Enter new password
        print("\nStep 2: Enter new password")
        while True:
            new_password = input("New password (min 4 characters): ").strip()
            
            if len(new_password) < 4:
                print("❌ Password must be at least 4 characters!")
                continue
            
            break
        
        # Step 3: Confirm new password
        print("\nStep 3: Confirm new password")
        confirm_password = input("Confirm new password: ").strip()
        
        if new_password != confirm_password:
            print("❌ Passwords don't match!")
            input("\nPress Enter to continue...")
            return
        
        # Update password in database
        new_hash = hashlib.sha256(new_password.encode()).hexdigest()
        
        conn = sqlite3.connect(self.db.db_file)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password_hash = ? WHERE username = ? AND role = 'owner'", 
                      (new_hash, owner_username))
        
        # Log the change
        cursor.execute('''
            INSERT INTO dealership_logs (action, user_affected, details)
            VALUES (?, ?, ?)
        ''', ('change_owner_password', owner_username, f'Owner password changed'))
        
        conn.commit()
        conn.close()
        
        print(f"\n✅ OWNER PASSWORD CHANGED SUCCESSFULLY!")
        print(f"   Owner: {owner_name}")
        print("\n⚠️  Give the new password to the owner securely!")
        
        input("\nPress Enter to continue...")
    
    def reset_owner_password(self):
        """Reset owner password when owner forgets it (requires face verification)"""
        print("\n" + "=" * 60)
        print("🆘 RESET OWNER PASSWORD (FORGOT PASSWORD)")
        print("=" * 60)
        
        print("\n⚠️  This feature is for when the owner forgets their password.")
        print("It requires owner verification through face recognition.\n")
        
        # Check if owner exists
        if not self.db.get_owner_exists():
            print("❌ No owner registered yet!")
            input("\nPress Enter to continue...")
            return
        
        # Get owner details
        conn = sqlite3.connect(self.db.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, username, full_name, face_data 
            FROM users 
            WHERE role = 'owner' AND is_active = 1
            LIMIT 1
        ''')
        
        owner = cursor.fetchone()
        if not owner:
            print("❌ No active owner found!")
            conn.close()
            input("\nPress Enter to continue...")
            return
        
        owner_id, owner_username, owner_name, face_data = owner
        conn.close()
        
        if not face_data:
            print(f"❌ Owner '{owner_name}' has no face data registered!")
            print("Please register face first in 'Register Owner' option.")
            input("\nPress Enter to continue...")
            return
        
        # Step 1: Verify owner's face
        print(f"\nStep 1: Verify {owner_name}'s identity")
        print("Owner must verify face to reset password")
        
        similarity = self.face_system.verify_face(face_data, 0.75)
        
        if similarity < 0.75:
            print(f"\n❌ Face verification failed! (Match: {similarity:.1%})")
            print("Only the registered owner can reset the password.")
            input("\nPress Enter to continue...")
            return
        
        print(f"\n✅ Owner verified: {owner_name}")
        print(f"   Face match: {similarity:.1%}")
        
        # Step 2: Enter new password
        print("\nStep 2: Set new password")
        while True:
            new_password = input("New password (min 4 characters): ").strip()
            
            if len(new_password) < 4:
                print("❌ Password must be at least 4 characters!")
                continue
            
            break
        
        # Step 3: Confirm new password
        print("\nStep 3: Confirm new password")
        confirm_password = input("Confirm new password: ").strip()
        
        if new_password != confirm_password:
            print("❌ Passwords don't match!")
            input("\nPress Enter to continue...")
            return
        
        # Update password in database
        new_hash = hashlib.sha256(new_password.encode()).hexdigest()
        
        conn = sqlite3.connect(self.db.db_file)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password_hash = ? WHERE username = ? AND role = 'owner'", 
                      (new_hash, owner_username))
        
        # Log the reset action
        cursor.execute('''
            INSERT INTO dealership_logs (action, user_affected, details)
            VALUES (?, ?, ?)
        ''', ('reset_owner_password', owner_username, 
              f'Owner password reset via face verification (match: {similarity:.1%})'))
        
        conn.commit()
        conn.close()
        
        print(f"\n✅ OWNER PASSWORD RESET SUCCESSFULLY!")
        print(f"   Owner: {owner_name}")
        print(f"   New password: {new_password}")
        print("\n⚠️  Give the new password to the owner securely!")
        
        input("\nPress Enter to continue...")
    
    def deregister_user(self):
        """Deregister a user (owner or driver)"""
        print("\n" + "=" * 60)
        print("🚫 DEREGISTER USER")
        print("=" * 60)
        
        conn = sqlite3.connect(self.db.db_file)
        cursor = conn.cursor()
        
        # Get all active users
        cursor.execute('''
            SELECT id, username, role, full_name 
            FROM users 
            WHERE is_active = 1
            ORDER BY role DESC, full_name
        ''')
        
        users = cursor.fetchall()
        
        if not users:
            print("\n❌ No users found!")
            conn.close()
            input("\nPress Enter to continue...")
            return
        
        print("\n📋 Active Users:")
        for i, (user_id, username, role, full_name) in enumerate(users, 1):
            role_icon = "👑" if role == "owner" else "👤"
            print(f"  {i}. {role_icon} {full_name} ({username}) - {role}")
        
        try:
            selection = int(input("\nSelect user to deregister (number): ").strip())
            if 1 <= selection <= len(users):
                user_id, username, role, full_name = users[selection-1]
                
                print(f"\n⚠️  WARNING: You are about to deregister:")
                print(f"   Name: {full_name}")
                print(f"   Role: {role}")
                print(f"   Username: {username}")
                print("\n⚠️  This person will be able to register again ONLY after deregistration.")
                
                confirm = input("\nType 'YES' to confirm deregistration: ").strip().upper()
                
                if confirm == 'YES':
                    # Deactivate user
                    cursor.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))
                    
                    # Log the action
                    cursor.execute('''
                        INSERT INTO dealership_logs (action, user_affected, details)
                        VALUES (?, ?, ?)
                    ''', ('deregister_user', username, f'Deregistered {role}: {full_name} - Can now register again if needed'))
                    
                    conn.commit()
                    print(f"\n✅ {role.capitalize()} '{full_name}' deregistered successfully!")
                    print("⚠️  This person can now register again if needed.")
                else:
                    print("❌ Deregistration cancelled.")
            else:
                print("❌ Invalid selection!")
        except ValueError:
            print("❌ Please enter a valid number!")
        
        conn.close()
        input("\nPress Enter to continue...")
    
    def change_recognition_threshold(self):
        """Change face recognition threshold"""
        print("\n" + "=" * 60)
        print("🎯 CHANGE RECOGNITION THRESHOLD")
        print("=" * 60)
        
        # Get current threshold
        conn = sqlite3.connect(self.db.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT recognition_threshold FROM settings WHERE id = 1")
        current_threshold = cursor.fetchone()[0]
        conn.close()
        
        print(f"\nCurrent threshold: {current_threshold*100:.0f}%")
        print("\nThreshold explanation:")
        print("  Higher = More strict (better security)")
        print("  Lower = More lenient (easier access)")
        print("  Recommended: 65-75% for strict duplicate prevention")
        
        while True:
            try:
                new_percent = float(input("\nNew threshold (50-95%): ").strip())
                
                if 50 <= new_percent <= 95:
                    new_threshold = new_percent / 100
                    
                    # Update in database
                    conn = sqlite3.connect(self.db.db_file)
                    cursor = conn.cursor()
                    cursor.execute("UPDATE settings SET recognition_threshold = ? WHERE id = 1", 
                                 (new_threshold,))
                    
                    # Log the change
                    cursor.execute('''
                        INSERT INTO dealership_logs (action, details)
                        VALUES (?, ?)
                    ''', ('change_threshold', f'Threshold changed from {current_threshold*100:.0f}% to {new_percent:.0f}%'))
                    
                    conn.commit()
                    conn.close()
                    
                    print(f"\n✅ Threshold updated to {new_percent:.0f}%")
                    break
                else:
                    print("❌ Please enter between 50% and 95%")
            except ValueError:
                print("❌ Please enter a valid number!")
        
        input("\nPress Enter to continue...")
    
    def view_system_logs(self):
        """View dealership activity logs"""
        print("\n" + "=" * 60)
        print("📊 DEALERSHIP ACTIVITY LOGS")
        print("=" * 60)
        
        conn = sqlite3.connect(self.db.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT timestamp, action, user_affected, details
            FROM dealership_logs
            ORDER BY timestamp DESC
            LIMIT 20
        ''')
        
        logs = cursor.fetchall()
        conn.close()
        
        if not logs:
            print("\nNo dealership logs found.")
        else:
            print(f"\nRecent dealership activity ({len(logs)} entries):\n")
            print("-" * 80)
            print(f"{'Timestamp':<20} {'Action':<20} {'User':<15} Details")
            print("-" * 80)
            
            for timestamp, action, user_affected, details in logs:
                time_str = timestamp[:19]
                user = user_affected or "System"
                print(f"{time_str:<20} {action:<20} {user:<15} {details}")
        
        input("\nPress Enter to continue...")

# ============================================================================
# DRIVER/OWNER SYSTEM (IN-CAR)
# ============================================================================

class CarSystem:
    def __init__(self, db, face_system):
        self.db = db
        self.face_system = face_system
        self.current_user = None
    
    def login(self):
        """Logs in the registered owner automatically."""
        # Check if an owner is registered
        if not self.db.get_owner_exists():
            print("\n❌ No owner is registered in the system.")
            print("Please use the Dealership Management system to register an owner first.")
            return False

        # Get the registered owner's credentials
        owner_username, stored_hash, owner_name = self.db.get_owner_credentials()

        if not owner_username or not stored_hash:
            print("❌ Could not retrieve valid owner credentials from the database!")
            return False

        # Find the user record in the database
        conn = sqlite3.connect(self.db.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, username, role, full_name, face_data
            FROM users
            WHERE username = ? AND password_hash = ? AND role = 'owner' AND is_active = 1
        ''', (owner_username, stored_hash))

        user = cursor.fetchone()
        conn.close()

        if user:
            self.current_user = {
                'id': user[0],
                'username': user[1],
                'role': user[2],
                'full_name': user[3],
                'face_data': user[4]
            }
            # Log the successful login
            self.log_action('login', 'success', f'Auto-login for owner: {owner_name}')
            print(f"\n✅ Welcome, {owner_name}!")
            if not user[4]: # if no face_data
                 print("⚠️  Note: Please visit dealership to register face recognition")
            return True
        else:
            print("\n❌ Auto-login for the registered owner failed.")
            print("Please check the system setup or contact the dealership.")
            return False
    
    def start_car_face(self):
        """Start car using face recognition"""
        print("\n" + "=" * 50)
        print("🚗 START CAR - FACE RECOGNITION")
        print("=" * 50)
        
        # Check time restrictions
        conn = sqlite3.connect(self.db.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT allowed_start_hour, allowed_end_hour, recognition_threshold FROM settings WHERE id = 1")
        start_hour, end_hour, threshold = cursor.fetchone()
        conn.close()
        
        current_hour = datetime.now().hour
        if not (start_hour <= current_hour <= end_hour):
            print(f"⏰ Outside allowed hours ({start_hour}:00 - {end_hour}:00)")
            print("Car cannot be started now.")
            self.log_action('start_car', 'denied', 'Outside allowed hours')
            input("\nPress Enter to continue...")
            return
        
        print(f"⏰ Time check: OK ({datetime.now().strftime('%H:%M')})")
        
        # Face verification
        if not self.current_user['face_data']:
            print("❌ No face data available!")
            print("Contact dealership to register your face.")
            return
        
        similarity = self.face_system.verify_face(self.current_user['face_data'], threshold)
        
        print(f"\n🎯 Face match: {similarity:.1%} (Required: {threshold*100:.0f}%)")
        
        if similarity >= threshold:
            print(f"\n✅ VERIFIED: {self.current_user['full_name']}")
            print("🚗 ENGINE STARTED - Safe travels!")
            self.log_action('start_car', 'success', f'Face match: {similarity:.1%}')
        else:
            print(f"\n❌ ACCESS DENIED - Face not recognized")
            print("🔒 ENGINE LOCKED")
            print("\nOptions:")
            print("  1. Try emergency PIN")
            print("  2. Contact dealership")
            print("  3. Visit dealership to reset PIN if forgotten")
            self.log_action('start_car', 'failed', f'Face match: {similarity:.1%}')
        
        input("\nPress Enter to continue...")
    
    def start_car_pin(self):
        """Start car using emergency PIN"""
        print("\n" + "=" * 50)
        print("🚗 START CAR - EMERGENCY PIN")
        print("=" * 50)
        
        print("\n⚠️  EMERGENCY ACCESS ONLY")
        print("Use this only if face recognition fails\n")
        
        conn = sqlite3.connect(self.db.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT emergency_pin FROM settings WHERE id = 1")
        correct_pin = cursor.fetchone()[0]
        conn.close()
        
        attempts = 3
        while attempts > 0:
            pin = input(f"Enter 6-digit PIN ({attempts} attempts): ").strip()
            
            if not pin.isdigit() or len(pin) != 6:
                print("❌ PIN must be 6 digits!")
                attempts -= 1
                continue
            
            if pin == correct_pin:
                print("\n✅ EMERGENCY ACCESS GRANTED")
                print("🚗 ENGINE STARTED - Emergency mode")
                self.log_action('emergency_pin', 'success', 'Emergency access used')
                break
            else:
                attempts -= 1
                if attempts > 0:
                    print(f"❌ Wrong PIN! {attempts} attempts remaining")
                else:
                    print("\n🔒 TOO MANY WRONG ATTEMPTS!")
                    print("⚠️  If you forgot the PIN, visit dealership menu")
                    print("    and use 'Reset Emergency PIN' option")
                    self.log_action('emergency_pin', 'failed', 'Too many wrong attempts')
        
        input("\nPress Enter to continue...")
    
    def view_settings(self):
        """View and optionally change settings"""
        while True:
            print("\n" + "=" * 50)
            print("⚙️  SETTINGS")
            print("=" * 50)
            
            conn = sqlite3.connect(self.db.db_file)
            cursor = conn.cursor()
            cursor.execute("SELECT allowed_start_hour, allowed_end_hour FROM settings WHERE id = 1")
            start_hour, end_hour = cursor.fetchone()
            conn.close()
            
            print(f"\nCurrent driving hours: {start_hour}:00 to {end_hour}:00")
            
            print("\n📋 Options:")
            print("  1. Change driving hours")
            print("  2. Back to main menu")
            
            choice = input("\nSelect option (1-2): ").strip()
            
            if choice == "1":
                self.change_driving_hours()
            elif choice == "2":
                break
            else:
                print("❌ Invalid option!")
    
    def change_driving_hours(self):
        """Change allowed driving hours (requires owner verification)"""
        print("\n" + "=" * 50)
        print("⏰ CHANGE DRIVING HOURS")
        print("=" * 50)
        
        # Check if current user is owner
        if self.current_user['role'] != 'owner':
            print("\n❌ ACCESS DENIED!")
            print("Only the car owner can change driving hours.")
            print("Please contact the owner to make changes.")
            input("\nPress Enter to continue...")
            return
        
        # Get owner credentials for verification
        owner_username, stored_hash, owner_name = self.db.get_owner_credentials()
        
        if not owner_username:
            print("❌ Owner credentials not found!")
            input("\nPress Enter to continue...")
            return
        
        # Verify owner password
        print(f"\n🔐 Owner verification required: {owner_name}")
        attempts = 3
        while attempts > 0:
            password = input(f"Enter owner password ({attempts} attempts): ").strip()
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            if password_hash == stored_hash:
                break
            
            attempts -= 1
            if attempts > 0:
                print(f"❌ Wrong password! {attempts} attempts remaining")
            else:
                print("❌ Too many wrong attempts!")
                input("\nPress Enter to continue...")
                return
        
        print(f"\n✅ Owner verified: {owner_name}")
        
        # Now allow changing driving hours
        conn = sqlite3.connect(self.db.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT allowed_start_hour, allowed_end_hour FROM settings WHERE id = 1")
        current_start, current_end = cursor.fetchone()
        
        print(f"\nCurrent hours: {current_start}:00 to {current_end}:00")
        
        try:
            new_start = int(input("\nNew start hour (0-23): "))
            new_end = int(input("New end hour (0-23): "))
            
            if not (0 <= new_start <= 23 and 0 <= new_end <= 23):
                print("❌ Hours must be between 0 and 23!")
                conn.close()
                return
            
            if new_start >= new_end:
                print("❌ Start hour must be before end hour!")
                conn.close()
                return
            
            cursor.execute("UPDATE settings SET allowed_start_hour = ?, allowed_end_hour = ? WHERE id = 1",
                          (new_start, new_end))
            
            # Log the change
            cursor.execute('''
                INSERT INTO access_logs (user_id, username, action, status, details)
                VALUES (?, ?, ?, ?, ?)
            ''', (self.current_user['id'], self.current_user['username'], 
                  'change_hours', 'success', 
                  f'Changed hours from {current_start}:00-{current_end}:00 to {new_start}:00-{new_end}:00'))
            
            conn.commit()
            conn.close()
            
            print(f"\n✅ Driving hours updated to {new_start}:00 - {new_end}:00")
            self.log_action('change_hours', 'success')
            
        except ValueError:
            print("❌ Please enter valid numbers!")
            conn.close()
        
        input("\nPress Enter to continue...")
    
    def log_action(self, action, status, details=""):
        """Log user action"""
        conn = sqlite3.connect(self.db.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO access_logs (user_id, username, action, status, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (self.current_user['id'], self.current_user['username'], 
              action, status, details))
        conn.commit()
        conn.close()
    
    def user_menu(self):
        """Main menu for driver/owner"""
        while True:
            print("\n" + "=" * 50)
            print("🚗 CAR SECURITY SYSTEM")
            print(f"👤 {self.current_user['role'].upper()}: {self.current_user['full_name']}")
            print("=" * 50)
            
            print("\n📋 OPTIONS:")
            print("  1. 🚗 Start Car (Face Recognition)")
            print("  2. 🔢 Start Car (Emergency PIN)")
            print("  3. ⚙️  Settings")
            print("  4. 👋 Logout")
            
            choice = input("\nSelect option (1-4): ").strip()
            
            if choice == "1":
                self.start_car_face()
            elif choice == "2":
                self.start_car_pin()
            elif choice == "3":
                self.view_settings()
            elif choice == "4":
                print("\n👋 Logging out...")
                self.log_action('logout', 'success')
                self.current_user = None
                break
            else:
                print("❌ Invalid option!")

# ============================================================================
# MAIN APPLICATION
# ============================================================================

def main():
    print("\n🚗 CAR SECURITY SYSTEM")
    print("=" * 60)
    print("Version: Dealership & Driver Edition")
    print("⚠️  ONE PERSON - ONE REGISTRATION POLICY ENFORCED")
    print("=" * 60)
    
    # Initialize systems
    db = CarDatabase()
    face_system = FaceRecognitionSystem()
    
    while True:
        print("\n📋 SELECT SYSTEM:")
        print("  1. 🏢 Dealership Management")
        print("  2. 🚗 Car System (Driver/Owner Login)")
        print("  3. 🚪 Exit")
        
        choice = input("\nSelect system (1-3): ").strip()
        
        if choice == "1":
            # Dealership system
            dealership = DealershipSystem(db, face_system)
            dealership.show_menu()
        
        elif choice == "2":
            # Check if owner exists before allowing car system access
            if not db.get_owner_exists():
                print("\n❌ NO OWNER REGISTERED YET!")
                print("=" * 50)
                print("You must register an owner first.")
                print("\nPlease:")
                print("1. Select '🏢 Dealership Management' (option 1)")
                print("2. Choose '👑 Register Owner' (option 1)")
                print("3. Follow the registration process")
                print("\nOnce owner is registered, you can access the Car System.")
                input("\nPress Enter to continue...")
                continue
            
            # Car system login - Smart auto-login
            car_system = CarSystem(db, face_system)
            if car_system.login():
                car_system.user_menu()
        
        elif choice == "3":
            print("\n👋 Goodbye!")
            break
        
        else:
            print("❌ Invalid choice!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  System interrupted")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        input("Press Enter to exit...")