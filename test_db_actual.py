import sqlite3
import sys
import os

db_path = os.path.join(os.getcwd(), 'system', 'config', 'ngfw.db')

if not os.path.exists(db_path):
    print(f"Database file not found at {db_path}")
    sys.exit(1)

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, username, role, password_hash FROM users")
    users = cursor.fetchall()
    
    print("Users in database:")
    for user in users:
        print(f"ID: {user[0]}, Username: {user[1]}, Role: {user[2]}, Password Hash: {user[3]}")
        from bcrypt import checkpw
        print(f"Password 'admin123' matches hash: {checkpw(b'admin123', str(user[3]).encode('utf-8'))}")
        
    conn.close()
except Exception as e:
    print(f"Error reading database: {e}")
    sys.exit(1)
