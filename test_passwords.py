import sqlite3
import bcrypt
import os

db_path = os.path.join(os.getcwd(), 'system', 'config', 'ngfw.db')

if not os.path.exists(db_path):
    print(f"DB not found at {db_path}")
else:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT username, password_hash FROM users")
    users = cur.fetchall()
    
    for u in users:
        print(f"User: {u[0]}")
        print(f"  Hash: {u[1]}")
        
        # Test admin123
        try:
            val1 = bcrypt.checkpw(b"admin123", u[1].encode('utf-8'))
            print(f"  Matches 'admin123': {val1}")
        except Exception as e:
            print(f"  Error checking admin123: {e}")
            
        # Test Admin@1234
        try:
            val2 = bcrypt.checkpw(b"Admin@1234", u[1].encode('utf-8'))
            print(f"  Matches 'Admin@1234': {val2}")
        except Exception as e:
            print(f"  Error checking Admin@1234: {e}")
            
    conn.close()
