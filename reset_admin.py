import sys
import os
import bcrypt

sys.path.append(os.getcwd())

from system.database.database import DatabaseManager, User

def reset_admin_password():
    db_path = os.path.join(os.getcwd(), 'system', 'config', 'ngfw.db')
    print(f"Connecting to database at {db_path}...")
    
    db = DatabaseManager(f"sqlite:///{db_path}")
    
    new_password = "Admin@1234"
    hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    
    with db.session() as session:
        admin_user = session.query(User).filter_by(username='admin').first()
        if admin_user:
            admin_user.password_hash = hashed
            session.commit()
            print(f"SUCCESS: 'admin' account password has been reset to: {new_password}")
        else:
            print("ERROR: 'admin' user not found in the database.")

if __name__ == "__main__":
    reset_admin_password()
