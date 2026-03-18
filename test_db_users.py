import sys
import os

sys.path.append(os.getcwd())

from system.database.database import DatabaseManager, User

db = DatabaseManager('sqlite:///ngfw.db')
db.initialize()

with db.session() as session:
    users = session.query(User).all()
    print("Users in database:")
    for user in users:
        print(f"ID: {user.id}, Username: {user.username}, Role: {user.role}, Password Hash: {user.password_hash}")
        
    admin_user = session.query(User).filter_by(username='admin').first()
    if admin_user:
        from api.rest.auth import _verify_password
        print(f"Verify 'admin123' against DB hash: {_verify_password('admin123', admin_user.password_hash)}")
    else:
        print("Admin user not found in DB!")
