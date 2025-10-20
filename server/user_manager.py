import hashlib
import json
import os

USERS_FILE = "users.json"

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

def register_user(username, password):
    users = load_users()
    if username in users:
        return False
    users[username] = hashlib.sha256(password.encode()).hexdigest()
    save_users(users)
    return True

def authenticate(username, password):
    users = load_users()
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return username in users and users[username] == hashed
