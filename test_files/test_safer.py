"""
Safer version of the code showing how to fix vulnerabilities
This file should have fewer or no vulnerabilities
"""

import os
import subprocess
import json
import hashlib
import secrets
import bcrypt
from sqlite3 import connect

# FIXED: Use environment variables instead of hardcoded passwords
PASSWORD = os.getenv('DB_PASSWORD')
if not PASSWORD:
    raise ValueError("DB_PASSWORD environment variable not set")

# FIXED: SQL Injection - Use parameterized queries
def get_user_data(user_id):
    conn = connect("database.db")
    cursor = conn.cursor()
    # Safe - parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchall()

# FIXED: Command Injection - Use subprocess with list of arguments
def run_command(user_input):
    # Safe - no shell interpretation
    result = subprocess.run(['ls', user_input], capture_output=True, text=True, check=True)
    return result.stdout

# FIXED: Secure Random
def generate_token():
    # Using secrets module for cryptographically secure random
    token = secrets.token_hex(16)
    return token

# FIXED: Strong Cryptography - SHA-256
def hash_password(password):
    # SHA-256 is secure
    return hashlib.sha256(password.encode()).hexdigest()

# FIXED: Use bcrypt for password hashing
def hash_password_secure(password):
    # Bcrypt is designed for password hashing
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

# FIXED: Avoid eval - use safer alternatives
def calculate(user_expression):
    # Use ast.literal_eval for safe evaluation of literals only
    import ast
    try:
        result = ast.literal_eval(user_expression)
        return result
    except (ValueError, SyntaxError):
        raise ValueError("Invalid expression")

# FIXED: Avoid pickle - use JSON for data serialization
def load_user_data(data):
    # JSON is safer than pickle
    user_obj = json.loads(data)
    return user_obj

# FIXED: Path Traversal - Validate and sanitize paths
def read_file(filename):
    # Validate filename doesn't contain path traversal
    if '..' in filename or '/' in filename or '\\' in filename:
        raise ValueError("Invalid filename")
    safe_path = os.path.join("data", filename)
    with open(safe_path, "r") as f:
        return f.read()

# FIXED: Don't use assert for security checks
def check_admin(user):
    # Proper security check
    if not user.is_admin:
        raise PermissionError("Not an admin")
    return True

if __name__ == "__main__":
    # Safe usage examples
    user_id = "1"
    get_user_data(user_id)
    
    user_input = "test.txt"
    run_command(user_input)

