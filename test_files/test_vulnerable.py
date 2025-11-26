"""
Test file with various security vulnerabilities for testing the vulnerability scanner
"""

import os
import subprocess
import pickle
import hashlib
import random
from sqlite3 import connect

# VULNERABILITY: Hardcoded Password
PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"

# VULNERABILITY: SQL Injection
def get_user_data(user_id):
    conn = connect("database.db")
    cursor = conn.cursor()
    # SQL Injection vulnerability - user input directly in query
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchall()

# VULNERABILITY: SQL Injection with f-string
def get_user_data_unsafe(username):
    conn = connect("database.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()

# VULNERABILITY: Command Injection
def run_command(user_input):
    # Dangerous - command injection
    os.system(f"ls {user_input}")
    # Also dangerous
    subprocess.call(["rm", "-rf", user_input], shell=True)

# VULNERABILITY: Insecure Random
def generate_token():
    # Using insecure random for security-sensitive operations
    token = random.randint(1000, 9999)
    return str(token)

# VULNERABILITY: Weak Cryptography (MD5)
def hash_password(password):
    # MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()

# VULNERABILITY: Weak Cryptography (SHA1)
def hash_data(data):
    # SHA1 is also weak
    return hashlib.sha1(data.encode()).hexdigest()

# VULNERABILITY: Eval Usage
def calculate(user_expression):
    # Dangerous - can execute arbitrary code
    result = eval(user_expression)
    return result

# VULNERABILITY: Pickle Unsafe Deserialization
def load_user_data(data):
    # Pickle can execute arbitrary code during deserialization
    user_obj = pickle.loads(data)
    return user_obj

# VULNERABILITY: Path Traversal
def read_file(filename):
    # Path traversal vulnerability
    with open(f"../{filename}", "r") as f:
        return f.read()

# VULNERABILITY: Assert in Code (security check)
def check_admin(user):
    # Assert can be disabled with -O flag
    assert user.is_admin, "Not an admin"
    return True

# VULNERABILITY: Exec Usage
def execute_code(user_code):
    # Exec can execute arbitrary Python code
    exec(user_code)

# Hardcoded credentials in comments (should also be flagged)
# DB_PASSWORD = "mySecretPassword123"
# AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"

if __name__ == "__main__":
    # Test usage
    user_id = "1 OR 1=1"  # SQL injection example
    get_user_data(user_id)
    
    user_input = "test; rm -rf /"  # Command injection example
    run_command(user_input)
    
    expression = "__import__('os').system('ls')"  # Eval injection
    calculate(expression)

