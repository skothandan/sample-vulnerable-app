# NOTE: contains intentional security test patterns for SAST/SCA/IaC scanning.
import sqlite3
import subprocess
import pickle
import os
import ast  # Added for safe evaluation

# hardcoded API token (Issue 1)
API_TOKEN = "AKIAEXAMPLERAWTOKEN12345"

# simple SQLite DB on local disk (Issue 2: insecure storage + lack of access control)
DB_PATH = "/tmp/app_users.db"
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
conn.commit()

def add_user(username, password):
    # Fixed SQL injection vulnerability by using parameterized query (Issue 3)
    sql = "INSERT INTO users (username, password) VALUES (?, ?)"
    cur.execute(sql, (username, password))
    conn.commit()

def get_user(username):
    # Fixed SQL injection vulnerability by using parameterized query (Issue 3)
    q = "SELECT id, username FROM users WHERE username = ?"
    cur.execute(q, (username,))
    return cur.fetchall()

def run_shell(command):
    # command injection risk if command includes unsanitized input (Issue 4)
    # This function should be avoided or carefully controlled. If necessary, use a whitelist of allowed commands.
    allowed_commands = ['echo', 'ls', 'pwd']
    if command.split()[0] not in allowed_commands:
        return "Command not allowed"
    return subprocess.getoutput(command)

def deserialize_blob(blob):
    # Fixed insecure deserialization of untrusted data (Issue 5)
    # Using ast.literal_eval for safe evaluation of literals
    try:
        return ast.literal_eval(blob.decode())
    except (ValueError, SyntaxError):
        return None

if __name__ == "__main__":
    # seed some data
    add_user("alice", "alicepass")
    add_user("bob", "bobpass")

    # Demonstrate risky calls
    print("API_TOKEN in use:", API_TOKEN)
    print(get_user("alice"))  # Fixed SQLi payload
    print(run_shell("echo Hello"))
    try:
        # attempting to deserialize an arbitrary blob (will now safely handle invalid input)
        print(deserialize_blob(b"{'key': 'value'}"))
    except Exception as e:
        print("Deserialization error:", e)

# IMPORTANT: The code above has been updated to address the following security issues:
# 1. SQL Injection vulnerabilities in add_user and get_user functions
# 2. Unsafe deserialization in deserialize_blob function
# 3. Command injection risk in run_shell function (partially mitigated, but should be used with caution)
# 
# Note: The hardcoded API token and insecure database storage issues are still present and should be addressed separately.