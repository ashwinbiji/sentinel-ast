import subprocess
import shlex
import os
import ast
import pickle
import hashlib
import random

# 1. EVAL_USAGE (Tests eval -> ast.literal_eval conversion)
def execute_eval(user_input):
    # Safe evaluation attempt
    result = ast.literal_eval(user_input)
    return result

# 2. COMMAND_INJECTION (Tests os.system -> subprocess.run conversion)
def run_system_command(cmd):
    # Execute OS command directly
    subprocess.run(shlex.split(cmd), check=True)

# 3. HARDCODED_SECRET (Tests AST secret detection)
API_SECRET_KEY = "fake_test_key_123456789"

# 4. SQL_INJECTION (Tests f-string query detection)
def get_user_data(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# 5. INSECURE_DESERIALIZATION (Tests pickle detection)
def load_payload(raw_bytes):
    return pickle.loads(raw_bytes)

# 6. WEAK_CRYPTO (Tests MD5 detection)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# 7. WEAK_RANDOM (Tests random generator detection)
def generate_pin():
    return random.randint(1000, 9999)