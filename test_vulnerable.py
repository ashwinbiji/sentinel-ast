import os
import subprocess
import pickle
import hashlib
import random

# 1. EVAL_USAGE
def execute_eval(user_input):
    eval(user_input)

# 2. COMMAND_INJECTION
def run_command(cmd):
    os.system(cmd)
    subprocess.run(f"ls {cmd}", shell=True)

# 3. HARDCODED_SECRET
SECRET_KEY = "gsk_999888777666555444333222111"

# 4. SQL_INJECTION
def query_db(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# 5. INSECURE_DESERIALIZATION
def unpack_payload(data):
    return pickle.loads(data)

# 6. WEAK_CRYPTO
def hash_pass(password):
    return hashlib.md5(password.encode()).hexdigest()

# 7. WEAK_RANDOM
def get_reset_token():
    return random.randint(1000, 9999)