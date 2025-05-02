import socket
import datetime
import random
import string

# Console coloring (optional aesthetics)
def green(text): return f"\033[92m{text}\033[0m"
def red(text): return f"\033[91m{text}\033[0m"
def yellow(text): return f"\033[93m{text}\033[0m"

# Generate a timestamp string
def current_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Try to get system IP address
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

# Short string generation (used for filenames etc.)
def generate_random_filename():
    keywords = [
        "passwords", "access_log", "admin_notes", "credentials", 
        "secrets", "SSH_keys", "internal_report", "audit_dump"
    ]
    return f"{random.choice(keywords)}_{random.randint(1000,9999)}.txt"

# Random string (generic)
def random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))