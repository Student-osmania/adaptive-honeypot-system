import os
import hashlib
import time
import random
import string

def get_file_hash(filepath):
    """Calculate MD5 hash of a file's contents"""
    if not os.path.isfile(filepath):
        return ""
    try:
        hash_md5 = hashlib.md5()
        with open(filepath, "rb") as f:
            # Read in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception:
        return ""

def add_fake_metadata(filepath):
    """Add fake file metadata to make honeypot files appear more authentic"""
    if not os.path.exists(filepath):
        return
    # Simulate metadata by modifying access and modification times
    fake_time = time.time() - random.randint(50000, 500000)
    try:
        os.utime(filepath, (fake_time, fake_time))
    except Exception:
        pass  # Silently fail if we can't change file times

def generate_fake_content():
    """Generate fake content for honeypot files"""
    lines = [
        "Confidential: Salary structure 2024",
        "Admin login credentials: [REDACTED]",
        "Private SSH key: -----BEGIN PRIVATE KEY-----",
        "Password reset link: http://fakecorp/reset",
        "Email dump - user@internal.fake"
    ]
    return "\n".join(random.choices(lines, k=random.randint(3, 5)))

def write_fake_file(filepath):
    """Create a fake file with convincing content"""
    try:
        with open(filepath, "w") as f:
            f.write(generate_fake_content())
        add_fake_metadata(filepath)
        return True
    except Exception:
        return False

def get_random_string(length=12):
    """Generate a random string of specified length"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def read_file_safely(file_path, max_bytes=2048):
    """Safely attempts to read a portion of the file content, up to max_bytes."""
    try:
        with open(file_path, 'r', errors='ignore') as f:
            return f.read(max_bytes)
    except Exception:
        return ""