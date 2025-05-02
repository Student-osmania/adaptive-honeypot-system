import os
import json
import sqlite3
import threading
from datetime import datetime
from config import LOG_FILE, LOG_JSON, LOG_DB, BEHAVIOR_CSV

# Ensure log directories exist
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
os.makedirs(os.path.dirname(BEHAVIOR_CSV), exist_ok=True)

# Thread lock for safe file access
_log_lock = threading.Lock()

def log_event(event_type, file_path, user="unknown", ip_address="unknown", hash_before=None, hash_after=None, additional_metadata=None):
    """Thread-safe logging of honeypot events to multiple formats"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        "timestamp": timestamp,
        "event_type": event_type,
        "file_path": file_path,
        "user": user,
        "ip_address": ip_address,
        "hash_before": hash_before or "",
        "hash_after": hash_after or "",
        "additional_metadata": additional_metadata or {}
    }

    with _log_lock:
        # Human-readable log
        try:
            with open(LOG_FILE, "a") as log_file:
                log_file.write(f"{timestamp} [{event_type}] {file_path} (User: {user}, IP: {ip_address})\n")
        except Exception:
            pass  # Continue even if one log format fails

        # JSON log
        try:
            with open(LOG_JSON, "a") as json_file:
                json.dump(log_entry, json_file)
                json_file.write("\n")
        except Exception:
            pass

        # SQLite log - with connection pooling
        try:
            conn = sqlite3.connect(LOG_DB)
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS logs
                      (timestamp TEXT, event_type TEXT, file_path TEXT, user TEXT, ip_address TEXT,
                      hash_before TEXT, hash_after TEXT, additional_metadata TEXT)''')
            c.execute("INSERT INTO logs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (timestamp, event_type, file_path, user, ip_address, hash_before or "", 
                     hash_after or "", json.dumps(additional_metadata or {})))
            conn.commit()
            conn.close()
        except Exception:
            pass

        # Structured CSV for AI/analysis
        try:
            write_header = not os.path.exists(BEHAVIOR_CSV) or os.path.getsize(BEHAVIOR_CSV) == 0
            with open(BEHAVIOR_CSV, "a") as f:
                if write_header:
                    f.write("timestamp,event_type,file_path,user,ip_address,hash_before,hash_after,action_taken,additional_metadata\n")
                # Escape commas in metadata if it's a string
                metadata_str = json.dumps(additional_metadata or {}) if additional_metadata else ""
                f.write(f"{timestamp},{event_type},{file_path},{user},{ip_address},{hash_before or ''},{hash_after or ''},log_only,\"{metadata_str}\"\n")
        except Exception:
            pass