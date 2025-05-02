import time
import os
import datetime
import json
import shutil
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from core.logger import log_event
from utils.helpers import current_timestamp, get_local_ip, yellow, green, red
from utils.file_utils import get_file_hash, read_file_safely
from config import DECOY_DIR

# Global observer object
_observer = None
_observer_lock = threading.Lock()

class HoneypotHandler(FileSystemEventHandler):
    def __init__(self):
        self.event_history = {}
        self.event_lock = threading.Lock()
        self.last_alert_time = 0
        self.alert_cooldown = 60  # seconds between alerts for the same file
        self.interaction_counts = {}
        self.high_value_keywords = [
            'password', 'secret', 'key', 'token', 'credential', 'admin',
            'config', 'backup', 'database', 'user', 'account', 'ssh',
            'private', 'confidential', 'certificate'
        ]
        
    def on_modified(self, event):
        if event.is_directory:
            return
            
        try:
            file_path = event.src_path
            current_time = time.time()

            with self.event_lock:
                # Avoid redundant logging: debounce per file
                previous = self.event_history.get(file_path, {})
                last_time = previous.get('last_modified', 0)
                last_hash = previous.get('hash', "")

                # Skip if modified too soon after last event (debounce)
                if (current_time - last_time) < 1:
                    return

                # Get new hash
                new_hash = get_file_hash(file_path)

                # If file hash hasn't changed, ignore
                if new_hash == last_hash and (current_time - last_time) < 5:
                    return

                # Read content & size
                file_content = read_file_safely(file_path)
                file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

                self.event_history[file_path] = {
                    'last_modified': current_time,
                    'hash': new_hash,
                    'size': file_size
                }

                # Count interactions
                self.interaction_counts[file_path] = self.interaction_counts.get(file_path, 0) + 1

            # Assessment can happen outside the lock
            threat_level = self._assess_threat_level(file_path, file_content)
            metadata = {
                'interaction_count': self.interaction_counts.get(file_path, 0),
                'threat_level': threat_level,
                'time_of_day': datetime.datetime.now().strftime('%H:%M:%S'),
                'file_size': file_size
            }

            log_event("MODIFIED", file_path, ip_address=get_local_ip(),
                      hash_before=last_hash, hash_after=new_hash,
                      additional_metadata=metadata)

            # Only backup high threat files to avoid unnecessary disk operations
            if threat_level == 'HIGH':
                self._backup_file(file_path)

            if threat_level == 'HIGH' and (current_time - self.last_alert_time > self.alert_cooldown):
                self.last_alert_time = current_time
                print(red(f"[!] HIGH THREAT: File modified: {os.path.basename(file_path)}"))
            elif threat_level == 'MEDIUM':
                print(yellow(f"[!] File modified: {os.path.basename(file_path)}"))
            else:
                print(green(f"[+] File modified: {os.path.basename(file_path)}"))

        except Exception as e:
            print(f"[!] Error handling file modification: {e}")
            log_event("MODIFIED", event.src_path, ip_address=get_local_ip())

    def on_created(self, event):
        if event.is_directory:
            return
            
        try:
            file_path = event.src_path
            
            # Quick check to prevent processing files that don't exist anymore
            if not os.path.exists(file_path):
                return
                
            hash_after = get_file_hash(file_path)
            file_content = read_file_safely(file_path)
            file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
            
            with self.event_lock:
                # Record in history
                self.event_history[file_path] = {
                    'creation_time': time.time(),
                    'hash': hash_after,
                    'size': file_size
                }
                
                # Initialize interaction count
                self.interaction_counts[file_path] = 1
            
            # Calculate threat level
            threat_level = self._assess_threat_level(file_path, file_content)
            
            # Enhanced metadata
            metadata = {
                'initial_hash': hash_after,
                'threat_level': threat_level,
                'time_of_day': datetime.datetime.now().strftime('%H:%M:%S'),
                'file_size': file_size,
                'file_extension': os.path.splitext(file_path)[1]
            }
            
            # Log the event with enhanced data
            log_event("CREATED", file_path, ip_address=get_local_ip(),
                      hash_after=hash_after, additional_metadata=metadata)
            
            # Create backup only for high threat files
            if threat_level == 'HIGH':
                self._backup_file(file_path)
            
            # Print appropriate notification
            if threat_level == 'HIGH':
                print(red(f"[!] HIGH THREAT: New file created: {os.path.basename(file_path)}"))
            elif threat_level == 'MEDIUM':
                print(yellow(f"[!] New file created: {os.path.basename(file_path)}"))
            else:
                print(green(f"[+] New file created: {os.path.basename(file_path)}"))
                
        except Exception as e:
            print(f"[!] Error handling file creation: {e}")
            # Basic logging as fallback
            log_event("CREATED", event.src_path, ip_address=get_local_ip())

    def on_deleted(self, event):
        if event.is_directory:
            return
            
        try:
            file_path = event.src_path
            
            with self.event_lock:
                # Get history data if available
                history_data = self.event_history.get(file_path, {})
                interaction_count = self.interaction_counts.get(file_path, 0)
            
            # Calculate basic threat level based on filename
            threat_level = 'LOW'
            for keyword in self.high_value_keywords:
                if keyword in os.path.basename(file_path).lower():
                    threat_level = 'MEDIUM'
                    break
            
            # If there were multiple interactions before deletion, raise threat level
            if interaction_count > 3:
                threat_level = 'HIGH'
            
            # Enhanced metadata
            metadata = {
                'last_known_hash': history_data.get('hash', ''),
                'interaction_count': interaction_count,
                'threat_level': threat_level,
                'time_of_day': datetime.datetime.now().strftime('%H:%M:%S'),
                'file_existed_for': time.time() - history_data.get('creation_time', time.time()) if 'creation_time' in history_data else 'unknown'
            }
            
            # Log with enhanced data
            log_event("DELETED", file_path, ip_address=get_local_ip(), 
                      additional_metadata=metadata)
            
            with self.event_lock:
                # Clean up our tracking dictionaries
                if file_path in self.event_history:
                    del self.event_history[file_path]
                if file_path in self.interaction_counts:
                    del self.interaction_counts[file_path]
                
            # Print appropriate notification
            if threat_level == 'HIGH':
                print(red(f"[!] HIGH THREAT: File deleted: {os.path.basename(file_path)}"))
            elif threat_level == 'MEDIUM':
                print(yellow(f"[!] File deleted: {os.path.basename(file_path)}"))
            else:
                print(green(f"[+] File deleted: {os.path.basename(file_path)}"))
                
        except Exception as e:
            print(f"[!] Error handling file deletion: {e}")
            # Basic logging as fallback
            log_event("DELETED", event.src_path, ip_address=get_local_ip())

    def on_moved(self, event):
        if event.is_directory:
            return
            
        try:
            src_path = event.src_path
            dest_path = event.dest_path
            
            # Calculate threat level - file moves can be suspicious
            threat_level = 'MEDIUM'  # Default to medium for moves
            
            # Consider moves to hidden locations high threat
            if os.path.basename(dest_path).startswith('.'):
                threat_level = 'HIGH'
            
            with self.event_lock:    
                # Get history data if available
                history_data = self.event_history.get(src_path, {})
                
                # Update our tracking
                if src_path in self.event_history:
                    self.event_history[dest_path] = self.event_history[src_path]
                    del self.event_history[src_path]
                if src_path in self.interaction_counts:
                    self.interaction_counts[dest_path] = self.interaction_counts[src_path]
                    del self.interaction_counts[src_path]
            
            # Enhanced metadata
            metadata = {
                'last_known_hash': history_data.get('hash', ''),
                'threat_level': threat_level,
                'time_of_day': datetime.datetime.now().strftime('%H:%M:%S'),
                'destination_is_hidden': os.path.basename(dest_path).startswith('.')
            }
            
            # Log with enhanced data
            log_event("MOVED", f"{src_path} -> {dest_path}", 
                      ip_address=get_local_ip(), additional_metadata=metadata)
            
            # Print appropriate notification  
            if threat_level == 'HIGH':
                print(red(f"[!] HIGH THREAT: File moved: {os.path.basename(src_path)} -> {os.path.basename(dest_path)}"))
            else:
                print(yellow(f"[!] File moved: {os.path.basename(src_path)} -> {os.path.basename(dest_path)}"))
                
        except Exception as e:
            print(f"[!] Error handling file move: {e}")
            # Basic logging as fallback
            log_event("MOVED", f"{event.src_path} -> {event.dest_path}", 
                      ip_address=get_local_ip())

    def _assess_threat_level(self, file_path, content):
        """Assess the threat level of a file interaction based on filename and content"""
        filename = os.path.basename(file_path).lower()
        
        # Check for high-value filenames
        threat_level = 'LOW'
        for keyword in self.high_value_keywords:
            if keyword in filename:
                threat_level = 'MEDIUM'
                break
        
        # Consider certain extensions as higher risk
        high_risk_extensions = ['.sh', '.exe', '.bat', '.ps1', '.php', '.py', '.pl']
        if any(file_path.endswith(ext) for ext in high_risk_extensions):
            threat_level = 'MEDIUM'
        
        # If there's content, scan it for suspicious patterns
        if content:
            # Check for scripts, shell commands, base64
            suspicious_patterns = ['eval', 'exec', 'system', 'base64', 'curl', 'wget']
            if any(pattern in content.lower() for pattern in suspicious_patterns):
                threat_level = 'HIGH'

        return threat_level

    def _backup_file(self, file_path):
        """Create a backup of a file that triggered an alert"""
        try:
            # Only backup if file still exists
            if not os.path.exists(file_path):
                return
                
            # Define backup directory with timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_dir = os.path.join(os.path.dirname(DECOY_DIR), "backups")
            os.makedirs(backup_dir, exist_ok=True)
            
            # Create unique backup filename
            filename = os.path.basename(file_path)
            backup_path = os.path.join(backup_dir, f"{timestamp}_{filename}")
            
            # Copy file to backup location
            shutil.copy2(file_path, backup_path)
            print(green(f"[+] Backed up suspicious file to {backup_path}"))
        except Exception as e:
            print(f"[!] Failed to back up file: {e}")


def start_watchdog():
    """Start the watchdog to monitor the honeypot directory for changes"""
    global _observer
    
    with _observer_lock:
        # Stop any existing observer
        if _observer is not None:
            _observer.stop()
            _observer.join(timeout=5)
        
        # Create and start new observer
        event_handler = HoneypotHandler()
        _observer = Observer()
        _observer.schedule(event_handler, path=DECOY_DIR, recursive=True)
        _observer.start()
    
    print(green(f"[+] File watcher started - monitoring {DECOY_DIR}"))
    return _observer  # Return the observer for main thread to join