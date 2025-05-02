import threading
import time
import os
import signal
import sys
from core import watcher, deployment
from utils import timing
from utils import backup  
from utils.helpers import green, yellow, red
from mock_services import http_server, ftp_server, ssh_server
from core.logger import log_event

_stop_event = threading.Event()

def signal_handler(sig, frame):
    """Handle shutdown signals gracefully"""
    print(yellow("\n[+] Shutting down honeypot system..."))
    backup.create_backup()  
    _stop_event.set()
    log_event(event_type="SYSTEM_SHUTDOWN", file_path="", additional_metadata={"message": "System shutdown initiated."})
    sys.exit(0)

def check_prerequisites():
    """Check if all required directories exist and create them if not"""
    from config import DECOY_DIR, PRE_GENERATED_DIR, DEPLOYED_DIR

    dirs = [
        os.path.dirname(DECOY_DIR),
        DECOY_DIR,
        PRE_GENERATED_DIR,
        DEPLOYED_DIR,
        "logs",
        "data",
        "models/gpt4all",
        "models/prompt_templates",
        "backups"  
    ]

    for d in dirs:
        if not os.path.exists(d):
            os.makedirs(d, exist_ok=True)
            print(f"Created directory: {d}")

    log_files = [
        "logs/honeypot.log",
        "logs/honeypot.json",
        "data/behavior_logs.csv"
    ]

    for log_file in log_files:
        if not os.path.exists(log_file):
            with open(log_file, "w") as f:
                if log_file.endswith("csv"):
                    f.write("timestamp,event_type,file_path,user,ip_address,hash_before,hash_after,action_taken,additional_metadata\n")
                elif log_file.endswith("log"):
                    f.write("# Honeypot Log File\n")
                elif log_file.endswith("json"):
                    f.write("# Honeypot JSON Log\n")

def start_system():
    """Initialize and start the honeypot system"""
    print(green("[+] Starting Honeypot System..."))
    log_event(event_type="SYSTEM_START", file_path="", additional_metadata={"message": "Honeypot system started."})

    try:
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        check_prerequisites()

        backup.create_backup()

        deployment.deploy_initial_decoys()

        http_thread = threading.Thread(target=http_server.app.run, kwargs={"host": "0.0.0.0", "port": 8080, "debug": False})
        ftp_thread = threading.Thread(target=ftp_server.start_ftp_server)
        ssh_thread = threading.Thread(target=ssh_server.start_ssh_server)

        http_thread.daemon = True
        ftp_thread.daemon = True
        ssh_thread.daemon = True
        http_thread.start()
        ftp_thread.start()
        ssh_thread.start()

        print(green("[+] Mock services (HTTP, SSH and FTP) started successfully"))

        watchdog = watcher.start_watchdog()
        print(green("[+] File watcher started successfully"))

        timer_thread = timing.schedule_analysis()
        print(green("[+] Periodic analysis scheduler started"))

        print(green("[+] Honeypot system is now running. Press CTRL+C to exit."))

        while not _stop_event.is_set():
            time.sleep(1)

    except KeyboardInterrupt:
        print(yellow("[+] Shutting down honeypot system..."))
        backup.create_backup() 
        log_event(event_type="SYSTEM_SHUTDOWN", file_path="", additional_metadata={"message": "System shutdown initiated."})
    except Exception as e:
        print(red(f"[!] Error in main thread: {e}"))
        log_event(event_type="ERROR", file_path="", additional_metadata={"message": f"Error in main thread: {e}"})
    finally:
        _stop_event.set()

if __name__ == "__main__":
    start_system()
