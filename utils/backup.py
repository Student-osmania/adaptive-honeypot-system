import os
import shutil
import datetime
from config import BACKUP_DIR

def create_backup():
    """Backup important folders and files into the backups/ folder."""
    try:
        if not os.path.exists(BACKUP_DIR):
            os.makedirs(BACKUP_DIR)

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_folder = os.path.join(BACKUP_DIR, f"backup_{timestamp}")
        os.makedirs(backup_folder)

        # List of folders and files to backup
        items_to_backup = [
            "logs",
            "decoys/deployed",
            "decoys/pre_generated",
            "data",
            "models/prompt_templates",
            "models/gpt4all",
            "config.py"
        ]

        for item in items_to_backup:
            if os.path.exists(item):
                if os.path.isdir(item):
                    shutil.copytree(item, os.path.join(backup_folder, item))
                else:
                    shutil.copy2(item, os.path.join(backup_folder, item))

        print(f"[+] Backup created successfully at {backup_folder}")
    except Exception as e:
        print(f"[!] Failed to create backup: {e}")
