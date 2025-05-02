import os
import shutil
from config import PRE_GENERATED_DIR, DEPLOYED_DIR
from utils.helpers import green, yellow
from utils.file_utils import generate_fake_content

def deploy_initial_decoys():
    print(green("[+] Deploying initial decoys..."))

    # Ensure directories exist
    if not os.path.exists(DEPLOYED_DIR):
        os.makedirs(DEPLOYED_DIR)
    
    if not os.path.exists(PRE_GENERATED_DIR):
        os.makedirs(PRE_GENERATED_DIR)
    
    # Create sample decoy files in categories
    sample_categories = ["documents", "credentials", "configs"]
    files_created = False
    
    for category in sample_categories:
        category_path = os.path.join(PRE_GENERATED_DIR, category)
        if not os.path.exists(category_path):
            os.makedirs(category_path)
            files_created = True
            
            # Create 2 sample files per category
            for i in range(2):
                filename = f"sample_{category}_{i+1}.txt"
                file_path = os.path.join(category_path, filename)
                with open(file_path, "w") as f:
                    f.write(generate_fake_content())
                print(f"    [+] Created: {filename} in {category}")
    
    if files_created:
        print(yellow("[!] Created sample decoy files in pre-generated directory"))
    
    # Deploy decoys from all category folders
    deployed_count = 0
    for category in os.listdir(PRE_GENERATED_DIR):
        category_path = os.path.join(PRE_GENERATED_DIR, category)
        if os.path.isdir(category_path):
            for filename in os.listdir(category_path):
                src = os.path.join(category_path, filename)
                dst = os.path.join(DEPLOYED_DIR, filename)
                if os.path.isfile(src):
                    shutil.copy2(src, dst)
                    print(f"    [+] Deployed: {filename}")
                    deployed_count += 1

    print(green(f"[+] Decoy deployment complete. {deployed_count} files deployed."))