import os

# Paths
DECOY_DIR = "decoys/deployed/"
PRE_GENERATED_DIR = "decoys/pre_generated/"
DEPLOYED_DIR = "decoys/deployed/"
LOG_FILE = "logs/honeypot.log"
LOG_JSON = "logs/honeypot.json"
LOG_DB = "logs/honeypot.db"
BEHAVIOR_CSV = "data/behavior_logs.csv"

# AI Settings
USE_GPT4ALL = True
GPT4ALL_MODEL_PATH = "models/gpt4all/nous-hermes.gguf"

# OpenAI fallback
USE_OPENAI = False
OPENAI_API_KEY = "your-openai-api-key"
DECISION_INTERVAL = 20  

# Mock Service Settings
ENABLE_HTTP_SERVER = True
HTTP_SERVER_PORT = 8080
HTTP_SERVER_HOST = "0.0.0.0"

ENABLE_FTP_SERVER = True
FTP_SERVER_PORT = 2121
FTP_SERVER_HOST = "0.0.0.0"
FTP_USER = "admin"
FTP_PASSWORD = "password123"  

SERVICE_LOG_DIR = "logs/services/"

BACKUP_DIR = "backups"

