import socket
import threading
import datetime
import re

LOG_PATH = "logs/cloud_honeypot.log"

CLOUD_BANNER = b"""
[CloudService API v2.3]
Authentication required. Format: AUTH <access_key>:<secret_key>
> """

AUTHORIZED = {}

CLOUD_COMMANDS = {
    "LIST BUCKETS": "Buckets: honeypot-data, logs-bucket, secret-backups",
    "START INSTANCE": "Instance i-abcd1234 starting...",
    "STOP INSTANCE": "Instance i-abcd1234 stopping...",
    "GET KEYS": "Access Denied: Insufficient permissions",
    "HELP": "Commands: LIST BUCKETS, START INSTANCE, STOP INSTANCE, GET KEYS",
}

def log_cloud_event(client_ip, command, alert=False):
    timestamp = datetime.datetime.utcnow().isoformat()
    with open(LOG_PATH, "a") as f:
        f.write(f"{timestamp} - {client_ip} - CLOUD CMD: {command}\n")
        if alert:
            f.write(f"{timestamp} - {client_ip} - ALERT: Credential misuse or suspicious API attempt\n")

def handle_client(sock, addr):
    client_ip = addr[0]
    print(f"[+] Cloud service connection from {client_ip}")
    sock.sendall(CLOUD_BANNER)

    authenticated = False

    try:
        while True:
            data = sock.recv(1024)
            if not data:
                break
            command = data.decode().strip()
            log_cloud_event(client_ip, command)

            if not authenticated:
                match = re.match(r'AUTH\s+([A-Z0-9]+):([a-zA-Z0-9+/=]+)', command)
                if match:
                    access_key, secret_key = match.groups()
                    AUTHORIZED[client_ip] = (access_key, secret_key)
                    response = f"Authentication successful for access_key={access_key}"
                    authenticated = True
                else:
                    response = "Error: Invalid AUTH format. Use AUTH <access_key>:<secret_key>"
            else:
                cmd_upper = command.upper()
                if cmd_upper in CLOUD_COMMANDS:
                    response = CLOUD_COMMANDS[cmd_upper]
                else:
                    response = "Error: Unknown command. Type HELP"

                if "KEY" in cmd_upper or "DELETE" in cmd_upper or "ROOT" in cmd_upper:
                    log_cloud_event(client_ip, command, alert=True)

            sock.sendall((response + "\n> ").encode())
    except Exception as e:
        print(f"[!] Cloud service error: {e}")
    finally:
        sock.close()

def start_cloud_service(host='0.0.0.0', port=8089):
    print(f"[+] Cloud Honeypot service running on {host}:{port}")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)

    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client, addr)).start()

if __name__ == "__main__":
    start_cloud_service()
