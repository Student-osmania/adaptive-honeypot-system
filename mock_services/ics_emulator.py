import socket
import threading
import datetime

LOG_PATH = "logs/ics_honeypot.log"

ICS_BANNER = b"Welcome to SCADA-Control v1.2\nType HELP for command list.\n> "

COMMAND_RESPONSES = {
    "READ TEMP": "TEMP = 72.5°F",
    "READ PRESSURE": "PRESSURE = 101.3 kPa",
    "START PUMP": "PUMP1: ACTIVATED",
    "STOP PUMP": "PUMP1: DEACTIVATED",
    "STATUS": "ALL SYSTEMS NOMINAL",
    "HELP": "Available: READ TEMP, READ PRESSURE, START PUMP, STOP PUMP, STATUS",
}

def log_ics_event(client_ip, command, alert=False):
    timestamp = datetime.datetime.utcnow().isoformat()
    with open(LOG_PATH, "a") as f:
        f.write(f"{timestamp} - {client_ip} - ICS COMMAND: {command}\n")
        if alert:
            f.write(f"{timestamp} - {client_ip} - ALERT: Unauthorized ICS command\n")

def handle_client(sock, addr):
    client_ip = addr[0]
    print(f"[+] ICS connection from {client_ip}")
    sock.sendall(ICS_BANNER)

    try:
        while True:
            data = sock.recv(1024)
            if not data:
                break
            command = data.decode().strip().upper()
            log_ics_event(client_ip, command)

            if command in COMMAND_RESPONSES:
                response = COMMAND_RESPONSES[command]
            else:
                response = "UNKNOWN COMMAND"

            if "FORMAT" in command or "ROOT" in command or "DELETE" in command:
                log_ics_event(client_ip, command, alert=True)
                response = "ALERT: Unauthorized command attempt logged"

            sock.sendall((response + "\n> ").encode())
    except Exception as e:
        print(f"[!] ICS error: {e}")
    finally:
        sock.close()

def start_ics_emulator(host='0.0.0.0', port=5020):
    print(f"[+] ICS Honeypot running on {host}:{port}")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)

    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client, addr)).start()

if __name__ == "__main__":
    start_ics_emulator()
