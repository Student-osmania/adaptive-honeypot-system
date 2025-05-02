import socket
import threading
import datetime
import re

LOG_PATH = "logs/sql_honeypot.log"

SQL_BANNER = b"""
FakeSQL DB Server v1.0
Connected to database: honeypot
Type 'help' for available commands.
> """

SQL_RESPONSES = {
    "SHOW TABLES": "users, passwords, transactions",
    "SELECT * FROM USERS": "id | username | email\n1 | admin | admin@example.com",
    "HELP": "Available: SHOW TABLES, SELECT, INSERT, UPDATE, DELETE, EXIT",
    "EXIT": "Goodbye!",
}

def log_sql_event(ip, query, alert=False):
    timestamp = datetime.datetime.utcnow().isoformat()
    with open(LOG_PATH, "a") as f:
        f.write(f"{timestamp} - {ip} - SQL QUERY: {query}\n")
        if alert:
            f.write(f"{timestamp} - {ip} - ALERT: Potential SQL Injection or data exfiltration attempt\n")

def detect_injection(query):
    patterns = [r"(?i)(\bor\b|\band\b).*=.*", r"(?i)union\s+select", r"--", r"1\s*=\s*1", r"drop\s+table"]
    return any(re.search(p, query) for p in patterns)

def handle_sql_client(sock, addr):
    client_ip = addr[0]
    print(f"[+] SQL honeypot connection from {client_ip}")
    sock.sendall(SQL_BANNER)

    try:
        while True:
            data = sock.recv(1024)
            if not data:
                break
            query = data.decode().strip()
            log_sql_event(client_ip, query)

            if detect_injection(query):
                log_sql_event(client_ip, query, alert=True)
                response = "ERROR: Malicious query detected."
            elif query.upper() in SQL_RESPONSES:
                response = SQL_RESPONSES[query.upper()]
                if query.upper() == "EXIT":
                    sock.sendall((response + "\n").encode())
                    break
            else:
                response = "ERROR: Unknown or unsupported SQL command."

            sock.sendall((response + "\n> ").encode())

    except Exception as e:
        print(f"[!] SQL honeypot error: {e}")
    finally:
        sock.close()

def start_sql_service(host='0.0.0.0', port=3307):
    print(f"[+] FakeSQL honeypot running on {host}:{port}")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)

    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_sql_client, args=(client, addr)).start()

if __name__ == "__main__":
    start_sql_service()
