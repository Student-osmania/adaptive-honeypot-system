import socket
import threading
import re
from datetime import datetime

LOG_PATH = "logs/sql_honeypot.log"

def log_event(client_ip, query, alert=None):
    with open(LOG_PATH, "a") as f:
        timestamp = datetime.utcnow().isoformat()
        f.write(f"{timestamp} - {client_ip} - QUERY: {query}\n")
        if alert:
            f.write(f"{timestamp} - {client_ip} - ALERT: {alert}\n")

def detect_sql_injection(query):
    patterns = [
        r"(?i)\bunion\b.*\bselect\b",
        r"(?i)or\s+1=1",
        r"(?i)drop\s+table",
        r"(?i)insert\s+into",
        r"(?i)--",
    ]
    for pattern in patterns:
        if re.search(pattern, query):
            return True
    return False

def handle_client(client_socket, client_addr):
    client_ip = client_addr[0]
    client_socket.sendall(b"FakeSQL v1.0\nLogin: ")
    client_socket.recv(1024)
    client_socket.sendall(b"Password: ")
    client_socket.recv(1024)
    client_socket.sendall(b"Connected to FakeSQL. Enter your SQL queries below.\n> ")

    try:
        while True:
            data = client_socket.recv(2048)
            if not data:
                break
            query = data.decode().strip()
            print(f"[SQL] {client_ip} -> {query}")

            alert = None
            if detect_sql_injection(query):
                alert = "SQL Injection detected"
                response = "ERROR: Malformed SQL statement\n"
            else:
                response = "Query OK, 0 rows affected\n"

            log_event(client_ip, query, alert)
            client_socket.sendall(response.encode() + b"\n> ")
    except Exception as e:
        print(f"[!] SQL client error: {e}")
    finally:
        client_socket.close()

def start_sql_honeypot(host='0.0.0.0', port=3306):
    print(f"[+] SQL Honeypot listening on {host}:{port}")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)

    while True:
        client_sock, addr = server.accept()
        threading.Thread(target=handle_client, args=(client_sock, addr)).start()

if __name__ == "__main__":
    start_sql_honeypot()
