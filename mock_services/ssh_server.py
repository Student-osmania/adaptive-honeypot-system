import socket
import threading
import paramiko
import time
from paramiko import ServerInterface, RSAKey
from paramiko.common import OPEN_SUCCEEDED
from core.logger import log_event
from utils.helpers import yellow

class HoneypotSSHServer(ServerInterface):
    def __init__(self, client_ip="unknown"):
        self.username = None
        self.ip_address = client_ip  # Set from connection socket
        self.start_time = time.time()
        self.commands = []
        self.authenticated = False
        self.client_version = "unknown"
        self._transport = None  # Will be set by Paramiko

    # Called automatically by Paramiko
    def set_transport(self, transport):
        self._transport = transport
        try:
            self.client_version = transport.remote_version
        except:
            pass

    def check_auth_password(self, username, password):
        self.username = username
        
        log_event(
            event_type="SSH_AUTH_ATTEMPT",
            file_path="",
            user=username,
            ip_address=self.ip_address,
            additional_metadata={
                "password": password,
                "status": "accepted",
                "client_version": self.client_version
            }
        )
        self.authenticated = True
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return OPEN_SUCCEEDED if kind == "session" else super().check_channel_request(kind, chanid)

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

def handle_connection(client, addr):
    ip = addr[0] if addr else "unknown"
    transport = paramiko.Transport(client)
    transport.add_server_key(RSAKey.generate(2048))
    server = HoneypotSSHServer(client_ip=ip)
    
    try:
        transport.start_server(server=server)
    except paramiko.SSHException as e:
        log_event(
            event_type="SSH_ERROR",
            file_path="",
            ip_address=ip,
            additional_metadata={"error": f"Transport error: {str(e)}"}
        )
        return

    chan = transport.accept(20)
    if not chan:
        return

    try:
        log_event(
            event_type="SSH_SESSION_START",
            file_path="",
            user=server.username,
            ip_address=server.ip_address,
            additional_metadata={
                "session_start": time.strftime("%Y-%m-%d %H:%M:%S"),
                "client_version": server.client_version
            }
        )

        # Interactive shell
        chan.set_combine_stderr(True)
        chan.send("Welcome to Ubuntu 20.04 LTS\r\n")
        chan.send("$ ")
        
        buffer = ""
        while not chan.closed:
            if chan.recv_ready():
                data = chan.recv(1024).decode('utf-8')
                
                for char in data:
                    if char not in ('\r', '\n'):
                        chan.send(char)
                
                if '\r' in data or '\n' in data:
                    command = buffer.strip()
                    buffer = ""
                    
                    if command:
                        log_event(
                            event_type="SSH_COMMAND",
                            file_path="",
                            user=server.username,
                            ip_address=server.ip_address,
                            additional_metadata={
                                "command": command,
                                "timestamp": time.time()
                            }
                        )
                        response = process_command(command)
                        chan.send("\r\n" + response + "\r\n$ ")
                    else:
                        chan.send("\r\n$ ")
                else:
                    buffer += data
                    
    except Exception as e:
        log_event(
            event_type="SSH_ERROR",
            file_path="",
            user=server.username,
            ip_address=server.ip_address,
            additional_metadata={"error": str(e)}
        )
    finally:
        log_event(
            event_type="SSH_SESSION_END",
            file_path="",
            user=server.username,
            ip_address=server.ip_address,
            additional_metadata={
                "duration": round(time.time() - server.start_time, 2),
                "commands": server.commands
            }
        )
        chan.close()
        transport.close()

def process_command(command):
    if command == "exit":
        return "logout"
    elif command == "ls":
        return "file1.txt  file2.log"
    elif command == "whoami":
        return "root"
    else:
        return f"{command}: command not found"

def start_ssh_server(host='0.0.0.0', port=2222):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)
    
    print(yellow(f"[+] SSH honeypot running on {host}:{port}"))
    
    try:
        while True:
            client, addr = sock.accept()
            threading.Thread(
                target=handle_connection,
                args=(client, addr),
                daemon=True
            ).start()
    except KeyboardInterrupt:
        print(yellow("\n[!] Stopping SSH honeypot..."))
    finally:
        sock.close()

if __name__ == "__main__":
    start_ssh_server()