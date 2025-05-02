from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from core.logger import log_event

class LoggingFTPHandler(FTPHandler):
    def on_connect(self):
        """Log FTP connection with IP address."""
        try:
            # Get IP address from the socket
            self.remote_ip = self.socket.getpeername()[0]
        except Exception:
            self.remote_ip = 'unknown'
        
        log_event(
            event_type="FTP_CONNECTION",
            file_path="",
            user="unknown",
            ip_address=self.remote_ip,
            additional_metadata={"message": "FTP session opened"}
        )

    def on_login(self, username):
        """Log successful FTP login with username and IP."""
        self.remote_user = username
        
        log_event(
            event_type="FTP_LOGIN",
            file_path="",
            user=self.remote_user,
            ip_address=getattr(self, 'remote_ip', 'unknown'),
            additional_metadata={"message": "User logged in"}
        )

    def on_login_failed(self, username, password):
        """Log failed FTP login attempt with username and IP."""
        ip = getattr(self, 'remote_ip', 'unknown')
        
        log_event(
            event_type="FTP_LOGIN_FAILURE",
            file_path="",
            user=username,
            ip_address=ip,
            additional_metadata={"message": f"Failed login attempt with password: {password}"}
        )

    def on_disconnect(self):
        """Log FTP disconnection."""
        user = getattr(self, 'remote_user', 'unknown')
        ip = getattr(self, 'remote_ip', 'unknown')
        
        log_event(
            event_type="FTP_DISCONNECT",
            file_path="",
            user=user,
            ip_address=ip,
            additional_metadata={"message": "FTP session closed"}
        )

    def on_file_sent(self, file):
        """Log file sent over FTP."""
        user = getattr(self, 'remote_user', 'unknown')
        ip = getattr(self, 'remote_ip', 'unknown')
        
        log_event(
            event_type="FTP_FILE_SENT",
            file_path=file,
            user=user,
            ip_address=ip,
            additional_metadata={"message": "File sent via FTP"}
        )

def start_ftp_server():
    """Start the FTP server."""
    # Create an FTP authorizer
    authorizer = DummyAuthorizer()

    # Add a user with permissions
    authorizer.add_user(
        username="user",
        password="password",
        homedir=r"C:\Users\chakr\Desktop\major project\honeypot\mock_services",
        perm="elradfmw"
    )

    # Initialize the custom FTP handler
    handler = LoggingFTPHandler
    handler.authorizer = authorizer

    # Start the FTP server
    server = FTPServer(('0.0.0.0', 21), handler)
    print("[+] Starting FTP server on port 21...")
    server.serve_forever()
