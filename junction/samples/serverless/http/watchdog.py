import os
import socket
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

SOCK_DIR = "/tmp/serverless/"
SOCK_EXT = ".sock"

class UnixHTTPServer(HTTPServer):
    address_family = socket.AF_UNIX

    def server_bind(self):
        # Create the directory if it doesn't exist
        if not os.path.exists(SOCK_DIR):
            try:
                os.makedirs(SOCK_DIR, mode=0o777)
            except OSError as e:
                print(f"[Watchdog] Failed to create directory: {e}", file=sys.stderr)
                sys.exit(1)

        # Unlink the socket file if it exists
        if os.path.exists(self.server_address):
            os.unlink(self.server_address)

        # Bind the socket
        HTTPServer.server_bind(self)
        
        # Set permissions so others can write/connect to it
        os.chmod(self.server_address, 0o777)

class WatchDog:
    def __init__(self, name, handler_class):
        self.sock_path = os.path.join(SOCK_DIR, name + SOCK_EXT)
        self.handler_class = handler_class

    def run(self):
        try:
            # Create the server bound to the Unix Socket path
            server = UnixHTTPServer(self.sock_path, self.handler_class)
            print(f"[Watchdog] Listening on {self.sock_path}...")
            server.serve_forever()
        except Exception as e:
            print(f"[Watchdog] Critical Error: {e}", file=sys.stderr)
            sys.exit(1)
