from http.server import BaseHTTPRequestHandler
import urllib.parse
from watchdog import WatchDog

# --- 1. Generate Database ---
USERS_DB = {i: f"user_{i}" for i in range(100)}

# --- 2. Handler Logic ---
class UserHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Log request (mimics std::cout << "[User] Received...")
        print(f"[User] Received request: {self.path}")

        # Basic Routing Logic (mimics "/user/:id")
        # Python's BaseHTTPRequestHandler doesn't have built-in path params
        # so we parse manually.
        prefix = "/user/"
        if self.path.startswith(prefix):
            try:
                # Extract ID string after "/user/"
                id_str = self.path[len(prefix):]
                user_id = int(id_str)

                if user_id in USERS_DB:
                    response_body = USERS_DB[user_id]
                    
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    # Content-Length is good practice for Keep-Alive connections
                    self.send_header("Content-Length", str(len(response_body)))
                    self.end_headers()
                    
                    self.wfile.write(response_body.encode('utf-8'))
                    print(f"[User] Responding with: {response_body}")
                    return
            except ValueError:
                pass # Fall through to 404

        # 404 Case
        error_msg = "User does not exist"
        self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(error_msg)))
        self.end_headers()
        self.wfile.write(error_msg.encode('utf-8'))

    # Disable default logging to stderr (to match C++ clean output)
    def log_message(self, format, *args):
        return

if __name__ == "__main__":
    # Create and Run WatchDog
    # "user" -> creates /tmp/serverless/user.sock
    w = WatchDog("user", UserHandler)
    w.run()
