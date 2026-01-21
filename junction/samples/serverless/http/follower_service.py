import http.client
from http.server import BaseHTTPRequestHandler
import sys
from watchdog import WatchDog
import patch

patch.patch_socket()

# --- 1. CONFIGURATION ---
GATEWAY_IP = "10.10.1.1"
GATEWAY_PORT = 8080

# --- 2. GENERATE DATABASE ---
def generate_followers(count):
    db = {}
    for i in range(count):
        db[i] = list(range(i))
    return db

FOLLOWERS_DB = generate_followers(100)

# --- 3. GATEWAY CLIENT HELPER ---
def call_gateway(path):
    conn = None
    try:
        # Python tries to set TCP_NODELAY here, but our patch will catch the error
        conn = http.client.HTTPConnection(GATEWAY_IP, GATEWAY_PORT)
        
        conn.request("GET", path)
        resp = conn.getresponse()
        
        if resp.status == 200:
            return resp.read().decode('utf-8')
        return "" 

    except Exception as e:
        print(f"[Follower] Gateway call failed: {e}", file=sys.stderr)
        return ""
    finally:
        if conn:
            conn.close()

# --- 4. HANDLER LOGIC ---
class FollowerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        prefix = "/followers/"
        if not self.path.startswith(prefix):
            self.send_error(404, "Not Found")
            return

        try:
            user_id_str = self.path[len(prefix):]
            user_id = int(user_id_str)
            
            if user_id not in FOLLOWERS_DB:
                raise ValueError("User not found")
            
            followers = FOLLOWERS_DB[user_id]
            
            names = []
            for f_id in followers:
                req_path = f"/user/{f_id}"
                name = call_gateway(req_path)
                names.append(name)
            
            response_body = ", ".join(names)
            
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body.encode('utf-8'))
            
        except (ValueError, KeyError):
            error_msg = "User does exist" 
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(error_msg)))
            self.end_headers()
            self.wfile.write(error_msg.encode('utf-8'))

    def log_message(self, format, *args):
        return

if __name__ == "__main__":
    w = WatchDog("follower", FollowerHandler)
    w.run()
