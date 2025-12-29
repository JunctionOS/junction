import http.client
import sys

# --- CONFIGURATION ---
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
# ---------------------

def run_client(host, port):
    print(f"--- CLI HTTP Client targeting {host}:{port} ---")
    print("Format: METHOD PATH [BODY]")
    print("Ex:     GET /user")
    print("Ex:     POST /user {\"name\": \"foo\"}")
    print("Type 'quit' to exit.\n")

    while True:
        try:
            # 1. Single Line Input
            command = input(f"[{host}:{port}] > ").strip()
            
            if not command:
                continue
            
            if command.lower() in ["quit", "exit"]:
                break

            # 2. Parse the Command
            # Split into max 3 parts: Method, Path, Rest-is-Body
            parts = command.split(maxsplit=2)
            
            if len(parts) < 2:
                print("Error: Invalid format. Usage: METHOD PATH [BODY]")
                continue

            method = parts[0].upper()
            path = parts[1]
            body = parts[2] if len(parts) > 2 else None

            # Headers logic: If body looks like JSON, set header
            headers = {}
            if body:
                if body.startswith("{") or body.startswith("["):
                    headers["Content-Type"] = "application/json"
                else:
                    headers["Content-Type"] = "text/plain"

            # 3. Send Request
            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request(method, path, body=body, headers=headers)
            
            # 4. Get Response
            resp = conn.getresponse()
            resp_body = resp.read().decode('utf-8')

            print(f"< HTTP {resp.status} {resp.reason}")
            # Print important headers
            for k, v in resp.getheaders():
                if k.lower() in ['content-type', 'content-length', 'server']:
                    print(f"< {k}: {v}")
            
            if resp_body:
                print(f"\n{resp_body}")
            print("") # Empty line for spacing
            
            conn.close()

        except ConnectionRefusedError:
            print(f"[!] Connection Refused at {host}:{port}")
        except Exception as e:
            print(f"[!] Error: {e}")

if __name__ == "__main__":
    target_host = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HOST
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
    
    run_client(target_host, target_port)
