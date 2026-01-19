import http.client
import sys
import time
import random
import argparse
import statistics

# --- CONFIGURATION ---
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
# ---------------------

def send_measured_request(conn, method, path, body=None):
    """
    Helper to send a request and measure latency.
    Returns: (latency_ms, response_obj, response_body_bytes)
    """
    headers = {}
    if body:
        if body.startswith("{") or body.startswith("["):
            headers["Content-Type"] = "application/json"
        else:
            headers["Content-Type"] = "text/plain"

    # Start Clock
    t_start = time.perf_counter()
    
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    resp_body = resp.read() # Read entire body to complete the transaction
    
    # Stop Clock
    t_end = time.perf_counter()
    
    latency_ms = (t_end - t_start) * 1000
    return latency_ms, resp, resp_body


def run_test_suite(host, port, request_count=1000):
    print(f"--- Running Performance Benchmark ---")
    print(f"Target:       {host}:{port}")
    print(f"Sample Size:  {request_count}")
    print(f"Workload:     /followers Only (Shim Target)")
    
    # 1. GENERATE PATHS (/followers only)
    paths = []
    for i in range(request_count):
        user_id = random.randint(0, 99)
        paths.append(f"/followers/{user_id}")

    # 2. WARM UP
    print("warming up...", end="", flush=True)
    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        # Warm up with a simple request
        for _ in range(20):
            send_measured_request(conn, "GET", "/followers/1")
        print(" done.")
    except Exception as e:
        print(f"\n[!] Warm-up failed: {e}")
        return

    # 3. THE REAL TEST
    print(f"Sending {request_count} requests...", flush=True)
    
    latencies = []
    start_total = time.time()
    
    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)

        for idx, path in enumerate(paths):
            print(f"\rProgress: {idx+1}/{request_count}", end="", flush=True)
            # --- USE HELPER ---
            latency, resp, _ = send_measured_request(conn, "GET", path)
            latencies.append(latency)
            
            if resp.status != 200:
                print(f"!", end="") # Visual indicator of errors

        conn.close()

    except Exception as e:
        print(f"\n[!] Error during test: {e}")
        return

    duration = time.time() - start_total
    print(f" done in {duration:.2f}s.\n")

    # 4. STATISTICS
    if latencies:
        print(f"--- Results ---")
        print(f"Min:    {min(latencies):.3f} ms")
        print(f"Avg:    {statistics.mean(latencies):.3f} ms")
        print(f"Median: {statistics.median(latencies):.3f} ms")
        print(f"P99:    {statistics.quantiles(latencies, n=100)[98]:.3f} ms")
        print(f"Max:    {max(latencies):.3f} ms")
        print("--------------------------------")


def run_interactive_client(host, port):
    print(f"--- Interactive Client ({host}:{port}) ---")
    print("Type 'quit' to exit.")
    
    while True:
        try:
            cmd = input(f"[{host}:{port}] > ").strip()
            if cmd in ["quit", "exit"]: break
            if not cmd: continue
            
            parts = cmd.split(maxsplit=2)
            if len(parts) < 2:
                print("Usage: METHOD PATH [BODY]")
                continue

            method, path = parts[0], parts[1]
            body = parts[2] if len(parts) > 2 else None

            conn = http.client.HTTPConnection(host, port, timeout=5)
            
            # --- USE HELPER ---
            latency, resp, resp_body = send_measured_request(conn, method, path, body)
            
            conn.close()
            
            print(f"< HTTP {resp.status} ({latency:.2f} ms)")
            if resp_body:
                print(resp_body.decode('utf-8'))
            print("")

        except ConnectionRefusedError:
            print(f"[!] Connection Refused at {host}:{port}")
        except Exception as e:
            print(f"[!] Error: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default=DEFAULT_HOST)
    parser.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    parser.add_argument("--test", action="store_true", help="Run /followers benchmark")
    parser.add_argument("-n", "--count", type=int, default=1000)
    
    args = parser.parse_args()

    if args.test:
        run_test_suite(args.host, args.port, args.count)
    else:
        run_interactive_client(args.host, args.port)
