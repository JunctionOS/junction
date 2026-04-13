#!/usr/bin/env python3
"""
migrate_criu.py - Disk-less stop-and-copy migration benchmark using CRIU.
Follows https://criu.org/Disk-less_migration

Memory pages are streamed directly to the destination page-server over TCP.
Only small metadata images are copied via scp.

Requires: criu built and installed (see README)
Requires: passwordless ssh/scp from node-0 to node-1

Usage:
  Node 1 (receiver): scripts/migrate_criu.py receiver
  Node 0 (sender):   scripts/migrate_criu.py sender <service_port>
                     scripts/migrate_criu.py migrate <service_port> [-v]
"""

import argparse
import os
import socket
import subprocess
import time

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
ROOT_DIR = os.path.join(SCRIPT_DIR, "..")
COUNTER_SVC = os.path.join(ROOT_DIR, "build", "junction", "samples", "migration", "counter_service")

DST_IP = "128.105.146.85"  # host IP of node-1 (page-server + service reachability)
DST_SSH = "node-1"         # SSH alias for the destination host (see ~/.ssh/config)
DUMP_DIR = "/tmp/criu_dump"
PAGE_SERVER_PORT = 9999


def send_cmd(ip, port, cmd, timeout=5):
    with socket.create_connection((ip, port), timeout=timeout) as s:
        s.sendall((cmd + "\n").encode())
        return s.recv(64).decode().strip()


def wait_for_service(ip, port, timeout=30):
    deadline = time.perf_counter() + timeout
    while time.monotonic() < deadline:
        try:
            send_cmd(ip, port, "GET", timeout=0.1)
            return time.perf_counter()
        except OSError:
            time.sleep(0.01)
    raise TimeoutError(f"Service at {ip}:{port} did not come up within {timeout}s")


def run(cmd, **kwargs):
    print(f"==> Running: {' '.join(cmd)}")
    return subprocess.run(cmd, **kwargs)


def cmd_receiver():
    subprocess.run(["sudo", "pkill", "-f", "counter_service"], capture_output=True)
    subprocess.run(["sudo", "mkdir", "-p", DUMP_DIR], check=True)
    subprocess.run(["sudo", "mount", "-t", "tmpfs", "none", DUMP_DIR], check=True)
    print(f"==> Starting CRIU page-server on port {PAGE_SERVER_PORT} ...")
    run([
        "sudo", "criu", "page-server",
        "--images-dir", DUMP_DIR,
        "--port", str(PAGE_SERVER_PORT),
    ], check=True)
    print("==> Page-server done. Waiting for metadata images and restore ...")
    # Poll until counter_service is running (restored by migrate)
    while subprocess.run(["pgrep", "-f", "counter_service"],
                         capture_output=True).returncode != 0:
        time.sleep(0.1)
    print("==> Restore complete. counter_service is running.")


def cmd_sender(port):
    print(f"==> Starting counter_service on port {port}")
    with open(os.devnull, 'r') as devnull_r, open(os.devnull, 'w') as devnull_w:
        proc = subprocess.Popen(
            ["setsid", COUNTER_SVC, str(port)],
            stdin=devnull_r, stdout=devnull_w, stderr=devnull_w
        )
    print(f"==> PID: {proc.pid}. Run 'migrate {port}' on this node to trigger migration.")
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.kill()
        print("\n==> Sender stopped.")


def cmd_migrate(port, verbose):
    v = ["-v"] if verbose else []

    print(f"==> Incrementing counter on source (localhost):")
    for _ in range(3):
        print(send_cmd("127.0.0.1", port, "INC"))
    print("==> Counter state before migration:")
    print(send_cmd("127.0.0.1", port, "GET"))

    pid = int(subprocess.check_output(["pgrep", "-f", "counter_service"])
              .decode().strip().splitlines()[0])
    print(f"==> Dumping pid={pid}, streaming pages to {DST_IP}:{PAGE_SERVER_PORT}")

    subprocess.run(["sudo", "mkdir", "-p", DUMP_DIR], check=True)
    subprocess.run(["sudo", "mount", "-t", "tmpfs", "none", DUMP_DIR],
                   capture_output=True)

    t_start = time.perf_counter()

    run([
        "sudo", "criu", "dump",
        "--tree", str(pid),
        "--images-dir", DUMP_DIR,
        "--leave-stopped",
        "--page-server", "--address", DST_IP, "--port", str(PAGE_SERVER_PORT),
    ] + v, check=True)
    t_src_down = time.perf_counter()

    # Measure metadata size (pages already on dst)
    dump_size = sum(
        os.path.getsize(os.path.join(DUMP_DIR, f))
        for f in os.listdir(DUMP_DIR)
    )

    # Count pages transferred — pagemap is on dst since pages were streamed there
    result = subprocess.run(
        ["ssh", DST_SSH, f"stat -c %s {DUMP_DIR}/pages-*.img 2>/dev/null || echo 0"],
        capture_output=True, text=True
    )
    pages_bytes = sum(int(x) for x in result.stdout.split() if x.isdigit())
    pages_written = pages_bytes // 4096

    # Copy small metadata images to dst
    print("==> Copying metadata images to destination ...")
    run(["scp", "-r", f"{DUMP_DIR}/.", f"{DST_SSH}:{DUMP_DIR}/"], check=True)

    # Restore on dst
    print("==> Restoring on destination ...")
    run([
        "ssh", DST_SSH,
        f"sudo setsid criu restore --images-dir {DUMP_DIR} -d {' '.join(v)}"
    ], check=True)

    t_dst_up = wait_for_service(DST_IP, port)

    # Kill stopped process on source
    subprocess.run(["sudo", "kill", "-9", str(pid)], capture_output=True)

    downtime_ms = (t_dst_up - t_src_down) * 1000
    total_ms = (t_dst_up - t_start) * 1000

    print("==> Verifying source is no longer serving:")
    try:
        send_cmd("127.0.0.1", port, "GET", timeout=2)
        print("WARNING: source still responding!")
    except OSError:
        print("==> Source confirmed down.")

    print("==> Counter state on destination:")
    print(send_cmd(DST_IP, port, "GET"))
    print("==> Incrementing counter on destination:")
    for _ in range(3):
        print(send_cmd(DST_IP, port, "INC"))
    print("==> Final counter state on destination:")
    print(send_cmd(DST_IP, port, "GET"))

    print(f"\n==> Metadata size:        {dump_size // 1024} KiB")
    print(f"==> Pages transferred:    {pages_written} ({pages_written * 4} KiB)")
    print(f"==> Downtime:             {downtime_ms:.1f} ms")
    print(f"==> Total migration time: {total_ms:.1f} ms")

    # Cleanup
    subprocess.run(["sudo", "umount", DUMP_DIR], capture_output=True)
    subprocess.run(["ssh", DST_SSH, f"sudo umount {DUMP_DIR}"], capture_output=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="role", required=True)
    sub.add_parser("sender").add_argument("port", type=int)
    sub.add_parser("receiver")
    p = sub.add_parser("migrate")
    p.add_argument("port", type=int)
    p.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.role == "sender":
        cmd_sender(args.port)
    elif args.role == "receiver":
        cmd_receiver()
    elif args.role == "migrate":
        cmd_migrate(args.port, args.verbose)


if __name__ == "__main__":
    main()
