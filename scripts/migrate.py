#!/usr/bin/env python3
"""
migrate.py - Stop-and-copy live migration test script.
Requires: scripts/build.sh (to build migration samples)
Requires: iokerneld already running on each node (see README)

Usage:
  Node 0 (sender):    scripts/migrate.py sender <service_port>
  Node 1 (receiver):  scripts/migrate.py receiver
  Initiator:          scripts/migrate.py initiator <service_port>
"""

import argparse
import os
import socket
import subprocess
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
ROOT_DIR = os.path.join(SCRIPT_DIR, "..")
BUILD_DIR = os.path.join(ROOT_DIR, "build", "junction")
JUNCTION_RUN = os.path.join(BUILD_DIR, "junction_run")
JUNCTION_CTL = os.path.join(ROOT_DIR, "build", "junction-ctl", "junction-ctl")
MIGRATION_BUILD_DIR = os.path.join(BUILD_DIR, "samples", "migration")
SERVICE_CONFIG = os.path.join(MIGRATION_BUILD_DIR, "caladan_service.config")
DST_CONFIG = os.path.join(MIGRATION_BUILD_DIR, "caladan_migration_dst.config")
COUNTER_SVC = os.path.join(MIGRATION_BUILD_DIR, "counter_service")

SRC_IP = "10.10.1.1"
DST_IP = "10.10.1.2"


def send_cmd(ip, port, cmd, timeout=5):
    """Send a command to counter_service and return the response."""
    with socket.create_connection((ip, port), timeout=timeout) as s:
        s.sendall((cmd + "\n").encode())
        return s.recv(64).decode().strip()


def wait_for_service(ip, port, timeout=30):
    """Poll until the service responds, return time when it first responds."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            send_cmd(ip, port, "GET", timeout=0.1)
            return time.perf_counter()
        except OSError:
            time.sleep(0.001)
    raise TimeoutError(f"Service at {ip}:{port} did not come up within {timeout}s")


def kill_leftover():
    subprocess.run(["sudo", "pkill", "-f", "junction_run"],
                   capture_output=True)
    time.sleep(1)


def cmd_sender(port):
    kill_leftover()
    print(f"==> Starting counter_service on {SRC_IP}:{port}")
    subprocess.run([
        "sudo", "-E", JUNCTION_RUN, SERVICE_CONFIG, "--snapshot_enabled",
        "--", COUNTER_SVC, str(port)
    ])


def cmd_receiver():
    kill_leftover()
    print("==> Migration server listening on port 44")
    subprocess.run([
        "sudo", "-E", JUNCTION_RUN, DST_CONFIG, "--snapshot_enabled"
    ])


def cmd_initiator(port):
    # Increment counter on source
    print(f"==> Incrementing counter on source ({SRC_IP}):")
    for _ in range(3):
        print(send_cmd(SRC_IP, port, "INC"))
    print("==> Counter state before migration:")
    print(send_cmd(SRC_IP, port, "GET"))

    # Get PID
    pid = subprocess.check_output(
        [JUNCTION_CTL, SRC_IP, "ps"]
    ).decode().strip().strip("[]").split(",")[0].strip()
    print(f"==> Migrating pid={pid} from {SRC_IP} to {DST_IP}:44")

    # Trigger migration and measure
    t_start = time.perf_counter()
    subprocess.run([JUNCTION_CTL, SRC_IP, "migrate", pid, DST_IP, "44"],
                   check=True)
    t_src_down = time.perf_counter()

    # Verify source is down
    print("==> Verifying source is no longer serving (expect error):")
    try:
        send_cmd(SRC_IP, port, "GET", timeout=2)
        print("WARNING: source still responding!")
    except OSError:
        print("==> Source confirmed down.")

    # Wait for destination to be ready
    t_wait_start = time.perf_counter()
    t_dst_up = wait_for_service(DST_IP, port)
    wait_us = (t_dst_up - t_wait_start) * 1e6
    print(f"==> wait_for_service took: {wait_us:.1f} us")

    downtime_us = (t_dst_up - t_src_down) * 1e6
    total_us = (t_dst_up - t_start) * 1e6

    print("==> Counter state on destination:")
    print(send_cmd(DST_IP, port, "GET"))

    # Verify counter continues incrementing on destination
    print("==> Incrementing counter on destination:")
    for _ in range(3):
        print(send_cmd(DST_IP, port, "INC"))
    print("==> Final counter state on destination:")
    print(send_cmd(DST_IP, port, "GET"))

    print(f"\n==> Downtime:             {downtime_us:.1f} us")
    print(f"==> Total migration time: {total_us:.1f} us")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="role", required=True)
    s = sub.add_parser("sender")
    s.add_argument("port", type=int)
    sub.add_parser("receiver")
    i = sub.add_parser("initiator")
    i.add_argument("port", type=int)
    args = parser.parse_args()

    if args.role == "sender":
        cmd_sender(args.port)
    elif args.role == "receiver":
        cmd_receiver()
    elif args.role == "initiator":
        cmd_initiator(args.port)


if __name__ == "__main__":
    main()
