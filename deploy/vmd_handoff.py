#!/usr/bin/env python3
"""Trigger a blue-green vmd generation handoff.

Sends `deploy <generation>` to the gateway's control socket — the gateway's
handoff controller runs the whole cutover (preflight the new generation, quiesce,
drain the old, activate, switch, stabilize) — then polls until the new
generation is live. The controller owns the sequence, so this trigger can drop
its connection at any point without abandoning a half-finished handoff.
"""
import argparse
import socket
import sys
import time


def send(sock_path: str, cmd: str, timeout: float = 5.0) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(sock_path)
        s.sendall((cmd + "\n").encode())
        return s.recv(4096).decode().strip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("generation", help="next generation id (e.g. b)")
    ap.add_argument("--control-sock", default="/run/vmd/gateway-control.sock")
    ap.add_argument("--timeout", type=int, default=180, help="seconds to await completion")
    args = ap.parse_args()

    resp = send(args.control_sock, "deploy " + args.generation)
    print(resp)
    if not resp.startswith("OK"):
        return 1

    want = "OK current=" + args.generation
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        cur = send(args.control_sock, "current")
        if cur == want:
            print("handoff complete: " + cur)
            return 0
        time.sleep(2)

    print("timeout waiting for handoff to complete", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
