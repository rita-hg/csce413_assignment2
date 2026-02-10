#!/usr/bin/env python3
"""Starter template for the port knocking server."""

import argparse
import logging
import select
import socket
import subprocess
import time

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 10.0

# How long to keep the port open for a successful knocker (seconds)
DEFAULT_OPEN_SECONDS = 20.0


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )


def _iptables(args):
    """Run iptables and return True if success."""
    p = subprocess.run(
        ["iptables"] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if p.returncode != 0:
        msg = (p.stderr or p.stdout or "").strip()
        logging.warning("iptables %s failed: %s", " ".join(args), msg)
        return False
    return True


def open_protected_port(protected_port):
    """Open the protected port using firewall rules."""
    # Design: protect via INPUT chain.
    # - Ensure a baseline DROP exists for protected_port.
    # - On successful knock, insert an ACCEPT rule at the top for the specific src IP.
    # The current knocker IP is passed via a module-global set by listen_for_knocks().
    global _CURRENT_SRC_IP  # set when sequence completes
    src_ip = _CURRENT_SRC_IP

    if not src_ip:
        logging.warning("No source IP set; cannot open port.")
        return

    # Ensure DROP exists (best effort)
    _iptables(["-C", "INPUT", "-p", "tcp", "--dport", str(protected_port), "-j", "DROP"]) or \
        _iptables(["-I", "INPUT", "1", "-p", "tcp", "--dport", str(protected_port), "-j", "DROP"])

    # Add per-IP ACCEPT rule (avoid duplicates)
    if not _iptables(["-C", "INPUT", "-p", "tcp", "--dport", str(protected_port), "-s", src_ip, "-j", "ACCEPT"]):
        if _iptables(["-I", "INPUT", "1", "-p", "tcp", "--dport", str(protected_port), "-s", src_ip, "-j", "ACCEPT"]):
            logging.info("Opened firewall for %s -> tcp/%s", src_ip, protected_port)


def close_protected_port(protected_port):
    """Close the protected port using firewall rules."""
    # Remove the per-IP ACCEPT rule(s) for the most recent knocker IP (best effort).
    global _CURRENT_SRC_IP
    src_ip = _CURRENT_SRC_IP
    if not src_ip:
        logging.warning("No source IP set; cannot close port.")
        return

    # Remove all matching ACCEPT rules (repeat until it fails)
    while _iptables(["-D", "INPUT", "-p", "tcp", "--dport", str(protected_port), "-s", src_ip, "-j", "ACCEPT"]):
        pass

    logging.info("Closed firewall for %s -> tcp/%s", src_ip, protected_port)


def listen_for_knocks(sequence, window_seconds, protected_port):
    """Listen for knock sequence and open the protected port."""
    logger = logging.getLogger("KnockServer")
    logger.info("Listening for knocks: %s", sequence)
    logger.info("Protected port: %s", protected_port)
    
    # Default: block the protected port (so "before knocking" fails)
    # Check if DROP rule exists; if not, insert at top of INPUT.
    rule_check = [
        "iptables", "-C", "INPUT",
        "-p", "tcp", "--dport", str(protected_port),
        "-j", "DROP",
    ]
    rule_insert = [
        "iptables", "-I", "INPUT", "1",
        "-p", "tcp", "--dport", str(protected_port),
        "-j", "DROP",
    ]
    try:
        rc = subprocess.run(rule_check, check=False).returncode
        if rc != 0:
            subprocess.run(rule_insert, check=False)
            logger.info("Inserted default DROP for tcp/%s", protected_port)
        else:
            logger.info("Default DROP for tcp/%s already present", protected_port)
    except Exception as e:
        logger.warning("Failed to ensure default DROP rule: %s", e)


    # UDP listeners for each knock port (simple + works well in containers)
    sockets = []
    port_by_sock = {}
    for p in sequence:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", p))
        sockets.append(s)
        port_by_sock[s] = p

    # Track state per source IP: index into sequence + start time
    progress = {}  # ip -> {"idx": int, "start": float, "last": float}

    global _CURRENT_SRC_IP
    _CURRENT_SRC_IP = None

    OPEN_SECONDS = DEFAULT_OPEN_SECONDS

    def reset(ip):
        progress.pop(ip, None)

    while True:
        readable, _, _ = select.select(sockets, [], [], 1.0)
        now = time.time()

        # Cleanup stale states
        # Cleanup stale states (skip internal scheduler key)
        stale = []
        for ip, st in progress.items():
            if ip == "_close_task":
                continue
            if (now - st["last"]) > window_seconds:
                stale.append(ip)

        for ip in stale:
            reset(ip)


        for s in readable:
            port = port_by_sock[s]
            try:
                _data, (src_ip, _src_port) = s.recvfrom(512)
            except OSError:
                continue

            st = progress.get(src_ip)
            if st is None:
                st = {"idx": 0, "start": now, "last": now}
                progress[src_ip] = st
            else:
                st["last"] = now

            # Enforce timing window
            if (now - st["start"]) > window_seconds:
                logger.info("[%s] Sequence timed out; reset", src_ip)
                reset(src_ip)
                continue

            expected = sequence[st["idx"]]

            if port == expected:
                st["idx"] += 1
                logger.info("[%s] Knock %d/%d OK (port %s)", src_ip, st["idx"], len(sequence), port)

                if st["idx"] == len(sequence):
                    logger.info("[%s] Correct sequence! Opening protected port.", src_ip)
                    _CURRENT_SRC_IP = src_ip
                    open_protected_port(protected_port)

                    # Optional: auto-close after OPEN_SECONDS
                    if OPEN_SECONDS > 0:
                        # store IP locally so if _CURRENT_SRC_IP changes later, we still close correct one
                        ip_to_close = src_ip
                        time_to_close = now + OPEN_SECONDS
                        # simple non-threaded close scheduler (checks each loop)
                        progress["_close_task"] = {"ip": ip_to_close, "at": time_to_close}

                    reset(src_ip)

            else:
                logger.info("[%s] Wrong knock on port %s (expected %s); reset", src_ip, port, expected)
                reset(src_ip)

        # Handle scheduled close (if any)
        task = progress.get("_close_task")
        if task and time.time() >= task["at"]:
            _CURRENT_SRC_IP = task["ip"]
            close_protected_port(protected_port)
            progress.pop("_close_task", None)


def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking server starter")
    parser.add_argument(
        "--sequence",
        default=",".join(str(port) for port in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports",
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PROTECTED_PORT,
        help="Protected service port",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=DEFAULT_SEQUENCE_WINDOW,
        help="Seconds allowed to complete the sequence",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging()

    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    listen_for_knocks(sequence, args.window, args.protected_port)


if __name__ == "__main__":
    main()
