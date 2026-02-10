#!/usr/bin/env python3
from __future__ import annotations

"""Starter template for the honeypot assignment.
Features:
- Looks like OpenSSH (which is the banner)
- Logs: src ip/port, duration, auth attempts, commands/data
- Minimal interactive shell with believable output
"""

import os
import socket
import threading
import time
import paramiko
import traceback
from dataclasses import dataclass
from typing import Optional
from logger import create_logger, alert_if_interesting

HOST = "0.0.0.0"
PORT = int(os.getenv("HONEYPOT_PORT", "22"))

KEY_DIR = "/app/keys"
HOSTKEY_PATH = os.path.join(KEY_DIR, "ssh_host_rsa_key")

# “Looks real” banner
paramiko.Transport._preferred_kex = (
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group14-sha256",
)
BANNER = os.getenv("SSH_BANNER", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.5")

# Common credentials that will "work" (to allow post-auth command capture)
ACCEPTED_CREDS = {
    ("root", "toor"),
    ("admin", "admin"),
    ("ubuntu", "ubuntu"),
    ("test", "test"),
}

# Slight delays help feel a bit more realistic
FAIL_DELAY_SEC = float(os.getenv("FAIL_DELAY_SEC", "0.7"))
AUTH_MAX_TRIES = int(os.getenv("AUTH_MAX_TRIES", "6"))

logger, jsonl = create_logger("ssh-honeypot")


@dataclass
class ConnInfo:
    conn_id: str
    src_ip: str
    src_port: int
    start_ts: float


def ensure_host_key() -> paramiko.RSAKey:
    os.makedirs(KEY_DIR, exist_ok=True)
    if not os.path.exists(HOSTKEY_PATH):
        logger.info("Generating RSA host key at %s", HOSTKEY_PATH)
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(HOSTKEY_PATH)
    return paramiko.RSAKey(filename=HOSTKEY_PATH)


class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, conn: ConnInfo):
        self.conn = conn
        self.event = threading.Event()
        self.auth_tries = 0
        self.username: Optional[str] = None
        self.authed = False

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_auth_password(self, username: str, password: str) -> int:
        self.auth_tries += 1
        self.username = username

        jsonl.write({
            "event_type": "auth_attempt",
            "conn_id": self.conn.conn_id,
            "src_ip": self.conn.src_ip,
            "src_port": self.conn.src_port,
            "username": username,
            "password": password,
            "try": self.auth_tries,
        })

        # Delay to mimic real server behavior
        time.sleep(FAIL_DELAY_SEC)

        if (username, password) in ACCEPTED_CREDS:
            self.authed = True
            ev = {
                "event_type": "auth_success",
                "conn_id": self.conn.conn_id,
                "src_ip": self.conn.src_ip,
                "src_port": self.conn.src_port,
                "username": username,
            }
            jsonl.write(ev)
            alert_if_interesting(logger, ev)
            return paramiko.AUTH_SUCCESSFUL

        # After too many tries, start rejecting more harshly
        # This is to reflect what servers may react
        if self.auth_tries >= AUTH_MAX_TRIES:
            return paramiko.AUTH_FAILED

        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        # Typical SSH clients request "session"
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel) -> bool:
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes) -> bool:
        # Allow PTY for realism
        return True

    def check_channel_exec_request(self, channel, command: bytes) -> bool:
        # If attacker uses: ssh user@host "command"
        cmd = command.decode(errors="ignore")
        ev = {
            "event_type": "command",
            "conn_id": self.conn.conn_id,
            "src_ip": self.conn.src_ip,
            "src_port": self.conn.src_port,
            "username": self.username,
            "command": cmd,
            "mode": "exec",
        }
        jsonl.write(ev)
        alert_if_interesting(logger, ev)

        # Return something plausible
        out = fake_command_output(cmd, self.username or "user")
        channel.send(out)
        channel.send_exit_status(0)
        return True


def fake_motd(username: str) -> str:
    # Minimal but believable Ubuntu-ish login text
    return (
        "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
        "\r\n"
        " * Documentation:  https://help.ubuntu.com\r\n"
        " * Management:     https://landscape.canonical.com\r\n"
        " * Support:        https://ubuntu.com/advantage\r\n"
        "\r\n"
        "System information as of " + time.strftime("%a %b %d %H:%M:%S %Z %Y") + "\r\n"
        "\r\n"
    )


def prompt(username: str) -> str:
    return f"{username}@webserver:~$ "


def fake_command_output(cmd: str, username: str) -> str:
    c = cmd.strip()

    if c in {"", "\n"}:
        return ""

    if c == "whoami":
        return f"{username}\r\n"

    if c in {"pwd"}:
        return f"/home/{username}\r\n"

    if c.startswith("cd "):
        # Pretend to accept but we won't actually maintain directories deeply
        return ""

    if c in {"ls", "ls -la", "ls -l"}:
        return (
            "total 16\r\n"
            "drwxr-xr-x 2 " + username + " " + username + " 4096 Feb  9 10:12 .\r\n"
            "drwxr-xr-x 3 root root 4096 Jan 12 08:01 ..\r\n"
            "-rw-r--r-- 1 " + username + " " + username + "  220 Jan 12 08:01 .bash_logout\r\n"
            "-rw-r--r-- 1 " + username + " " + username + " 3771 Jan 12 08:01 .bashrc\r\n"
            "-rw-r--r-- 1 " + username + " " + username + "  807 Jan 12 08:01 .profile\r\n"
        )

    if c in {"uname", "uname -a"}:
        return "Linux webserver 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n"

    if c.startswith("cat /etc/passwd"):
        # Sanitized but realistic-looking excerpt
        return (
            "root:x:0:0:root:/root:/bin/bash\r\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
            "syslog:x:102:106::/home/syslog:/usr/sbin/nologin\r\n"
            f"{username}:x:1000:1000::{'/home/' + username}:/bin/bash\r\n"
        )

    if c.startswith("id"):
        return f"uid=1000({username}) gid=1000({username}) groups=1000({username}),27(sudo)\r\n"

    if c in {"exit", "logout"}:
        return "__EXIT__"

    # Default: common shell error
    return f"bash: {c.split()[0]}: command not found\r\n"


def handle_shell(chan: paramiko.Channel, conn: ConnInfo, username: str) -> None:
    # Login banner + prompt
    chan.send(fake_motd(username))
    chan.send(prompt(username))

    buffer = ""
    while True:
        data = chan.recv(1024)
        if not data:
            break

        text = data.decode(errors="ignore")
        buffer += text

        # Log raw keystrokes/data too (useful for paste attacks / weird clients)
        jsonl.write({
            "event_type": "client_data",
            "conn_id": conn.conn_id,
            "src_ip": conn.src_ip,
            "src_port": conn.src_port,
            "username": username,
            "data": text,
        })

        # Process lines
        while "\n" in buffer or "\r" in buffer:
            # Normalize line ending handling
            line = buffer.replace("\r\n", "\n").replace("\r", "\n")
            parts = line.split("\n")
            cmd = parts[0]
            buffer = "\n".join(parts[1:])

            cmd = cmd.strip()
            if cmd:
                ev = {
                    "event_type": "command",
                    "conn_id": conn.conn_id,
                    "src_ip": conn.src_ip,
                    "src_port": conn.src_port,
                    "username": username,
                    "command": cmd,
                    "mode": "shell",
                }
                jsonl.write(ev)
                alert_if_interesting(logger, ev)

            out = fake_command_output(cmd, username)
            if out == "__EXIT__":
                chan.send("\r\nlogout\r\n")
                return

            if out:
                chan.send(out)

            chan.send(prompt(username))


def handle_client(client: socket.socket, addr) -> None:
    src_ip, src_port = addr[0], addr[1]
    conn_id = f"{int(time.time()*1000)}-{src_ip}:{src_port}"
    start = time.time()

    conn = ConnInfo(conn_id=conn_id, src_ip=src_ip, src_port=src_port, start_ts=start)

    jsonl.write({
        "event_type": "connection_open",
        "conn_id": conn_id,
        "src_ip": src_ip,
        "src_port": src_port,
    })

    transport: Optional[paramiko.Transport] = None
    try:
        transport = paramiko.Transport(client)
        transport.local_version = BANNER

        host_key = ensure_host_key()
        transport.add_server_key(host_key)

        server = HoneypotServer(conn)
        transport.start_server(server=server)

        chan = transport.accept(20)
        if chan is None:
            return

        # If shell requested, wait briefly
        server.event.wait(10)

        if server.authed:
            ev = {
                "event_type": "session_open",
                "conn_id": conn_id,
                "src_ip": src_ip,
                "src_port": src_port,
                "username": server.username,
            }
            jsonl.write(ev)
            alert_if_interesting(logger, ev)

            handle_shell(chan, conn, server.username or "user")
        else:
            # If they never successfully auth but got here, just close
            time.sleep(0.2)

    except EOFError:
        # Very common: scanners or clients connect then close before SSH handshake finishes
        logger.info("Client %s:%s disconnected during handshake (EOF).", src_ip, src_port)
        jsonl.write({
            "event_type": "handshake_eof",
            "conn_id": conn_id,
            "src_ip": src_ip,
            "src_port": src_port,
        })
    except Exception:
        logger.error("Exception in client handler:\n%s", traceback.format_exc())
        jsonl.write({
            "event_type": "error",
            "conn_id": conn_id,
            "src_ip": src_ip,
            "src_port": src_port,
            "error": "exception",
        })

    finally:
        duration = time.time() - start
        jsonl.write({
            "event_type": "connection_close",
            "conn_id": conn_id,
            "src_ip": src_ip,
            "src_port": src_port,
            "duration_seconds": round(duration, 3),
        })

        try:
            if transport is not None:
                transport.close()
        except Exception:
            pass
        try:
            client.close()
        except Exception:
            pass


def run_honeypot() -> None:
    logger.info("Starting SSH honeypot on %s:%d", HOST, PORT)

    # Create listening socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(100)

    while True:
        client, addr = sock.accept()
        t = threading.Thread(target=handle_client, args=(client, addr), daemon=True)
        t.start()


if __name__ == "__main__":
    run_honeypot()