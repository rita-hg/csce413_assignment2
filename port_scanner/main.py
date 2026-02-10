# #!/usr/bin/env python3
# """
# Port Scanner - Starter Template for Students
# Assignment 2: Network Security

# This is a STARTER TEMPLATE to help you get started.
# You should expand and improve upon this basic implementation.

# TODO for students:
# 1. Implement multi-threading for faster scans
# 2. Add banner grabbing to detect services
# 3. Add support for CIDR notation (e.g., 192.168.1.0/24)
# 4. Add different scan types (SYN scan, UDP scan, etc.)
# 5. Add output formatting (JSON, CSV, etc.)
# 6. Implement timeout and error handling
# 7. Add progress indicators
# 8. Add service fingerprinting
# """


# import argparse
# import ipaddress
# import socket
# import time
# from concurrent.futures import ThreadPoolExecutor, as_completed


# def parse_ports(port_range: str) -> tuple[int, int]:
#     """
#     Parse ports like "1-1024" into (1, 1024).
#     """
#     if "-" not in port_range:
#         raise ValueError("Port range must be in the form start-end (e.g., 1-1024).")

#     a, b = port_range.split("-", 1)
#     start = int(a.strip())
#     end = int(b.strip())

#     if not (1 <= start <= 65535 and 1 <= end <= 65535):
#         raise ValueError("Ports must be between 1 and 65535.")
#     if start > end:
#         raise ValueError("Start port must be <= end port.")

#     return start, end


# def resolve_targets(target: str) -> list[str]:
#     """
#     Support:
#     - Single IP (e.g., 172.20.0.10)
#     - Hostname (e.g., example.com)
#     - CIDR (e.g., 172.20.0.0/24)
#     """
#     # CIDR or IP?
#     try:
#         net = ipaddress.ip_network(target, strict=False)
#         # If it's a single IP (/32), hosts() is empty; handle that
#         if net.num_addresses == 1:
#             return [str(net.network_address)]
#         return [str(ip) for ip in net.hosts()]
#     except ValueError:
#         # Hostname -> resolve to one IP (simple + predictable)
#         try:
#             ip = socket.gethostbyname(target)
#             return [ip]
#         except socket.gaierror as e:
#             raise ValueError(f"Invalid target '{target}': {e}") from e


# def grab_banner(sock: socket.socket, timeout: float, max_bytes: int = 1024) -> str:
#     """
#     Best-effort banner grabbing. Many services won't send data unless you send first.
#     We keep it simple and safe.
#     """
#     try:
#         sock.settimeout(timeout)
#         data = sock.recv(max_bytes)
#         if not data:
#             return ""
#         return data.decode(errors="ignore").strip()
#     except (socket.timeout, OSError):
#         return ""


# def detect_service(port: int) -> str:
#     """
#     Best-effort service name using the OS services database.
#     No hard-coded service list.
#     """
#     try:
#         return socket.getservbyport(port, "tcp")
#     except OSError:
#         return ""


# def scan_port(target: str, port: int, timeout: float = 1.0, do_banner: bool = False) -> dict:
#     s = None
#     start = time.perf_counter()
#     try:
#         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         s.settimeout(timeout)

#         code = s.connect_ex((target, port))
#         elapsed_ms = (time.perf_counter() - start) * 1000.0

#         if code == 0:
#             service = detect_service(port)
#             banner = grab_banner(s, timeout=timeout) if do_banner else ""
#             return {
#                 "port": port,
#                 "state": "open",
#                 "time_ms": elapsed_ms,
#                 "service": service,
#                 "banner": banner,
#             }

#         return {"port": port, "state": "closed", "time_ms": elapsed_ms, "service": "", "banner": ""}

#     except (socket.timeout, ConnectionRefusedError, OSError):
#         elapsed_ms = (time.perf_counter() - start) * 1000.0
#         return {"port": port, "state": "closed", "time_ms": elapsed_ms, "service": "", "banner": ""}

#     finally:
#         if s is not None:
#             try:
#                 s.close()
#             except OSError:
#                 pass


# def scan_range(target: str, start_port: int, end_port: int, timeout: float, threads: int, do_banner: bool) -> list[dict]:
#     ports = list(range(start_port, end_port + 1))
#     results: list[dict] = []

#     print(f"[*] Scanning {target} from port {start_port} to {end_port}")

#     with ThreadPoolExecutor(max_workers=threads) as executor:
#         futures = [executor.submit(scan_port, target, p, timeout, do_banner) for p in ports]

#         done = 0
#         total = len(ports)
#         last_print = 0.0

#         for fut in as_completed(futures):
#             results.append(fut.result())

#             # lightweight progress
#             done += 1
#             now = time.time()
#             if now - last_print >= 0.5 or done == total:
#                 pct = (done / total) * 100.0
#                 print(f"\r[*] Progress: {done}/{total} ({pct:.1f}%)", end="", flush=True)
#                 last_print = now

#     print()
#     results.sort(key=lambda r: r["port"])
#     return results


# def main():
#     parser = argparse.ArgumentParser(description="TCP Port Scanner (authorized use only).")

#     # REQUIRED arguments (exactly what you want)
#     parser.add_argument("--target", required=True,
#                         help="Target hostname/IP or CIDR (e.g., 172.20.0.10 or 172.20.0.0/24)")
#     parser.add_argument("--ports", required=True,
#                         help="Port range start-end (e.g., 1-1024 or 1-10000)")

#     # OPTIONAL arguments (have safe defaults)
#     parser.add_argument("--timeout", type=float, default=0.3,
#                         help="Connection timeout in seconds (default: 0.3)")
#     parser.add_argument("--threads", type=int, default=600,
#                         help="Port-scan worker threads per host (default: 600)")
#     parser.add_argument("--host-threads", type=int, default=24,
#                         help="Concurrent hosts to scan (default: 50)")
#     parser.add_argument("--banner", action="store_true",
#                         help="Enable banner grabbing (slower)")
#     parser.add_argument("--only-open", action="store_true",
#                         help="Only print open ports (default behavior)")

#     args = parser.parse_args()

#     # Parse and validate port range
#     try:
#         start_port, end_port = parse_ports(args.ports)
#     except ValueError as e:
#         print(f"[!] Invalid port range: {e}")
#         raise SystemExit(1)

#     # Validate timeout / thread counts
#     if args.timeout <= 0:
#         print("[!] Timeout must be > 0")
#         raise SystemExit(1)
#     if args.threads < 1 or args.host_threads < 1:
#         print("[!] Threads must be >= 1")
#         raise SystemExit(1)

#     # Resolve targets (CIDR / hostname / IP)
#     try:
#         targets = resolve_targets(args.target)
#     except ValueError as e:
#         print(f"[!] {e}")
#         raise SystemExit(1)

#     def scan_one_host(ip: str):
#         host_start = time.perf_counter()
#         res = scan_range(ip, start_port, end_port, args.timeout, args.threads, args.banner)
#         host_elapsed = time.perf_counter() - host_start
#         return ip, res, host_elapsed

#     overall_start = time.perf_counter()

#     # Scan hosts concurrently (huge speedup for CIDR)
#     with ThreadPoolExecutor(max_workers=args.host_threads) as host_pool:
#         futures = [host_pool.submit(scan_one_host, ip) for ip in targets]

#         for fut in as_completed(futures):
#             ip, results, host_elapsed = fut.result()

#             open_count = sum(1 for r in results if r["state"] == "open")
#             closed_count = len(results) - open_count

#             print(f"\n[+] Results for {ip} (scan time: {host_elapsed:.3f}s)")
#         for r in results:
#             if r["state"] != "open":
#                 continue

#             line = f"    {r['port']}/tcp  open  ({r['time_ms']:.2f} ms)"
#             if r["service"]:
#                 line += f"  service={r['service']}"
#             if r["banner"]:
#                 b = r["banner"].replace("\r", " ").replace("\n", " ")
#                 if len(b) > 120:
#                     b = b[:120] + "..."
#                 line += f"  banner='{b}'"
#             print(line)


#             print(f"[+] Open: {open_count} | Closed: {closed_count}")

#     overall_elapsed = time.perf_counter() - overall_start
#     print(f"\n[+] Scan complete (total time: {overall_elapsed:.3f}s)")


import argparse
import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


# Your known answers (banner-only mode)
KNOWN_TARGETS = {
    "172.20.0.20": 2222,
    "172.20.0.11": 3306,
    "172.20.0.10": 5000,
    "172.20.0.1":  5001,
    "172.20.0.22": 6379,
    "172.20.0.21": 8888,
}


def parse_ports(port_range: str) -> tuple[int, int]:
    """Parse ports like '1-1024' into (1, 1024)."""
    if "-" not in port_range:
        raise ValueError("Port range must be in the form start-end (e.g., 1-1024).")

    a, b = port_range.split("-", 1)
    start = int(a.strip())
    end = int(b.strip())

    if not (1 <= start <= 65535 and 1 <= end <= 65535):
        raise ValueError("Ports must be between 1 and 65535.")
    if start > end:
        raise ValueError("Start port must be <= end port.")

    return start, end


def resolve_targets(target: str) -> list[str]:
    """
    Support:
    - Single IP (e.g., 172.20.0.10)
    - Hostname (e.g., example.com)
    - CIDR (e.g., 172.20.0.0/24)
    """
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses == 1:
            return [str(net.network_address)]
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        try:
            ip = socket.gethostbyname(target)
            return [ip]
        except socket.gaierror as e:
            raise ValueError(f"Invalid target '{target}': {e}") from e


def detect_service(port: int) -> str:
    """Best-effort service name using OS services database (no hard-coded list)."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def grab_banner(sock: socket.socket, timeout: float, max_bytes: int = 4096) -> str:
    """
    Best-effort banner grabbing.
    Reads whatever is immediately available, up to max_bytes, until timeout/no more data.
    """
    try:
        sock.settimeout(timeout)
        chunks = []
        total = 0

        while total < max_bytes:
            try:
                data = sock.recv(min(1024, max_bytes - total))
            except socket.timeout:
                break
            if not data:
                break

            chunks.append(data)
            total += len(data)

            # If we got a full HTTP header block, we can stop early
            if b"\r\n\r\n" in data:
                break

        if not chunks:
            return ""

        return b"".join(chunks).decode(errors="ignore").strip()

    except OSError:
        return ""



def scan_port(target: str, port: int, timeout: float = 1.0, do_banner: bool = True) -> dict:
    """
    TCP connect scan for one port.
    Returns a dict with port/state/timing plus service/banner if open.
    """
    s = None
    start = time.perf_counter()

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)

        code = s.connect_ex((target, port))
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        if code == 0:
            service = detect_service(port)
            banner = grab_banner(s, timeout=timeout) if do_banner else ""
            return {
                "port": port,
                "state": "open",
                "time_ms": elapsed_ms,
                "service": service,
                "banner": banner,
            }

        return {"port": port, "state": "closed", "time_ms": elapsed_ms, "service": "", "banner": ""}

    except (socket.timeout, ConnectionRefusedError, OSError):
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return {"port": port, "state": "closed", "time_ms": elapsed_ms, "service": "", "banner": ""}

    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


def scan_range(target: str, start_port: int, end_port: int, timeout: float, threads: int, do_banner: bool) -> list[dict]:
    """Scan a port range on one target using threads."""
    ports = list(range(start_port, end_port + 1))
    results: list[dict] = []

    print(f"[*] Scanning {target} from port {start_port} to {end_port}")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan_port, target, p, timeout, do_banner) for p in ports]

        done = 0
        total = len(ports)
        last_print = 0.0

        for fut in as_completed(futures):
            results.append(fut.result())

            # light progress update
            done += 1
            now = time.time()
            if now - last_print >= 0.5 or done == total:
                pct = (done / total) * 100.0
                print(f"\r[*] Progress: {done}/{total} ({pct:.1f}%)", end="", flush=True)
                last_print = now

    print()
    results.sort(key=lambda r: r["port"])
    return results


def probe_banner(ip: str, port: int, timeout: float) -> None:
    """Connect once to a known host:port and print service + banner."""
    s = None
    start = time.perf_counter()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        service = detect_service(port)

        # Nudge HTTP-like services to respond with headers
        if port in (8888, 5000, 5001):
            try:
                s.sendall(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
            except OSError:
                pass

        # Nudge Redis to respond
        if port == 6379:
            try:
                s.sendall(b"PING\r\n")
            except OSError:
                pass

        time.sleep(0.05)

        banner = grab_banner(s, timeout=timeout)


        print(f"[+] {ip}:{port} open ({elapsed_ms:.2f} ms)")
        print(f"    service: {service}")
        print(f"    banner: {banner if banner else '<no banner returned>'}")

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        print(f"[-] {ip}:{port} failed ({elapsed_ms:.2f} ms) : {e}")

    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


def main():
    parser = argparse.ArgumentParser(description="TCP Port Scanner (authorized use only).")

    # Banner-only mode for your known answers (no scanning)
    parser.add_argument("--banners", action="store_true",
                        help="Only collect banners for known IP:port pairs (no scanning).")

    # Scanner mode args (required unless --banners is used)
    parser.add_argument("--target", help="Target hostname/IP or CIDR (e.g., 172.20.0.10 or 172.20.0.0/24)")
    parser.add_argument("--ports", help="Port range start-end (e.g., 1-1024 or 1-10000)")

    # Defaults chosen to be reasonably fast without melting machines
    parser.add_argument("--timeout", type=float, default=0.3, help="Connection timeout seconds (default: 0.3)")
    parser.add_argument("--threads", type=int, default=600, help="Worker threads per host (default: 600)")
    parser.add_argument("--host-threads", type=int, default=24, help="Concurrent hosts (default: 24)")
    parser.add_argument("--banner", action="store_true", help="Enable banner grabbing during scans (slower)")
    parser.add_argument("--only-open", action="store_true", help="Only print open ports (recommended)")

    args = parser.parse_args()

    if args.timeout <= 0:
        print("[!] Timeout must be > 0")
        raise SystemExit(1)
    if args.threads < 1 or args.host_threads < 1:
        print("[!] Threads must be >= 1")
        raise SystemExit(1)

    # Banner-only mode (what you asked for)
    if args.banners:
        print("[*] Collecting banners for known services\n")
        for ip, port in KNOWN_TARGETS.items():
            probe_banner(ip, port, args.timeout)
        return

    # Scanner mode requires --target and --ports
    if not args.target or not args.ports:
        print("[!] Scanner mode requires --target and --ports (or use --banners).")
        raise SystemExit(1)

    try:
        start_port, end_port = parse_ports(args.ports)
    except ValueError as e:
        print(f"[!] Invalid port range: {e}")
        raise SystemExit(1)

    try:
        targets = resolve_targets(args.target)
    except ValueError as e:
        print(f"[!] {e}")
        raise SystemExit(1)

    def scan_one_host(ip: str):
        host_start = time.perf_counter()
        res = scan_range(ip, start_port, end_port, args.timeout, args.threads, args.banner)
        host_elapsed = time.perf_counter() - host_start
        return ip, res, host_elapsed

    overall_start = time.perf_counter()

    with ThreadPoolExecutor(max_workers=args.host_threads) as host_pool:
        futures = [host_pool.submit(scan_one_host, ip) for ip in targets]

        for fut in as_completed(futures):
            ip, results, host_elapsed = fut.result()

            open_results = [r for r in results if r["state"] == "open"]
            open_count = len(open_results)
            closed_count = len(results) - open_count

            print(f"\n[+] Results for {ip} (scan time: {host_elapsed:.3f}s)")
            if open_count == 0:
                print("    (no open ports found)")
            else:
                for r in open_results:
                    line = f"    {r['port']}/tcp open ({r['time_ms']:.2f} ms)"
                    if r["service"]:
                        line += f" service={r['service']}"
                    if r["banner"]:
                        b = r["banner"].replace("\r", " ").replace("\n", " ")
                        if len(b) > 120:
                            b = b[:120] + "..."
                        line += f" banner='{b}'"
                    print(line)

            print(f"[+] Open: {open_count} | Closed: {closed_count}")

    overall_elapsed = time.perf_counter() - overall_start
    print(f"\n[+] Scan complete (total time: {overall_elapsed:.3f}s)")


if __name__ == "__main__":
    main()
