#!/usr/bin/env python3

import csv
import os
import signal
import socket
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime


CSV_FILE = "network_services.csv"
INTERFACE = "any"
REFRESH = 1.0


# ---------------------------------------------------------
# Terminal
# ---------------------------------------------------------

def clear():
    print("\033[2J\033[H", end="")


def hide_cursor():
    print("\033[?25l", end="")


def show_cursor():
    print("\033[?25h", end="")


# ---------------------------------------------------------
# Local IPs
# ---------------------------------------------------------

def get_local_ips():
    try:
        output = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show"],
            text=True
        )

        ips = set()

        for line in output.splitlines():
            parts = line.split()

            if len(parts) >= 4:
                ip = parts[3].split("/")[0]
                ips.add(ip)

        return ips

    except Exception:
        return set()


# ---------------------------------------------------------
# Service lookup
# ---------------------------------------------------------

_service_cache = {}


def get_service(port, proto):

    key = (port, proto)

    if key in _service_cache:
        return _service_cache[key]

    try:
        service = socket.getservbyport(
            int(port),
            proto.lower()
        )
    except Exception:
        service = "-"

    _service_cache[key] = service

    return service


# ---------------------------------------------------------
# Statistics
# ---------------------------------------------------------

flows = defaultdict(lambda: {
    "packets": 0,
    "bytes": 0,
    "first": time.time(),
    "last": time.time()
})


total_packets = 0
total_bytes = 0


# ---------------------------------------------------------
# CSV
# ---------------------------------------------------------

csv_file = None
csv_writer = None


def init_csv():

    global csv_file
    global csv_writer

    new_file = not os.path.exists(CSV_FILE)

    csv_file = open(
        CSV_FILE,
        "a",
        newline="",
        buffering=1
    )

    csv_writer = csv.writer(csv_file)

    if new_file:
        csv_writer.writerow([
            "timestamp",
            "direction",
            "protocol",
            "src_ip",
            "src_port",
            "src_service",
            "dst_ip",
            "dst_port",
            "dst_service",
            "packets",
            "bytes"
        ])

        csv_file.flush()


# ---------------------------------------------------------
# Packet parser
# ---------------------------------------------------------

def parse_packet(line, local_ips):

    """
    tcpdump -tt -n -i any output examples:

    IP 192.168.1.10.54321 > 142.250.185.14.443:
    IP 192.168.1.10.53532 > 192.168.1.1.53:
    """

    try:

        parts = line.split()

        if len(parts) < 5:
            return None

        # Find the IP protocol
        ip_index = None

        for i, p in enumerate(parts):
            if p in ("IP", "IP6"):
                ip_index = i
                break

        if ip_index is None:
            return None

        protocol = None

        if "Flags" in line:
            protocol = "TCP"

        elif "UDP" in line:
            protocol = "UDP"

        elif "ICMP" in line:
            protocol = "ICMP"

        else:
            return None

        srcdst = parts[ip_index + 1]

        if ">" not in line:
            return None

        # Find >
        arrow_index = parts.index(">")

        src = parts[arrow_index - 1]
        dst = parts[arrow_index + 1]

        src = src.rstrip(":")
        dst = dst.rstrip(":")

        # IPv4 address + port
        def split_endpoint(endpoint):

            # IPv4
            pos = endpoint.rfind(".")

            if pos == -1:
                return endpoint, "-"

            ip = endpoint[:pos]
            port = endpoint[pos + 1:]

            return ip, port

        src_ip, src_port = split_endpoint(src)
        dst_ip, dst_port = split_endpoint(dst)

        # Validate IPv4
        if src_ip.count(".") != 3:
            return None

        if dst_ip.count(".") != 3:
            return None

        # Direction
        if dst_ip in local_ips:
            direction = "IN"

        elif src_ip in local_ips:
            direction = "OUT"

        else:
            return None

        # Packet size
        size = 0

        if "length" in parts:
            try:
                idx = parts.index("length")
                size = int(parts[idx + 1])
            except Exception:
                pass

        if size == 0:
            # fallback: try tcpdump captured length
            for p in parts:
                if p.startswith("length"):
                    try:
                        size = int(p.split()[1])
                    except Exception:
                        pass

        return {
            "direction": direction,
            "protocol": protocol,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "bytes": size
        }

    except Exception:
        return None


# ---------------------------------------------------------
# tcpdump
# ---------------------------------------------------------

def start_tcpdump():

    return subprocess.Popen(
        [
            "tcpdump",
            "-i", INTERFACE,
            "-n",
            "-l",
            "-tt",
            "-q"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )


# ---------------------------------------------------------
# Dashboard
# ---------------------------------------------------------

def render(local_ips):

    clear()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(
        f"\033[1;36m"
        f"NETTOP"
        f"\033[0m"
        f"   {now}"
    )

    print(
        f"Interface: {INTERFACE}    "
        f"Packets: {total_packets:,}    "
        f"Bytes: {total_bytes:,}"
    )

    print(
        "\n"
        "Direction Protocol "
        "Source                 Destination            "
        "Service             Packets       Bytes"
    )

    print("-" * 110)

    # Sort by traffic
    items = sorted(
        flows.items(),
        key=lambda x: x[1]["bytes"],
        reverse=True
    )

    for key, stats in items[:30]:

        (
            direction,
            protocol,
            src_ip,
            src_port,
            dst_ip,
            dst_port
        ) = key

        if direction == "IN":
            service = get_service(
                dst_port,
                protocol
            )

        else:
            service = get_service(
                src_port,
                protocol
            )

        src = f"{src_ip}:{src_port}"
        dst = f"{dst_ip}:{dst_port}"

        print(
            f"{direction:<9}"
            f"{protocol:<9}"
            f"{src:<23}"
            f"{dst:<23}"
            f"{service:<18}"
            f"{stats['packets']:>8}"
            f"{stats['bytes']:>12}"
        )

    print()
    print(
        """\033[90m"
        "q: quit    r: reset counters    "
        "CSV: " + CSV_FILE
        "\033[0m"""
    )


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

running = True


def stop(signum=None, frame=None):

    global running

    running = False


signal.signal(signal.SIGINT, stop)
signal.signal(signal.SIGTERM, stop)


def main():

    global total_packets
    global total_bytes
    global flows

    hide_cursor()

    init_csv()

    local_ips = get_local_ips()

    print("Local IPs:", ", ".join(local_ips))
    print("Starting tcpdump...")

    process = start_tcpdump()

    try:

        last_refresh = 0

        while running:

            # Read packets without blocking indefinitely
            line = process.stdout.readline()

            if line:

                packet = parse_packet(
                    line.strip(),
                    local_ips
                )

                if packet:

                    total_packets += 1
                    total_bytes += packet["bytes"]

                    key = (
                        packet["direction"],
                        packet["protocol"],
                        packet["src_ip"],
                        packet["src_port"],
                        packet["dst_ip"],
                        packet["dst_port"]
                    )

                    flows[key]["packets"] += 1
                    flows[key]["bytes"] += packet["bytes"]
                    flows[key]["last"] = time.time()

                    # CSV
                    src_service = get_service(
                        packet["src_port"],
                        packet["protocol"]
                    )

                    dst_service = get_service(
                        packet["dst_port"],
                        packet["protocol"]
                    )

                    csv_writer.writerow([
                        datetime.now().isoformat(),
                        packet["direction"],
                        packet["protocol"],
                        packet["src_ip"],
                        packet["src_port"],
                        src_service,
                        packet["dst_ip"],
                        packet["dst_port"],
                        dst_service,
                        1,
                        packet["bytes"]
                    ])

                    csv_file.flush()

            now = time.time()

            if now - last_refresh >= REFRESH:

                render(local_ips)

                last_refresh = now

    finally:

        stop()

        if process:
            process.terminate()

            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()

        if csv_file:
            csv_file.flush()
            csv_file.close()

        show_cursor()

        print("\nStopped.")


if __name__ == "__main__":
    main()
