#!/usr/bin/env python3

import csv
import os
import re
import select
import signal
import socket
import subprocess
import sys
import termios
import time
import tty

from collections import defaultdict
from datetime import datetime


# ============================================================
# CONFIGURATION
# ============================================================

CSV_FILE = "network_services.csv"

INTERFACE = "any"

# Dashboard refresh
REFRESH_INTERVAL = 1.0

# CSV persistence
CSV_SAVE_INTERVAL = 10.0

# Remove flows that haven't received traffic for this period
FLOW_TIMEOUT = 3600

# Number of flows shown on screen
MAX_DISPLAY_FLOWS = 30


# ============================================================
# GLOBAL STATE
# ============================================================

running = True

flows = {}

total_packets = 0
total_bytes = 0

previous_total_packets = 0
previous_total_bytes = 0

rx_packets = 0
tx_packets = 0

rx_bytes = 0
tx_bytes = 0

previous_rx_bytes = 0
previous_tx_bytes = 0

previous_time = time.time()

tcpdump_process = None


# ============================================================
# TERMINAL
# ============================================================

def clear_screen():
    print("\033[2J\033[H", end="")


def hide_cursor():
    print("\033[?25l", end="")


def show_cursor():
    print("\033[?25h", end="")


def move_home():
    print("\033[H", end="")


def bold(text):
    return f"\033[1m{text}\033[0m"


def cyan(text):
    return f"\033[36m{text}\033[0m"


def green(text):
    return f"\033[32m{text}\033[0m"


def yellow(text):
    return f"\033[33m{text}\033[0m"


def red(text):
    return f"\033[31m{text}\033[0m"


def grey(text):
    return f"\033[90m{text}\033[0m"


# ============================================================
# LOCAL IP DETECTION
# ============================================================

def get_local_ips():

    try:

        output = subprocess.check_output(
            [
                "ip",
                "-4",
                "-o",
                "addr",
                "show",
            ],
            text=True,
            stderr=subprocess.DEVNULL,
        )

        ips = set()

        for line in output.splitlines():

            parts = line.split()

            if len(parts) >= 4:

                address = parts[3]

                ip = address.split("/")[0]

                ips.add(ip)

        return ips

    except Exception:

        return set()


# ============================================================
# SERVICE LOOKUP
# ============================================================

service_cache = {}


def get_service(port, protocol):

    if port in ("", "-", None):
        return "-"

    try:
        port = int(port)
    except Exception:
        return "-"

    key = (port, protocol)

    if key in service_cache:
        return service_cache[key]

    try:

        service = socket.getservbyport(
            port,
            protocol.lower()
        )

    except Exception:

        service = "-"

    service_cache[key] = service

    return service


# ============================================================
# PORT PROCESS LOOKUP
# ============================================================

def get_listening_services():

    services = {}

    try:

        output = subprocess.check_output(
            [
                "ss",
                "-lntup"
            ],
            text=True,
            stderr=subprocess.DEVNULL,
        )

        for line in output.splitlines():

            if line.startswith("Netid"):
                continue

            parts = line.split()

            if len(parts) < 5:
                continue

            protocol = parts[0]

            local = parts[4]

            process = ""

            if len(parts) >= 7:
                process = parts[-1]

            match = re.search(
                r":(\d+)$",
                local
            )

            if not match:
                continue

            port = match.group(1)

            services[(protocol.upper(), port)] = process

    except Exception:
        pass

    return services


# ============================================================
# FLOW KEY
# ============================================================

def make_flow_key(packet):

    """
    Aggregate connections by:

        direction
        protocol
        local_port
        remote_ip
        remote_port

    This intentionally ignores the ephemeral local source port.

    Example:

        host:50001 -> 1.2.3.4:443
        host:50002 -> 1.2.3.4:443
        host:50003 -> 1.2.3.4:443

    becomes ONE flow.
    """

    direction = packet["direction"]

    protocol = packet["protocol"]

    if direction == "OUT":

        local_port = packet["src_port"]

        remote_ip = packet["dst_ip"]

        remote_port = packet["dst_port"]

    else:

        local_port = packet["dst_port"]

        remote_ip = packet["src_ip"]

        remote_port = packet["src_port"]

    return (
        direction,
        protocol,
        local_port,
        remote_ip,
        remote_port,
    )


# ============================================================
# TCPDUMP PARSER
# ============================================================

def parse_endpoint(endpoint):

    endpoint = endpoint.rstrip(":")

    # IPv4
    match = re.match(
        r"^(\d+\.\d+\.\d+\.\d+)\.(\d+)$",
        endpoint
    )

    if match:

        return (
            match.group(1),
            match.group(2),
        )

    return endpoint, "-"


def parse_packet(line, local_ips):

    """
    Parse tcpdump -tt -n -q output.

    Example:

    1759051234.123456 IP 192.168.1.10.50001 >
    142.250.185.14.443: tcp 0

    """

    try:

        if " > " not in line:
            return None

        parts = line.split()

        # ----------------------------------------------------
        # Protocol
        # ----------------------------------------------------

        if "IP " not in line and not "IP6 " in line:
            return None

        if "Flags" in line:
            protocol = "TCP"

        elif "udp" in line.lower():
            protocol = "UDP"

        elif "icmp" in line.lower():
            protocol = "ICMP"

        else:
            return None

        # ----------------------------------------------------
        # Find endpoints
        # ----------------------------------------------------

        arrow_index = -1

        for i, part in enumerate(parts):

            if part == ">":

                arrow_index = i
                break

        if arrow_index <= 0:
            return None

        src_raw = parts[arrow_index - 1]

        dst_raw = parts[arrow_index + 1]

        src_ip, src_port = parse_endpoint(src_raw)

        dst_ip, dst_port = parse_endpoint(dst_raw)

        # ----------------------------------------------------
        # Validate IPs
        # ----------------------------------------------------

        if src_ip not in local_ips and dst_ip not in local_ips:

            return None

        # ----------------------------------------------------
        # Direction
        # ----------------------------------------------------

        if src_ip in local_ips:

            direction = "OUT"

        elif dst_ip in local_ips:

            direction = "IN"

        else:

            return None

        # ----------------------------------------------------
        # Packet size
        # ----------------------------------------------------

        packet_size = 0

        length_match = re.search(
            r"length\s+(\d+)",
            line
        )

        if length_match:

            packet_size = int(
                length_match.group(1)
            )

        return {

            "direction": direction,

            "protocol": protocol,

            "src_ip": src_ip,

            "src_port": src_port,

            "dst_ip": dst_ip,

            "dst_port": dst_port,

            "bytes": packet_size,

        }

    except Exception:

        return None


# ============================================================
# START TCPDUMP
# ============================================================

def start_tcpdump():

    return subprocess.Popen(

        [
            "tcpdump",

            "-i",
            INTERFACE,

            "-n",

            "-l",

            "-tt",

            "-q",

        ],

        stdout=subprocess.PIPE,

        stderr=subprocess.DEVNULL,

        text=True,

        bufsize=1,

    )


# ============================================================
# PROCESS PACKET
# ============================================================

def process_packet(packet):

    global total_packets
    global total_bytes

    global rx_packets
    global tx_packets

    global rx_bytes
    global tx_bytes

    now = time.time()

    key = make_flow_key(packet)

    # --------------------------------------------------------
    # Create flow
    # --------------------------------------------------------

    if key not in flows:

        flows[key] = {

            "direction":
                packet["direction"],

            "protocol":
                packet["protocol"],

            "local_port":
                packet["src_port"]
                if packet["direction"] == "OUT"
                else packet["dst_port"],

            "remote_ip":
                packet["dst_ip"]
                if packet["direction"] == "OUT"
                else packet["src_ip"],

            "remote_port":
                packet["dst_port"]
                if packet["direction"] == "OUT"
                else packet["src_port"],

            "packets": 0,

            "bytes": 0,

            "first_seen": now,

            "last_seen": now,

        }

    # --------------------------------------------------------
    # Update flow
    # --------------------------------------------------------

    flow = flows[key]

    flow["packets"] += 1

    flow["bytes"] += packet["bytes"]

    flow["last_seen"] = now

    # --------------------------------------------------------
    # Global counters
    # --------------------------------------------------------

    total_packets += 1

    total_bytes += packet["bytes"]

    if packet["direction"] == "IN":

        rx_packets += 1

        rx_bytes += packet["bytes"]

    else:

        tx_packets += 1

        tx_bytes += packet["bytes"]


# ============================================================
# CLEANUP FLOWS
# ============================================================

def cleanup_flows():

    now = time.time()

    expired = []

    for key, flow in flows.items():

        if now - flow["last_seen"] > FLOW_TIMEOUT:

            expired.append(key)

    for key in expired:

        del flows[key]


# ============================================================
# SAVE CSV
# ============================================================

def save_csv():

    temporary_file = CSV_FILE + ".tmp"

    try:

        with open(
            temporary_file,
            "w",
            newline="",
            encoding="utf-8",
        ) as f:

            writer = csv.writer(f)

            writer.writerow([
                "direction",
                "protocol",
                "local_port",
                "local_service",
                "remote_ip",
                "remote_port",
                "remote_service",
                "packets",
                "bytes",
                "first_seen",
                "last_seen",
            ])

            for flow in flows.values():

                protocol = flow["protocol"]

                local_port = flow["local_port"]

                remote_port = flow["remote_port"]

                local_service = get_service(
                    local_port,
                    protocol
                )

                remote_service = get_service(
                    remote_port,
                    protocol
                )

                writer.writerow([

                    flow["direction"],

                    protocol,

                    local_port,

                    local_service,

                    flow["remote_ip"],

                    remote_port,

                    remote_service,

                    flow["packets"],

                    flow["bytes"],

                    datetime.fromtimestamp(
                        flow["first_seen"]
                    ).isoformat(),

                    datetime.fromtimestamp(
                        flow["last_seen"]
                    ).isoformat(),

                ])

            f.flush()

            os.fsync(f.fileno())

        # Atomic replacement
        os.replace(
            temporary_file,
            CSV_FILE
        )

    except Exception as e:

        print(
            f"\nCSV error: {e}",
            file=sys.stderr
        )


# ============================================================
# FORMAT BYTES
# ============================================================

def format_bytes(value):

    units = [
        "B",
        "KB",
        "MB",
        "GB",
        "TB",
    ]

    value = float(value)

    for unit in units:

        if value < 1024:

            return f"{value:.1f}{unit}"

        value /= 1024

    return f"{value:.1f}PB"


# ============================================================
# FORMAT RATE
# ============================================================

def format_rate(value):

    return format_bytes(value) + "/s"


# ============================================================
# RESET
# ============================================================

def reset_statistics():

    global flows

    global total_packets
    global total_bytes

    global rx_packets
    global tx_packets

    global rx_bytes
    global tx_bytes

    flows = {}

    total_packets = 0
    total_bytes = 0

    rx_packets = 0
    tx_packets = 0

    rx_bytes = 0
    tx_bytes = 0

    save_csv()


# ============================================================
# KEYBOARD
# ============================================================

def keyboard_available():

    return select.select(
        [sys.stdin],
        [],
        [],
        0
    )[0]


def read_key():

    if not keyboard_available():
        return None

    return sys.stdin.read(1)


# ============================================================
# DASHBOARD
# ============================================================

def render(local_ips, rx_rate, tx_rate):

    clear_screen()

    terminal_width = 120

    print(
        bold(cyan("NETTOP"))
        + " "
        + datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )

    print()

    print(
        f"Interface : {INTERFACE}"
    )

    print(
        f"Local IPs : "
        f"{', '.join(sorted(local_ips))}"
    )

    print()

    print(
        f"RX: {green(format_rate(rx_rate))}"
        f"    "
        f"TX: {yellow(format_rate(tx_rate))}"
        f"    "
        f"Flows: {len(flows):,}"
        f"    "
        f"Packets: {total_packets:,}"
        f"    "
        f"Traffic: {format_bytes(total_bytes)}"
    )

    print()

    header = (
        f"{'DIR':<5}"
        f"{'PROTO':<7}"
        f"{'LOCAL':<22}"
        f"{'REMOTE':<25}"
        f"{'SERVICE':<18}"
        f"{'PACKETS':>10}"
        f"{'BYTES':>12}"
    )

    print(bold(header))

    print("-" * min(
        terminal_width,
        len(header)
    ))

    # --------------------------------------------------------
    # Sort by bytes
    # --------------------------------------------------------

    sorted_flows = sorted(

        flows.values(),

        key=lambda f: f["bytes"],

        reverse=True,

    )

    for flow in sorted_flows[
        :MAX_DISPLAY_FLOWS
    ]:

        direction = flow["direction"]

        protocol = flow["protocol"]

        local_port = flow["local_port"]

        remote_ip = flow["remote_ip"]

        remote_port = flow["remote_port"]

        local_service = get_service(
            local_port,
            protocol
        )

        remote_service = get_service(
            remote_port,
            protocol
        )

        if direction == "OUT":

            local = f":{local_port}"

            remote = (
                f"{remote_ip}:"
                f"{remote_port}"
            )

            service = local_service

        else:

            local = f":{local_port}"

            remote = (
                f"{remote_ip}:"
                f"{remote_port}"
            )

            service = local_service

        if len(service) > 17:

            service = service[:17]

        print(

            f"{direction:<5}"

            f"{protocol:<7}"

            f"{local:<22}"

            f"{remote:<25}"

            f"{service:<18}"

            f"{flow['packets']:>10,}"

            f"{format_bytes(flow['bytes']):>12}"

        )

    print()

    print(
        grey(
            "q: quit    "
            "r: reset    "
            "CSV: " + CSV_FILE
        )
    )


# ============================================================
# SIGNAL HANDLING
# ============================================================

def stop(signum=None, frame=None):

    global running

    running = False


signal.signal(
    signal.SIGINT,
    stop
)

signal.signal(
    signal.SIGTERM,
    stop
)


# ============================================================
# MAIN
# ============================================================

def main():

    global tcpdump_process

    global previous_total_packets
    global previous_total_bytes

    global previous_rx_bytes
    global previous_tx_bytes

    global previous_time

    # --------------------------------------------------------
    # Check tcpdump
    # --------------------------------------------------------

    if os.geteuid() != 0:

        print(
            "Run with sudo:",
            file=sys.stderr
        )

        print(
            f"sudo {sys.argv[0]}",
            file=sys.stderr
        )

        sys.exit(1)

    # --------------------------------------------------------
    # Initial IP detection
    # --------------------------------------------------------

    local_ips = get_local_ips()

    if not local_ips:

        print(
            "Could not determine local IP addresses.",
            file=sys.stderr
        )

        sys.exit(1)

    # --------------------------------------------------------
    # Terminal raw mode
    # --------------------------------------------------------

    old_terminal = termios.tcgetattr(
        sys.stdin
    )

    tty.setcbreak(
        sys.stdin.fileno()
    )

    hide_cursor()

    clear_screen()

    try:

        # ----------------------------------------------------
        # Start tcpdump
        # ----------------------------------------------------

        tcpdump_process = start_tcpdump()

        last_refresh = 0

        last_csv_save = 0

        last_ip_refresh = 0

        while running:

            # ------------------------------------------------
            # Restart tcpdump if it dies
            # ------------------------------------------------

            if tcpdump_process.poll() is not None:

                time.sleep(1)

                if not running:
                    break

                tcpdump_process = start_tcpdump()

            # ------------------------------------------------
            # Read packet
            # ------------------------------------------------

            readable, _, _ = select.select(

                [tcpdump_process.stdout],

                [],

                [],

                0.1

            )

            if readable:

                line = (
                    tcpdump_process.stdout.readline()
                )

                if line:

                    packet = parse_packet(
                        line.strip(),
                        local_ips
                    )

                    if packet:

                        process_packet(
                            packet
                        )

            # ------------------------------------------------
            # Keyboard
            # ------------------------------------------------

            key = read_key()

            if key:

                if key.lower() == "q":

                    running = False

                    break

                elif key.lower() == "r":

                    reset_statistics()

            # ------------------------------------------------
            # Refresh IP addresses
            # ------------------------------------------------

            now = time.time()

            if now - last_ip_refresh > 10:

                local_ips = get_local_ips()

                last_ip_refresh = now

            # ------------------------------------------------
            # Dashboard refresh
            # ------------------------------------------------

            if now - last_refresh >= REFRESH_INTERVAL:

                elapsed = (
                    now - previous_time
                )

                if elapsed <= 0:
                    elapsed = 1

                rx_rate = (
                    rx_bytes -
                    previous_rx_bytes
                ) / elapsed

                tx_rate = (
                    tx_bytes -
                    previous_tx_bytes
                ) / elapsed

                render(
                    local_ips,
                    rx_rate,
                    tx_rate
                )

                previous_rx_bytes = rx_bytes

                previous_tx_bytes = tx_bytes

                previous_total_packets = (
                    total_packets
                )

                previous_total_bytes = (
                    total_bytes
                )

                previous_time = now

                last_refresh = now

            # ------------------------------------------------
            # Save CSV
            # ------------------------------------------------

            if now - last_csv_save >= CSV_SAVE_INTERVAL:

                cleanup_flows()

                save_csv()

                last_csv_save = now

    finally:

        running = False

        # ----------------------------------------------------
        # Stop tcpdump
        # ----------------------------------------------------

        if tcpdump_process:

            try:

                tcpdump_process.terminate()

                tcpdump_process.wait(
                    timeout=2
                )

            except Exception:

                try:
                    tcpdump_process.kill()
                except Exception:
                    pass

        # ----------------------------------------------------
        # Final CSV save
        # ----------------------------------------------------

        save_csv()

        # ----------------------------------------------------
        # Restore terminal
        # ----------------------------------------------------

        termios.tcsetattr(
            sys.stdin,
            termios.TCSADRAIN,
            old_terminal
        )

        show_cursor()

        clear_screen()

        print(
            "NETTOP stopped."
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()
