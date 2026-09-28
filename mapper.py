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

from datetime import datetime


# ============================================================
# CONFIGURATION
# ============================================================

CSV_FILE = "network_services.csv"

INTERFACE = "any"

REFRESH_INTERVAL = 1.0

CSV_SAVE_INTERVAL = 10.0

FLOW_TIMEOUT = 3600

MAX_DISPLAY_FLOWS = 30


# ============================================================
# NETTOP
# ============================================================

class NetTop:

    def __init__(self):

        self.running = True

        self.tcpdump = None

        self.flows = {}

        self.total_packets = 0
        self.total_bytes = 0

        self.rx_packets = 0
        self.tx_packets = 0

        self.rx_bytes = 0
        self.tx_bytes = 0

        self.previous_rx_bytes = 0
        self.previous_tx_bytes = 0

        self.previous_time = time.time()

        self.last_refresh = 0
        self.last_csv_save = 0
        self.last_ip_refresh = 0

        self.local_ips = set()

        self.service_cache = {}

        self.old_terminal = None

    # ========================================================
    # TERMINAL
    # ========================================================

    @staticmethod
    def clear_screen():

        print("\033[2J\033[H", end="")

    @staticmethod
    def hide_cursor():

        print("\033[?25l", end="")

    @staticmethod
    def show_cursor():

        print("\033[?25h", end="")

    # ========================================================
    # LOCAL IPs
    # ========================================================

    def get_local_ips(self):

        try:

            output = subprocess.check_output(
                [
                    "ip",
                    "-4",
                    "-o",
                    "addr",
                    "show"
                ],
                text=True,
                stderr=subprocess.DEVNULL
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

    # ========================================================
    # SERVICE LOOKUP
    # ========================================================

    def get_service(self, port, protocol):

        if port in ("", "-", None):

            return "-"

        try:

            port = int(port)

        except (ValueError, TypeError):

            return "-"

        key = (port, protocol)

        if key in self.service_cache:

            return self.service_cache[key]

        try:

            service = socket.getservbyport(
                port,
                protocol.lower()
            )

        except OSError:

            service = "-"

        self.service_cache[key] = service

        return service

    # ========================================================
    # ENDPOINT PARSER
    # ========================================================

    @staticmethod
    def parse_endpoint(endpoint):

        endpoint = endpoint.rstrip(":")

        match = re.match(
            r"^(\d+\.\d+\.\d+\.\d+)\.(\d+)$",
            endpoint
        )

        if match:

            return (
                match.group(1),
                match.group(2)
            )

        return endpoint, "-"

    # ========================================================
    # PACKET PARSER
    # ========================================================

    def parse_packet(self, line):

        try:

            if " > " not in line:

                return None

            parts = line.split()

            # ------------------------------------------------
            # Protocol
            # ------------------------------------------------

            if "Flags" in line:

                protocol = "TCP"

            elif re.search(
                r"\budp\b",
                line,
                re.IGNORECASE
            ):

                protocol = "UDP"

            elif re.search(
                r"\bicmp\b",
                line,
                re.IGNORECASE
            ):

                protocol = "ICMP"

            else:

                return None

            # ------------------------------------------------
            # Find >
            # ------------------------------------------------

            arrow_index = -1

            for i, part in enumerate(parts):

                if part == ">":

                    arrow_index = i

                    break

            if arrow_index <= 0:

                return None

            src_raw = parts[arrow_index - 1]

            dst_raw = parts[arrow_index + 1]

            src_ip, src_port = self.parse_endpoint(
                src_raw
            )

            dst_ip, dst_port = self.parse_endpoint(
                dst_raw
            )

            # ------------------------------------------------
            # Only traffic involving this host
            # ------------------------------------------------

            if src_ip in self.local_ips:

                direction = "OUT"

            elif dst_ip in self.local_ips:

                direction = "IN"

            else:

                return None

            # ------------------------------------------------
            # Packet length
            # ------------------------------------------------

            packet_size = 0

            match = re.search(
                r"length\s+(\d+)",
                line
            )

            if match:

                packet_size = int(
                    match.group(1)
                )

            return {
                "direction": direction,
                "protocol": protocol,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "bytes": packet_size
            }

        except Exception:

            return None

    # ========================================================
    # FLOW KEY
    # ========================================================

    @staticmethod
    def make_flow_key(packet):

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
            remote_port
        )

    # ========================================================
    # PROCESS PACKET
    # ========================================================

    def process_packet(self, packet):

        now = time.time()

        key = self.make_flow_key(packet)

        if key not in self.flows:

            if packet["direction"] == "OUT":

                local_port = packet["src_port"]

                remote_ip = packet["dst_ip"]

                remote_port = packet["dst_port"]

            else:

                local_port = packet["dst_port"]

                remote_ip = packet["src_ip"]

                remote_port = packet["src_port"]

            self.flows[key] = {

                "direction": packet["direction"],

                "protocol": packet["protocol"],

                "local_port": local_port,

                "remote_ip": remote_ip,

                "remote_port": remote_port,

                "packets": 0,

                "bytes": 0,

                "first_seen": now,

                "last_seen": now
            }

        flow = self.flows[key]

        flow["packets"] += 1

        flow["bytes"] += packet["bytes"]

        flow["last_seen"] = now

        self.total_packets += 1

        self.total_bytes += packet["bytes"]

        if packet["direction"] == "IN":

            self.rx_packets += 1

            self.rx_bytes += packet["bytes"]

        else:

            self.tx_packets += 1

            self.tx_bytes += packet["bytes"]

    # ========================================================
    # START TCPDUMP
    # ========================================================

    def start_tcpdump(self):

        return subprocess.Popen(
            [
                "tcpdump",
                "-i",
                INTERFACE,
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

    # ========================================================
    # CLEANUP
    # ========================================================

    def cleanup_flows(self):

        now = time.time()

        expired = []

        for key, flow in self.flows.items():

            if (
                now - flow["last_seen"]
                > FLOW_TIMEOUT
            ):

                expired.append(key)

        for key in expired:

            del self.flows[key]

    # ========================================================
    # SAVE CSV
    # ========================================================

    def save_csv(self):

        temporary_file = CSV_FILE + ".tmp"

        try:

            with open(
                temporary_file,
                "w",
                newline="",
                encoding="utf-8"
            ) as file:

                writer = csv.writer(file)

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
                    "last_seen"
                ])

                for flow in self.flows.values():

                    protocol = flow["protocol"]

                    local_port = flow["local_port"]

                    remote_port = flow["remote_port"]

                    local_service = self.get_service(
                        local_port,
                        protocol
                    )

                    remote_service = self.get_service(
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
                        ).isoformat()
                    ])

                file.flush()

                os.fsync(file.fileno())

            # Atomic replacement
            os.replace(
                temporary_file,
                CSV_FILE
            )

        except Exception as exc:

            print(
                f"\nCSV error: {exc}",
                file=sys.stderr
            )

    # ========================================================
    # FORMAT BYTES
    # ========================================================

    @staticmethod
    def format_bytes(value):

        value = float(value)

        units = [
            "B",
            "KB",
            "MB",
            "GB",
            "TB"
        ]

        for unit in units:

            if value < 1024:

                return f"{value:.1f}{unit}"

            value /= 1024

        return f"{value:.1f}PB"

    # ========================================================
    # DASHBOARD
    # ========================================================

    def render(self, rx_rate, tx_rate):

        self.clear_screen()

        print(
            "\033[1;36m"
            "NETTOP"
            "\033[0m"
            "   "
            + datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

        print()

        print(
            f"Interface : {INTERFACE}"
        )

        print(
            "Local IPs : "
            + ", ".join(
                sorted(self.local_ips)
            )
        )

        print()

        print(
            f"RX {self.format_bytes(rx_rate)}/s"
            f"    "
            f"TX {self.format_bytes(tx_rate)}/s"
            f"    "
            f"Flows {len(self.flows):,}"
            f"    "
            f"Packets {self.total_packets:,}"
            f"    "
            f"Traffic {self.format_bytes(self.total_bytes)}"
        )

        print()

        print(
            f"{'DIR':<5}"
            f"{'PROTO':<7}"
            f"{'LOCAL':<12}"
            f"{'REMOTE':<26}"
            f"{'SERVICE':<18}"
            f"{'PACKETS':>10}"
            f"{'BYTES':>12}"
        )

        print("-" * 100)

        sorted_flows = sorted(
            self.flows.values(),
            key=lambda flow: flow["bytes"],
            reverse=True
        )

        for flow in sorted_flows[
            :MAX_DISPLAY_FLOWS
        ]:

            local_port = flow["local_port"]

            remote = (
                f"{flow['remote_ip']}:"
                f"{flow['remote_port']}"
            )

            service = self.get_service(
                local_port,
                flow["protocol"]
            )

            print(

                f"{flow['direction']:<5}"

                f"{flow['protocol']:<7}"

                f":{local_port:<11}"

                f"{remote:<26}"

                f"{service:<18}"

                f"{flow['packets']:>10,}"

                f"{self.format_bytes(flow['bytes']):>12}"
            )

        print()

        print(
            "\033[90m"
            "q: quit    "
            "r: reset    "
            f"CSV: {CSV_FILE}"
            "\033[0m"
        )

    # ========================================================
    # RESET
    # ========================================================

    def reset(self):

        self.flows.clear()

        self.total_packets = 0
        self.total_bytes = 0

        self.rx_packets = 0
        self.tx_packets = 0

        self.rx_bytes = 0
        self.tx_bytes = 0

        self.previous_rx_bytes = 0
        self.previous_tx_bytes = 0

        self.save_csv()

    # ========================================================
    # KEYBOARD
    # ========================================================

    @staticmethod
    def key_available():

        readable, _, _ = select.select(
            [sys.stdin],
            [],
            [],
            0
        )

        return bool(readable)

    # ========================================================
    # MAIN LOOP
    # ========================================================

    def run(self):

        if os.geteuid() != 0:

            print(
                "This program must be run as root."
            )

            print()

            print(
                f"Run: sudo {sys.argv[0]}"
            )

            sys.exit(1)

        self.local_ips = self.get_local_ips()

        if not self.local_ips:

            print(
                "Unable to determine local IP addresses."
            )

            sys.exit(1)

        self.old_terminal = termios.tcgetattr(
            sys.stdin
        )

        tty.setcbreak(
            sys.stdin.fileno()
        )

        self.hide_cursor()

        self.clear_screen()

        try:

            self.tcpdump = self.start_tcpdump()

            while self.running:

                # --------------------------------------------
                # Read tcpdump
                # --------------------------------------------

                if self.tcpdump.poll() is not None:

                    time.sleep(1)

                    if self.running:

                        self.tcpdump = (
                            self.start_tcpdump()
                        )

                    continue

                readable, _, _ = select.select(

                    [self.tcpdump.stdout],

                    [],

                    [],

                    0.1
                )

                if readable:

                    line = (
                        self.tcpdump.stdout.readline()
                    )

                    if line:

                        packet = self.parse_packet(
                            line.strip()
                        )

                        if packet:

                            self.process_packet(
                                packet
                            )

                # --------------------------------------------
                # Keyboard
                # --------------------------------------------

                if self.key_available():

                    key = sys.stdin.read(1)

                    if key.lower() == "q":

                        self.running = False

                    elif key.lower() == "r":

                        self.reset()

                now = time.time()

                # --------------------------------------------
                # Refresh local IPs
                # --------------------------------------------

                if (
                    now - self.last_ip_refresh
                    >= 10
                ):

                    self.local_ips = (
                        self.get_local_ips()
                    )

                    self.last_ip_refresh = now

                # --------------------------------------------
                # Dashboard
                # --------------------------------------------

                if (
                    now - self.last_refresh
                    >= REFRESH_INTERVAL
                ):

                    elapsed = (
                        now - self.previous_time
                    )

                    if elapsed <= 0:

                        elapsed = 1

                    rx_rate = (

                        self.rx_bytes
                        - self.previous_rx_bytes

                    ) / elapsed

                    tx_rate = (

                        self.tx_bytes
                        - self.previous_tx_bytes

                    ) / elapsed

                    self.render(
                        rx_rate,
                        tx_rate
                    )

                    self.previous_rx_bytes = (
                        self.rx_bytes
                    )

                    self.previous_tx_bytes = (
                        self.tx_bytes
                    )

                    self.previous_time = now

                    self.last_refresh = now

                # --------------------------------------------
                # CSV
                # --------------------------------------------

                if (
                    now - self.last_csv_save
                    >= CSV_SAVE_INTERVAL
                ):

                    self.cleanup_flows()

                    self.save_csv()

                    self.last_csv_save = now

        finally:

            self.stop()

    # ========================================================
    # STOP
    # ========================================================

    def stop(self):

        self.running = False

        if self.tcpdump:

            try:

                self.tcpdump.terminate()

                self.tcpdump.wait(
                    timeout=2
                )

            except Exception:

                try:

                    self.tcpdump.kill()

                except Exception:

                    pass

        # Final CSV
        self.save_csv()

        if self.old_terminal:

            try:

                termios.tcsetattr(
                    sys.stdin,
                    termios.TCSADRAIN,
                    self.old_terminal
                )

            except Exception:

                pass

        self.show_cursor()

        self.clear_screen()

        print("NETTOP stopped.")


# ============================================================
# SIGNALS
# ============================================================

app = NetTop()


def signal_handler(signum, frame):

    app.running = False


signal.signal(
    signal.SIGINT,
    signal_handler
)

signal.signal(
    signal.SIGTERM,
    signal_handler
)


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    app.run()
