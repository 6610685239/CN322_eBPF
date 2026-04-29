#!/usr/bin/env python3
"""
loader.py — XDP Firewall Loader with Web Dashboard IPC
Connects to Node.js backend via Unix socket for real-time control.
"""

from bcc import BPF
import socket
import struct
import ctypes
import sqlite3
import threading
import json
import time
import os

# ─── Config ───────────────────────────────────────────────
IPC_SOCKET_PATH = "/tmp/firewall.sock"
DB_PATH         = os.environ.get("FIREWALL_DB", "/var/lib/firewall/firewall.db")
DEVICES         = ["enp0s9", "enp0s8", "enp0s3", "lo"]

# ─── BPF feature-flag key constants ───────────────────────
KEY_BLACKLIST = 0
KEY_PING      = 1
KEY_PORT      = 2
KEY_UDP_FLOOD = 10
KEY_ICMP_FLOOD = 11
KEY_SYN_FLOOD = 12


# ══════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════

def ip_to_int(ip_str: str) -> int:
    return struct.unpack("I", socket.inet_aton(ip_str))[0]

def int_to_ip(ip_int: int) -> str:
    return socket.inet_ntoa(struct.pack("<I", ip_int))


# ══════════════════════════════════════════════════════════
#  BPF Setup
# ══════════════════════════════════════════════════════════

b  = BPF(src_file="firewall.c", cflags=["-Wno-macro-redefined", "-Wno-duplicate-decl-specifier"])
fn = b.load_func("xdp_prog", BPF.XDP)

for dev in DEVICES:
    try:
        b.attach_xdp(dev, fn, 0)
        print(f"[XDP] Attached to {dev}")
    except Exception as e:
        print(f"[XDP] Skip {dev}: {e}")

blacklist_map    = b["blacklist"]
port_map         = b["port_blocklist"]
feature_flag_map = b["feature_flags"]
whitelist_map    = b["whitelist"]
flood_config_map = b["flood_config"]
blocked_ips_map  = b["blocked_ips"]


# ─── Flood config structure (must match firewall.c) ───────
class FloodConfig(ctypes.Structure):
    _fields_ = [
        ("soft_limit", ctypes.c_uint32),
        ("hard_limit", ctypes.c_uint32),
        ("enabled", ctypes.c_uint32),
    ]


# ══════════════════════════════════════════════════════════
#  Whitelist — ใส่ IP ของเครื่องตัวเองทั้งหมดอัตโนมัติ
# ══════════════════════════════════════════════════════════

def populate_whitelist():
    # รวบรวม IP จากทุก interface ผ่าน socket
    local_ips = set()

    try:
        hostname = socket.gethostname()
        primary_ip = socket.gethostbyname(hostname)
        local_ips.add(primary_ip)
    except Exception:
        pass

    try:
        import subprocess
        result = subprocess.run(
            ["ip", "-4", "addr", "show"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                ip_cidr = line.split()[1]          # เช่น "192.168.1.10/24"
                ip_addr = ip_cidr.split("/")[0]    # ตัด prefix ออก
                local_ips.add(ip_addr)
    except Exception:
        pass

    # เพิ่ม loopback เสมอ
    local_ips.add("127.0.0.1")

    # ใส่เข้า BPF whitelist map
    for ip_str in local_ips:
        try:
            ip_int = ip_to_int(ip_str)
            whitelist_map[ctypes.c_uint32(ip_int)] = ctypes.c_uint8(1)
            print(f"[WHITELIST] Allowed (self): {ip_str}")
        except Exception as e:
            print(f"[WHITELIST] Failed for {ip_str}: {e}")

populate_whitelist()


# ══════════════════════════════════════════════════════════
#  Load initial state from SQLite
# ══════════════════════════════════════════════════════════

def load_initial_state():
    """Read DB and populate BPF maps."""
    if not os.path.exists(DB_PATH):
        print("[DB] DB not found yet — will retry in 3 s")
        time.sleep(3)
        if not os.path.exists(DB_PATH):
            print("[DB] DB still missing — starting with defaults (all features ON)")
            for key in [KEY_BLACKLIST, KEY_PING, KEY_PORT]:
                feature_flag_map[ctypes.c_uint32(key)] = ctypes.c_uint8(1)
            return

    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()

    # Feature flags
    feature_key_map = {"blacklist": KEY_BLACKLIST, "ping": KEY_PING, "port": KEY_PORT,
                       "udp_flood": KEY_UDP_FLOOD, "icmp_flood": KEY_ICMP_FLOOD, "syn_flood": KEY_SYN_FLOOD}
    cur.execute("SELECT id, enabled FROM feature_flags")
    for row in cur.fetchall():
        name, enabled = row
        if name in feature_key_map:
            k = feature_key_map[name]
            feature_flag_map[ctypes.c_uint32(k)] = ctypes.c_uint8(1 if enabled else 0)
            print(f"[INIT] Feature '{name}' = {'ON' if enabled else 'OFF'}")

    # Flood rate limits
    flood_type_map = {"udp_flood": KEY_UDP_FLOOD, "icmp_flood": KEY_ICMP_FLOOD, "syn_flood": KEY_SYN_FLOOD}
    cur.execute("SELECT flood_type, soft_limit, hard_limit FROM flood_rates")
    rows = cur.fetchall()
    if not rows:
        # Use defaults if no rows
        rows = [
            ("udp_flood", 100, 200),
            ("icmp_flood", 50, 100),
            ("syn_flood", 200, 400),
        ]
    
    for row in rows:
        flood_type, soft_limit, hard_limit = row
        if flood_type in flood_type_map:
            k = flood_type_map[flood_type]
            cfg = FloodConfig(soft_limit=soft_limit, hard_limit=hard_limit, enabled=1)
            flood_config_map[ctypes.c_uint32(k)] = cfg
            print(f"[INIT] Flood '{flood_type}' soft={soft_limit} hard={hard_limit}")

    # Blacklist IPs
    cur.execute("SELECT ip FROM blacklist")
    for (ip_str,) in cur.fetchall():
        try:
            ip_int = ip_to_int(ip_str)
            blacklist_map[ctypes.c_uint32(ip_int)] = ctypes.c_uint64(0)
            print(f"[INIT] Blacklist IP: {ip_str}")
        except Exception as e:
            print(f"[INIT] Bad IP {ip_str}: {e}")

    # Port blocklist
    cur.execute("SELECT port FROM port_blocklist")
    for (port,) in cur.fetchall():
        try:
            port_map[ctypes.c_uint16(port)] = ctypes.c_uint8(1)
            print(f"[INIT] Blocked port: {port}")
        except Exception as e:
            print(f"[INIT] Bad port {port}: {e}")

    conn.close()

load_initial_state()


# ══════════════════════════════════════════════════════════
#  IPC — connect to Node.js and stream events / receive cmds
# ══════════════════════════════════════════════════════════

ipc_sock      = None
ipc_lock      = threading.Lock()
ipc_connected = False


def send_event(payload: dict):
    global ipc_sock
    with ipc_lock:
        if ipc_sock is None:
            return
        try:
            ipc_sock.sendall((json.dumps(payload) + "\n").encode())
        except Exception:
            pass


def handle_command(cmd: dict):
    action = cmd.get("action")

    if action == "toggle_feature":
        feature = cmd.get("feature")
        enabled = int(cmd.get("enabled", True))
        key_map = {"blacklist": KEY_BLACKLIST, "ping": KEY_PING, "port": KEY_PORT,
                   "udp_flood": KEY_UDP_FLOOD, "icmp_flood": KEY_ICMP_FLOOD, "syn_flood": KEY_SYN_FLOOD}
        if feature in key_map:
            feature_flag_map[ctypes.c_uint32(key_map[feature])] = ctypes.c_uint8(enabled)
            print(f"[CMD] Toggle '{feature}' → {'ON' if enabled else 'OFF'}")

    elif action == "update_flood_rates":
        flood_type = cmd.get("flood_type")
        soft_limit = int(cmd.get("soft_limit", 0))
        hard_limit = int(cmd.get("hard_limit", 0))
        flood_type_map = {"udp_flood": KEY_UDP_FLOOD, "icmp_flood": KEY_ICMP_FLOOD, "syn_flood": KEY_SYN_FLOOD}
        if flood_type in flood_type_map:
            k = flood_type_map[flood_type]
            cfg = FloodConfig(soft_limit=soft_limit, hard_limit=hard_limit, enabled=1)
            flood_config_map[ctypes.c_uint32(k)] = cfg
            print(f"[CMD] Update flood '{flood_type}' soft={soft_limit} hard={hard_limit}")

    elif action == "add_ip":
        ip_str = cmd.get("ip")
        try:
            ip_int = ip_to_int(ip_str)
            blacklist_map[ctypes.c_uint32(ip_int)] = ctypes.c_uint64(0)
            print(f"[CMD] Add blacklist IP: {ip_str}")
        except Exception as e:
            print(f"[CMD] add_ip error: {e}")

    elif action == "remove_ip":
        ip_str = cmd.get("ip")
        try:
            ip_int = ip_to_int(ip_str)
            key = ctypes.c_uint32(ip_int)
            if key in blacklist_map:
                del blacklist_map[key]
            print(f"[CMD] Remove blacklist IP: {ip_str}")
        except Exception as e:
            print(f"[CMD] remove_ip error: {e}")

    elif action == "add_port":
        port = cmd.get("port")
        try:
            port_map[ctypes.c_uint16(int(port))] = ctypes.c_uint8(1)
            print(f"[CMD] Add blocked port: {port}")
        except Exception as e:
            print(f"[CMD] add_port error: {e}")

    elif action == "remove_port":
        port = cmd.get("port")
        try:
            key = ctypes.c_uint16(int(port))
            if key in port_map:
                del port_map[key]
            print(f"[CMD] Remove blocked port: {port}")
        except Exception as e:
            print(f"[CMD] remove_port error: {e}")

    else:
        print(f"[CMD] Unknown action: {action}")


def ipc_reader(sock):
    buf = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if line.strip():
                    try:
                        handle_command(json.loads(line.decode()))
                    except json.JSONDecodeError:
                        pass
        except Exception:
            break


def ipc_connect_loop():
    global ipc_sock, ipc_connected
    while True:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(IPC_SOCKET_PATH)
            with ipc_lock:
                ipc_sock      = s
                ipc_connected = True
            print("[IPC] Connected to Node.js")
            send_event({"type": "ready"})
            ipc_reader(s)
            with ipc_lock:
                ipc_sock      = None
                ipc_connected = False
            s.close()
            print("[IPC] Disconnected — reconnecting in 3 s")
        except Exception as e:
            print(f"[IPC] Connect failed: {e} — retry in 3 s")
        time.sleep(3)

ipc_thread = threading.Thread(target=ipc_connect_loop, daemon=True)
ipc_thread.start()


# ══════════════════════════════════════════════════════════
#  Perf buffer callback
# ══════════════════════════════════════════════════════════

class EventData(ctypes.Structure):
    _fields_ = [
        ("saddr", ctypes.c_uint32),
        ("dport", ctypes.c_uint16),
        ("type",  ctypes.c_uint32),
        ("flood_type", ctypes.c_uint32),
    ]

TYPE_LABEL = {
    1: "blacklist",
    2: "ping",
    3: "port",
    4: "flood_hard_limit",
    5: "flood_blocked",
}

def print_event(cpu, data, size):
    event  = ctypes.cast(data, ctypes.POINTER(EventData)).contents
    ip_str = int_to_ip(event.saddr)
    etype  = TYPE_LABEL.get(event.type, "unknown")

    flood_type_names = {10: "UDP", 11: "ICMP", 12: "SYN"}
    flood_name = flood_type_names.get(event.flood_type, f"type-{event.flood_type}")

    label = {
        1: f"[BLACKLIST] Blocked IP: {ip_str}",
        2: f"[PING]      Blocked Ping from: {ip_str}",
        3: f"[PORT]       Blocked {ip_str} → Port {event.dport}",
        4: f"[FLOOD]     Hard limit exceeded: {flood_name} flood from {ip_str} (BLOCKED 1 min)",
        5: f"[FLOOD]     Temporarily blocked IP: {ip_str}",
    }.get(event.type, f"[?] {ip_str}")

    print(label)

    send_event({
        "type":      "log",
        "eventType": etype,
        "ip":        ip_str,
        "port":      event.dport if event.type == 3 else None,
        "floodType": flood_name if event.type in [3, 4, 5] else None,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    })


b["events"].open_perf_buffer(print_event)

print("🔥 Firewall ACTIVE & MONITORING...")
print("─" * 50)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    pass

for dev in DEVICES:
    try:
        b.remove_xdp(dev, 0)
    except Exception:
        pass

print("\n[XDP] Detached. Done.")