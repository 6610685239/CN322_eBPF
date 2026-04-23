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
import sys

# ─── Config ───────────────────────────────────────────────
IPC_SOCKET_PATH = "/tmp/firewall.sock"
DB_PATH         = os.environ.get("FIREWALL_DB", "/var/lib/firewall/firewall.db")
DEVICES         = ["enp0s9", "enp0s8", "enp0s3", "lo"]

# ─── BPF feature-flag key constants ───────────────────────
KEY_BLACKLIST = 0
KEY_PING      = 1
KEY_PORT      = 2


# ══════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════

def ip_to_int(ip_str: str) -> int:
    return struct.unpack("I", socket.inet_aton(ip_str))[0]

def int_to_ip(ip_int: int) -> str:
    return socket.inet_ntoa(struct.pack("<I", ip_int))

def ensure_db_dir():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


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


# ══════════════════════════════════════════════════════════
#  Load initial state from SQLite
# ══════════════════════════════════════════════════════════

def load_initial_state():
    """Read DB and populate BPF maps."""
    if not os.path.exists(DB_PATH):
        print("[DB] DB not found yet — will retry in 3 s")
        time.sleep(3)
        if not os.path.exists(DB_PATH):
            print("[DB] DB still missing; starting with defaults (all features ON)")
            for key in [KEY_BLACKLIST, KEY_PING, KEY_PORT]:
                feature_flag_map[ctypes.c_uint32(key)] = ctypes.c_uint8(1)
            return

    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()

    # Feature flags
    feature_key_map = {"blacklist": KEY_BLACKLIST, "ping": KEY_PING, "port": KEY_PORT}
    cur.execute("SELECT id, enabled FROM feature_flags")
    for row in cur.fetchall():
        name, enabled = row
        if name in feature_key_map:
            k = feature_key_map[name]
            feature_flag_map[ctypes.c_uint32(k)] = ctypes.c_uint8(1 if enabled else 0)
            print(f"[INIT] Feature '{name}' = {'ON' if enabled else 'OFF'}")

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

ipc_sock       = None
ipc_lock       = threading.Lock()
ipc_connected  = False


def send_event(payload: dict):
    """Thread-safe send to Node.js over IPC socket."""
    global ipc_sock
    with ipc_lock:
        if ipc_sock is None:
            return
        try:
            msg = json.dumps(payload) + "\n"
            ipc_sock.sendall(msg.encode())
        except Exception:
            pass  # handled by reconnect loop


def handle_command(cmd: dict):
    """Process a command received from Node.js."""
    action = cmd.get("action")

    if action == "toggle_feature":
        feature = cmd.get("feature")   # "blacklist" | "ping" | "port"
        enabled = int(cmd.get("enabled", True))
        key_map = {"blacklist": KEY_BLACKLIST, "ping": KEY_PING, "port": KEY_PORT}
        if feature in key_map:
            feature_flag_map[ctypes.c_uint32(key_map[feature])] = ctypes.c_uint8(enabled)
            print(f"[CMD] Toggle '{feature}' → {'ON' if enabled else 'OFF'}")

    elif action == "add_ip":
        ip_str = cmd.get("ip")
        try:
            ip_int = ip_to_int(ip_str)
            blacklist_map[ctypes.c_uint32(ip_int)] = ctypes.c_uint64(0)
            print(f"[CMD] Add IP {ip_str}")
        except Exception as e:
            print(f"[CMD] add_ip error: {e}")

    elif action == "remove_ip":
        ip_str = cmd.get("ip")
        try:
            ip_int = ip_to_int(ip_str)
            key = ctypes.c_uint32(ip_int)
            if key in blacklist_map:
                del blacklist_map[key]
            print(f"[CMD] Remove IP {ip_str}")
        except Exception as e:
            print(f"[CMD] remove_ip error: {e}")

    elif action == "add_port":
        port = cmd.get("port")
        try:
            port_map[ctypes.c_uint16(int(port))] = ctypes.c_uint8(1)
            print(f"[CMD] Add port {port}")
        except Exception as e:
            print(f"[CMD] add_port error: {e}")

    elif action == "remove_port":
        port = cmd.get("port")
        try:
            key = ctypes.c_uint16(int(port))
            if key in port_map:
                del port_map[key]
            print(f"[CMD] Remove port {port}")
        except Exception as e:
            print(f"[CMD] remove_port error: {e}")

    else:
        print(f"[CMD] Unknown action: {action}")


def ipc_reader(sock):
    """Read newline-delimited JSON commands from Node.js."""
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
                        cmd = json.loads(line.decode())
                        handle_command(cmd)
                    except json.JSONDecodeError:
                        pass
        except Exception:
            break


def ipc_connect_loop():
    """Persistent connection to Node.js IPC server with reconnect."""
    global ipc_sock, ipc_connected
    while True:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(IPC_SOCKET_PATH)
            with ipc_lock:
                ipc_sock      = s
                ipc_connected = True
            print("[IPC] Connected to Node.js")

            # Send ready signal
            send_event({"type": "ready"})

            # Block reading commands until disconnected
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
#  Perf buffer callback — forward events to Node.js & print
# ══════════════════════════════════════════════════════════

class EventData(ctypes.Structure):
    _fields_ = [
        ("saddr", ctypes.c_uint32),
        ("dport", ctypes.c_uint16),
        ("type",  ctypes.c_uint32),
    ]

TYPE_LABEL = {1: "blacklist", 2: "ping", 3: "web"}

def print_event(cpu, data, size):
    event  = ctypes.cast(data, ctypes.POINTER(EventData)).contents
    ip_str = int_to_ip(event.saddr)
    etype  = TYPE_LABEL.get(event.type, "unknown")

    label = {
        1: f"[BLACKLIST] Blocked IP: {ip_str}",
        2: f"[PING]      Blocked Ping from: {ip_str}",
        3: f"[WEB]       Blocked from: {ip_str} → Port {event.dport}",
    }.get(event.type, f"[?] {ip_str}")

    print(label)

    send_event({
        "type":      "log",
        "eventType": etype,
        "ip":        ip_str,
        "port":      event.dport if event.type == 3 else None,
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
