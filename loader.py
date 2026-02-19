from bcc import BPF
import socket
import struct
import ctypes

BLACKLIST_IP = [
    "8.8.8.8",
    "1.1.1.1",
    "192.168.1.108"
]

devices = ["enp0s9", "enp0s8", "enp0s3", "lo"]

b = BPF(src_file="firewall.c")
fn = b.load_func("xdp_prog", BPF.XDP)

for dev in devices:
    b.attach_xdp(dev, fn, 0)

def ip_to_int(ip_str):
    return struct.unpack("I", socket.inet_aton(ip_str))[0]

def int_to_ip(ip_int):
    return socket.inet_ntoa(struct.pack("<I", ip_int))

blacklist_map = b["blacklist"]
for ip in BLACKLIST_IP:
    try:
        ip_int = ip_to_int(ip)
        blacklist_map[ctypes.c_uint32(ip_int)] = ctypes.c_uint64(0)
    except Exception as e:
        None

def int_to_ip(ip_int):
    return socket.inet_ntoa(struct.pack("<I", ip_int))

# ฟังก์ชันที่จะถูกเรียกเมื่อมีข้อมูลส่งมาจาก Kernel
def print_event(cpu, data, size):
    # รับข้อมูลและแปลงกลับเป็นโครงสร้าง C (Struct)
    class Data(ctypes.Structure):
        _fields_ = [
            ("saddr", ctypes.c_uint32),
            ("dport", ctypes.c_uint16),
            ("type", ctypes.c_uint32)
        ]
    
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    ip_str = int_to_ip(event.saddr)
    
    if event.type == 1:
        print(f"[BLACKLIST] Blocked IP: {ip_str}")
    elif event.type == 2:
        print(f"[PING] Blocked Ping from: {ip_str}")
    elif event.type == 3:
        print(f"[WEB] Blocked Access from: {ip_str} -> Target Port: {event.dport}")

# 3. เปิดท่อรับข้อมูล
b["events"].open_perf_buffer(print_event)

print("🔥 Firewall ACTIVE & MONITORING...")
print("---------------------------------------------")

try:
    while True:
        # วนลูปเช็คข้อมูลจากท่อ (ไม่กิน CPU)
        b.perf_buffer_poll()
except KeyboardInterrupt:
    pass

for dev in devices:
    b.remove_xdp(dev, 0)
print("Done.")