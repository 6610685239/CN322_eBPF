from bcc import BPF
import time
import socket
import struct
import ctypes

# *** ตั้งค่าชื่อการ์ดแลน ***
# ใช้ "lo" ถ้าเทสในเครื่องตัวเอง (curl localhost)
# ใช้ "enp0s3" ถ้าเทสจากเครื่องอื่น
device = "enp0s9" #"lo" 

print(f"Loading Firewall on {device}...")

# 1. โหลดโค้ด C
b = BPF(src_file="firewall.c")
fn = b.load_func("xdp_prog", BPF.XDP)

# 2. ติดตั้ง Firewall
b.attach_xdp(device, fn, 0)

# 3. (Option) ลองแบน IP เล่นๆ
# สมมติแบน IP: 1.2.3.4 (เพื่อโชว์ว่า Map ทำงานได้)
blacklist = b["blacklist"]
bad_ip = struct.unpack("I", socket.inet_aton("192.168.1.108"))[0]
blacklist[ctypes.c_uint32(bad_ip)] = ctypes.c_uint64(0)

print("🔥 Firewall ACTIVE!")
print("Rules:")
print("1. Blacklisted IPs -> DROP")
print("2. ICMP Ping     -> DROP")
print("3. TCP Port 8000 -> DROP")
print("---------------------------------")
print("Press Ctrl+C to stop.")

# 4. อ่าน Log
try:
    b.trace_print()
except KeyboardInterrupt:
    pass

# 5. ถอด Firewall
print("\nRemoving Firewall...")
b.remove_xdp(device, 0)
print("Done.")