from bcc import BPF
import time
import socket
import struct
import ctypes

def int_to_ip(ip_int):
    return socket.inet_ntoa(struct.pack("<I", ip_int))

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
bad_ip = struct.unpack("I", socket.inet_aton("192.168.1.10"))[0]
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
    while True:
        # อ่านข้อมูลจาก Kernel
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        
        # แปลงข้อความเป็น String
        log_raw = msg.decode('utf-8')
        
        # --- ส่วนการถอดรหัส Log (Custom Parser) ---
        try:
            parts = log_raw.split()
            # ค้นหาตำแหน่งของ IP: และ PORT:
            ip_val = 0
            port_val = 0
            for p in parts:
                if p.startswith("IP:"):
                    ip_val = int(p.split(":")[1])
                if p.startswith("PORT:"):
                    port_val = int(p.split(":")[1])

            ip_str = int_to_ip(ip_val)

            if "TYPE:B" in log_raw:
                print(f"[BLACKLIST] Blocked IP: {ip_str}")
            elif "TYPE:P" in log_raw:
                print(f"[PING] Blocked Ping from: {ip_str}")
            elif "TYPE:W" in log_raw:
                print(f"[WEB] Blocked Access from: {ip_str} -> Target Port: {port_val}")
        except Exception as e:
            # ถ้าถอดรหัสไม่ได้ ให้โชว์ Raw log เพื่อ Debug
            print(f"📝 DEBUG RAW: {log_raw}")

except KeyboardInterrupt:
    pass
# 5. ถอด Firewall
print("\nRemoving Firewall...")
b.remove_xdp(device, 0)
print("Done.")