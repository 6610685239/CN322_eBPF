from bcc import BPF
import time

# 1. ระบุชื่อการ์ดแลน (Network Interface) ที่จะดักจับ
device = "lo"  # ชื่อการ์ดแลน

# 2. คอมไพล์โค้ด C
print("Compiling eBPF code...")
b = BPF(src_file="firewall.c")
fn = b.load_func("xdp_prog", BPF.XDP)

# 3. โหลดโปรแกรมเข้าสู่โหมด XDP
print(f"Attaching XDP to {device}...")
b.attach_xdp(device, fn, 0)

print("Firewall is ON! Try pinging this machine.")
print("Press Ctrl+C to stop.")

# 4. วนลูปเพื่อเลี้ยงโปรแกรมไว้ และอ่าน Log
try:
    b.trace_print()
except KeyboardInterrupt:
    pass

# 5. คืนค่าเดิมเมื่อปิดโปรแกรม 
print("Removing XDP...")
b.remove_xdp(device, 0)