#  Great Icewall of Thailand
**High-Performance Network Firewall using eBPF and XDP Project**

This project implements a high-performance packet filtering firewall using **eBPF (Extended Berkeley Packet Filter)** and **XDP (eXpress Data Path)** on Linux. It runs directly in the kernel space (network driver hook), allowing it to drop malicious packets with minimal CPU overhead before they reach the OS stack.

---

## Team Members
**Subject:** CN322 Computer Network Security  
**Semester:** 2/2568

<table>
  <thead>
    <tr>
      <th align="center">Student ID</th>
      <th align="left">Name</th>
      <th align="left">Role & Responsibility</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td align="center"><b>6610685056</b></td>
      <td>Chonchanan Jitrawang</td>
      <td>-</td>
    </tr>
    <tr>
      <td align="center"><b>6610685098</b></td>
      <td>Kittidet Wichaidit</td>
      <td>-</td>
    </tr>
    <tr>
      <td align="center"><b>6610685122</b></td>
      <td>Chayawat Kanjanakaew</td>
      <td>-</td>
    </tr>
    <tr>
      <td align="center"><b>6610685205</b></td>
      <td>Nonthapat Boonprasith</td>
      <td>-</td>
    </tr>
    <tr>
      <td align="center"><b>6610685239</b></td>
      <td>Parunchai Timklip</td>
      <td>-</td>
    </tr>
  </tbody>
</table>

---

## Features
The firewall currently supports the following filtering rules:

1.  **Dynamic IP Blacklisting:** Blocks specific IP addresses defined in an eBPF Hash Map.
2.  **ICMP Filtering:** Drops all ICMP (Ping) packets to prevent scanning/flooding.
3.  **Service Filtering:** Drops TCP traffic on specific ports:
    *   **Port 8000** (Test Web Server)

---

## Prerequisites
*   **OS:** Ubuntu 22.04 LTS or 24.04 LTS (VirtualBox/VMware recommended)
*   **Kernel:** Linux 5.4+ (Supports XDP)
*   **Tools:** Python 3, BCC (BPF Compiler Collection), Clang, LLVM

### Installation
Run the following commands to install dependencies:

```bash
sudo apt update
sudo apt install -y build-essential git clang llvm python3-bpfcc bpfcc-tools linux-headers-$(uname -r) curl
