// ไม่ต้อง define KBUILD_MODNAME เอง เพราะ BCC ทำให้แล้ว (แก้ Warning)
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h> // <--- เปลี่ยนมาใช้ UAPI เพื่อแก้ Error

// สร้างสมุดบัญชีดำ (Map)
BPF_HASH(blacklist, u32, u64);

int xdp_prog(struct xdp_md *ctx) {
    // 1. ประกาศตัวแปร
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    u32 saddr;
    u64 *val;
    u16 dport = 0; 
    // 2. เช็ค Ethernet Header
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    // เช็คว่าเป็น IP Packet ไหม
    if (eth->h_proto != htons(ETH_P_IP)) return XDP_PASS;

    // 3. เช็ค IP Header
    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    // *** ด่านที่ 1: เช็ค Blacklist IP ***
    saddr = ip->saddr; 
    val = blacklist.lookup(&saddr);
    
    if (val) {
        lock_xadd(val, 1); 
        bpf_trace_printk("TYPE:B IP:%u\n", saddr);
        return XDP_DROP;
    }

    // *** ด่านที่ 2: เช็ค Ping (ICMP) ***
    // IPPROTO_ICMP = 1
    if (ip->protocol == 1) {
        bpf_trace_printk("TYPE:P IP:%u\n", saddr);
        return XDP_DROP;
    }

    // *** ด่านที่ 3: เช็ค Web Port 8000 (TCP) ***
    // IPPROTO_TCP = 6
    if (ip->protocol == 6) {
        // คำนวณตำแหน่ง TCP Header
        tcp = (void *)ip + (ip->ihl * 4);
        
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;

        // เช็ค Port 8000
        if (ntohs(tcp->dest) == 8000 ) {
            bpf_trace_printk("TYPE:W IP:%u PORT:%u\n", (u32)saddr, (u32)dport);
            return XDP_DROP; 
        }
    }

    return XDP_PASS;
}