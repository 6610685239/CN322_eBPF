#define KBUILD_MODNAME "xdp_firewall"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

// ฟังก์ชันนี้จะถูกเรียกทุกครั้งที่มี Packet เข้ามา
int xdp_prog(struct xdp_md *ctx)
{
    // 1. อ่านตำแหน่งข้อมูล
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 2. เช็คEthernet Packet(Safety Check)
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 3. เช็ค IP Packet
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    // 4. ดูข้อมูลใน IP Header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // 5. เช็ค ICMP (Ping)
    // ถ้า Protocol == 1 คือ ICMP
    if (ip->protocol == 1)
    {
        bpf_trace_printk("Ping detected! Dropping packet...\\n");
        return XDP_DROP; // Dropping packet
    }

    return XDP_PASS; // ถ้าไม่ใช่ Ping ปล่อยผ่าน
}