#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>

// 1. นิยามโครงสร้างข้อมูลที่จะส่งกลับไป Python
struct data_t {
    u32 saddr;    // Source IP
    u16 dport;    // Destination Port
    u32 type;     // ประเภท (1:Blacklist, 2:Ping, 3:Web)
};

// 2. สร้างท่อส่งข้อมูลชื่อ "events"
BPF_PERF_OUTPUT(events);
BPF_HASH(blacklist, u32, u64);

int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct data_t evt = {}; // สร้างตัวแปรไว้เก็บข้อมูลส่งออก

    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != htons(ETH_P_IP)) return XDP_PASS;

    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    evt.saddr = ip->saddr; // บันทึก IP ลงในตัวแปรที่จะส่ง

    // --- ด่านที่ 1: Blacklist ---
    u64 *val = blacklist.lookup(&evt.saddr);
    if (val) {
        lock_xadd(val, 1); 
        evt.type = 1; // ประเภท Blacklist
        events.perf_submit(ctx, &evt, sizeof(evt)); // ส่งข้อมูลผ่านท่อ
        return XDP_DROP;
    }

    // --- ด่านที่ 2: ICMP Ping ---
    if (ip->protocol == 1) {
        evt.type = 2; // ประเภท Ping
        events.perf_submit(ctx, &evt, sizeof(evt));
        return XDP_DROP;
    }

    // --- ด่านที่ 3: TCP Port ---
    if (ip->protocol == 6) {
        tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;

        evt.dport = ntohs(tcp->dest); // บันทึก Port
        if (evt.dport == 8000 || evt.dport == 80 || evt.dport == 443) {
            evt.type = 3; // ประเภท Web
            events.perf_submit(ctx, &evt, sizeof(evt));
            return XDP_DROP; 
        }
    }

    return XDP_PASS;
}