#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>

struct data_t {
    u32 saddr;    
    u16 dport;    
    u32 type;     
};

BPF_PERF_OUTPUT(events);
BPF_HASH(blacklist, u32, u64);

int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct data_t evt = {}; 

    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != htons(ETH_P_IP)) return XDP_PASS;

    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    evt.saddr = ip->saddr; 

    u64 *val = blacklist.lookup(&evt.saddr);
    if (val) {
        lock_xadd(val, 1); 
        evt.type = 1; 
        events.perf_submit(ctx, &evt, sizeof(evt)); 
        return XDP_DROP;
    }

    if (ip->protocol == 1) {
        evt.type = 2; 
        events.perf_submit(ctx, &evt, sizeof(evt));
        return XDP_DROP;
    }

    if (ip->protocol == 6) {
        tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;

        evt.dport = ntohs(tcp->dest); 
        if (evt.dport == 8000 || evt.dport == 80 || evt.dport == 443) {
            evt.type = 3; 
            events.perf_submit(ctx, &evt, sizeof(evt));
            return XDP_DROP; 
        }
    }

    return XDP_PASS;
}