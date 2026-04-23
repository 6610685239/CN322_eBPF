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

// Feature toggles: key 0 = blacklist, 1 = ping, 2 = port
BPF_HASH(feature_flags, u32, u8);

// IP blacklist (IP -> hit count)
BPF_HASH(blacklist, u32, u64);

// Dynamic port blocklist (port -> 1)
BPF_HASH(port_blocklist, u16, u8);

int xdp_prog(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr  *ip;
    struct tcphdr *tcp;
    struct data_t  evt = {};

    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != htons(ETH_P_IP)) return XDP_PASS;

    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    evt.saddr = ip->saddr;

    u32 key_bl   = 0;
    u32 key_ping = 1;
    u32 key_port = 2;

    // --- Gate 1: Blacklist ---
    u8 *fl_bl = feature_flags.lookup(&key_bl);
    if (fl_bl && *fl_bl == 1) {
        u64 *val = blacklist.lookup(&evt.saddr);
        if (val) {
            lock_xadd(val, 1);
            evt.type = 1;
            events.perf_submit(ctx, &evt, sizeof(evt));
            return XDP_DROP;
        }
    }

    // --- Gate 2: ICMP Ping ---
    u8 *fl_ping = feature_flags.lookup(&key_ping);
    if (fl_ping && *fl_ping == 1) {
        if (ip->protocol == IPPROTO_ICMP) {
            evt.type = 2;
            events.perf_submit(ctx, &evt, sizeof(evt));
            return XDP_DROP;
        }
    }

    // --- Gate 3: TCP Port (dynamic list) ---
    u8 *fl_port = feature_flags.lookup(&key_port);
    if (fl_port && *fl_port == 1) {
        if (ip->protocol == IPPROTO_TCP) {
            tcp = (void *)ip + (ip->ihl * 4);
            if ((void *)(tcp + 1) > data_end) return XDP_PASS;

            evt.dport = ntohs(tcp->dest);
            u8 *blocked = port_blocklist.lookup(&evt.dport);
            if (blocked) {
                evt.type = 3;
                events.perf_submit(ctx, &evt, sizeof(evt));
                return XDP_DROP;
            }
        }
    }

    return XDP_PASS;
}
