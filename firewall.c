#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/icmp.h>

struct data_t {
    u32 saddr;
    u16 dport;
    u32 type;
    u32 flood_type;  // 10 = UDP, 11 = ICMP, 12 = SYN
};

// Flood rate limiting config: key (0=UDP, 1=ICMP, 2=SYN), value = {soft_limit, hard_limit}
struct flood_config_t {
    u32 soft_limit;
    u32 hard_limit;
    u32 enabled;
};

// Packet counter per IP per protocol per second: key = (timestamp_sec << 34 | proto << 32 | IP),
// value = packet_count
struct flow_key_t {
    u32 ip;
    u32 proto;  // IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP
    u32 ts_sec;
};

BPF_PERF_OUTPUT(events);

// Feature toggles: key 0=blacklist, 1=ping, 2=port, 10=udp_flood, 11=icmp_flood, 12=syn_flood
BPF_HASH(feature_flags, u32, u8);

// Flood rate limiting config
BPF_HASH(flood_config, u32, struct flood_config_t);

// IP blacklist (IP -> hit count)
BPF_HASH(blacklist, u32, u64);

// Blocked IPs (due to hard limit): key = IP, value = block_timestamp_sec
BPF_HASH(blocked_ips, u32, u64);

// Packet counters per flow (IP + protocol + sec)
BPF_HASH(packet_counters, struct flow_key_t, u64);

// Dynamic port blocklist (port -> 1)
BPF_HASH(port_blocklist, u16, u8);
// Whitelist
BPF_HASH(whitelist, u32, u8);

// Helper: Get current timestamp in seconds
static u64 bpf_get_current_time_sec() {
    return bpf_ktime_get_ns() / 1000000000ULL;
}


int xdp_prog(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr  *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct data_t  evt = {};

    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != htons(ETH_P_IP)) return XDP_PASS;

    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    evt.saddr = ip->saddr;

    // Whitelist
    u8 *wl = whitelist.lookup(&evt.saddr);
    if (wl) return XDP_PASS;

    u32 key_bl   = 0;
    u32 key_ping = 1;
    u32 key_port = 2;
    u32 key_udp_flood  = 10;
    u32 key_icmp_flood = 11;
    u32 key_syn_flood  = 12;

    // --- Check if IP is banned (flood hard limit) — silent drop ---
    u64 *blocked_ts = blocked_ips.lookup(&evt.saddr);
    if (blocked_ts) {
        u64 now = bpf_get_current_time_sec();
        if (now - *blocked_ts < 60) {
            return XDP_DROP;
        } else {
            blocked_ips.delete(&evt.saddr);
        }
    }

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

    // --- Gate 2: ICMP Ping + ICMP Flood Detection ---
    u8 *fl_ping = feature_flags.lookup(&key_ping);
    u8 *fl_icmp_flood = feature_flags.lookup(&key_icmp_flood);
    
    if (ip->protocol == IPPROTO_ICMP) {
        // Check ICMP flood
        if (fl_icmp_flood && *fl_icmp_flood == 1) {
            struct flood_config_t *cfg = flood_config.lookup(&key_icmp_flood);
            if (cfg && cfg->enabled) {
                u64 now = bpf_get_current_time_sec();
                struct flow_key_t flow = {
                    .ip = evt.saddr,
                    .proto = IPPROTO_ICMP,
                    .ts_sec = now
                };
                
                u64 *count = packet_counters.lookup(&flow);
                u64 current_count = (count) ? (*count + 1) : 1;
                packet_counters.update(&flow, &current_count);

                // Hard limit: ban IP for 60s
                if (current_count > cfg->hard_limit) {
                    blocked_ips.update(&evt.saddr, &now);
                    evt.type = 4;
                    evt.flood_type = 11;  // ICMP
                    events.perf_submit(ctx, &evt, sizeof(evt));
                    return XDP_DROP;
                }
                // Soft limit: drop every packet silently (no event — avoid IPC flood)
                else if (current_count > cfg->soft_limit) {
                    return XDP_DROP;
                }
            }
        }
        
        // Check regular ICMP ping block
        if (fl_ping && *fl_ping == 1) {
            evt.type = 2;
            events.perf_submit(ctx, &evt, sizeof(evt));
            return XDP_DROP;
        }
    }

    // --- Gate 3: UDP Flood Detection ---
    u8 *fl_udp_flood = feature_flags.lookup(&key_udp_flood);
    if (ip->protocol == IPPROTO_UDP) {
        if (fl_udp_flood && *fl_udp_flood == 1) {
            struct flood_config_t *cfg = flood_config.lookup(&key_udp_flood);
            if (cfg && cfg->enabled) {
                u64 now = bpf_get_current_time_sec();
                struct flow_key_t flow = {
                    .ip = evt.saddr,
                    .proto = IPPROTO_UDP,
                    .ts_sec = now
                };
                
                udp = (void *)ip + (ip->ihl * 4);
                if ((void *)(udp + 1) > data_end) return XDP_PASS;
                evt.dport = ntohs(udp->dest);

                u64 *count = packet_counters.lookup(&flow);
                u64 current_count = (count) ? (*count + 1) : 1;
                packet_counters.update(&flow, &current_count);

                // Hard limit: ban IP for 60s
                if (current_count > cfg->hard_limit) {
                    blocked_ips.update(&evt.saddr, &now);
                    evt.type = 4;
                    evt.flood_type = 10;  // UDP
                    events.perf_submit(ctx, &evt, sizeof(evt));
                    return XDP_DROP;
                }
                // Soft limit: drop every packet silently (no event — avoid IPC flood)
                else if (current_count > cfg->soft_limit) {
                    return XDP_DROP;
                }
            }
        }
    }

    // --- Gate 4: TCP Port (dynamic list) + SYN Flood Detection ---
    u8 *fl_port = feature_flags.lookup(&key_port);
    u8 *fl_syn_flood = feature_flags.lookup(&key_syn_flood);
    
    if (ip->protocol == IPPROTO_TCP) {
        tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;

        evt.dport = ntohs(tcp->dest);

        // Check SYN flood
        if (fl_syn_flood && *fl_syn_flood == 1) {
            struct flood_config_t *cfg = flood_config.lookup(&key_syn_flood);
            if (cfg && cfg->enabled) {
                u64 now = bpf_get_current_time_sec();
                struct flow_key_t flow = {
                    .ip = evt.saddr,
                    .proto = IPPROTO_TCP,
                    .ts_sec = now
                };
                
                u64 *count = packet_counters.lookup(&flow);
                u64 current_count = (count) ? (*count + 1) : 1;
                packet_counters.update(&flow, &current_count);

                // Hard limit: ban IP for 60s
                if (current_count > cfg->hard_limit) {
                    blocked_ips.update(&evt.saddr, &now);
                    evt.type = 4;
                    evt.flood_type = 12;  // SYN
                    events.perf_submit(ctx, &evt, sizeof(evt));
                    return XDP_DROP;
                }
                // Soft limit: drop every packet silently (no event — avoid IPC flood)
                else if (current_count > cfg->soft_limit) {
                    return XDP_DROP;
                }
            }
        }

        // Check port blocklist
        if (fl_port && *fl_port == 1) {
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
