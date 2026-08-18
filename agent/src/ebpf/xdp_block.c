#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/in6.h>

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

// BPF helper fn frwrd declarations
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) BPF_FUNC_map_update_elem;
static __u64 (*bpf_ktime_get_ns)(void) = (void *) BPF_FUNC_ktime_get_ns;

struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

// IPv4 Blocked IPs Hash Map (Key: __be32 IPv4 address, Value: __u8 flag)
struct bpf_map_def SEC("maps") blocked_ips = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__be32), // 4 bytes
    .value_size = sizeof(__u8),  // 1 byte flag
    .max_entries = 10240,
    .map_flags = 0,
};

// IPv6 Blocked IPs Hash Map (Key: 16-byte IPv6 address, Value: __u8 flag)
struct bpf_map_def SEC("maps") blocked_ips_v6 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 16,             // 16 bytes (struct in6_addr)
    .value_size = sizeof(__u8),  // 1 byte flag
    .max_entries = 10240,
    .map_flags = 0,
};

// IPv4 token bucket
struct token_bucket {
    __u64 last_time_ns;
    __u64 tokens;
    __u64 rate_limit_pps;
};

struct bpf_map_def SEC("maps") rate_limit_ips = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__be32),
    .value_size = sizeof(struct token_bucket),
    .max_entries = 10240,
    .map_flags = 0,
};

// XDP Performance Statistics Array (0: Total, 1: Dropped, 2: Passed)
struct bpf_map_def SEC("maps") xdp_stats = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),   // Index (0, 1, 2)
    .value_size = sizeof(__u64), // Packet Counter
    .max_entries = 4,
    .map_flags = 0,
};

// update telemetry stats
static inline void update_stat(__u32 stat_idx) {
    __u64 *count = bpf_map_lookup_elem(&xdp_stats, &stat_idx);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
}

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    update_stat(0); // idx 0: Total Packets Received

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        update_stat(2);
        return XDP_PASS;
    }

    __u16 h_proto = eth->h_proto;

    // --- IPv4 Handling (ETH_P_IP = 0x0800 -> 0x0008 in little endian) ---
    if (h_proto == 0x0008) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end) {
            update_stat(2);
            return XDP_PASS;
        }

        __be32 src_ip = iph->saddr;

        // IPv4 Blocked Map
        __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &src_ip);
        if (blocked) {
            update_stat(1); // idx 1: Dropped Packets
            return XDP_DROP;
        }

        // IPv4 Rate Limit Token Bucket
        struct token_bucket *tb = bpf_map_lookup_elem(&rate_limit_ips, &src_ip);
        if (tb) {
            __u64 now = bpf_ktime_get_ns();
            __u64 elapsed = now - tb->last_time_ns;

            // Replenish tokens
            if (elapsed > 0 && tb->rate_limit_pps > 0) {
                __u64 new_tokens = (elapsed * tb->rate_limit_pps) / 1000000000ULL;
                if (new_tokens > 0) {
                    tb->tokens += new_tokens;
                    if (tb->tokens > tb->rate_limit_pps) {
                        tb->tokens = tb->rate_limit_pps;
                    }
                    tb->last_time_ns = now;
                }
            }

            if (tb->tokens >= 1) {
                tb->tokens -= 1;
            } else {
                update_stat(1); // idx 1: Dropped Packets
                return XDP_DROP;
            }
        }
    }
    // --- IPv6 Handling (ETH_P_IPV6 = 0x86DD -> 0xDD86 in little endian) ---
    else if (h_proto == 0xDD86) {
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end) {
            update_stat(2);
            return XDP_PASS;
        }

        // Check IPv6 Blocked Map
        __u8 *blocked_v6 = bpf_map_lookup_elem(&blocked_ips_v6, &ip6h->saddr);
        if (blocked_v6) {
            update_stat(1); // idx 1: Dropped pkts
            return XDP_DROP;
        }
    }

    update_stat(2); // idx 2: Passed pkts
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

