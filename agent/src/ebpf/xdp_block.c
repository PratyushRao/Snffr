#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

// BPF helper function forward declaration
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) BPF_FUNC_map_lookup_elem;

// Legacy BPF map definition 
struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

struct bpf_map_def SEC("maps") blocked_ips = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 4, // size of __be32 (IPv4 address)
    .value_size = 1, // size of __u8 (flag)
    .max_entries = 10240,
    .map_flags = 0,
};

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Check if the packet is IPv4 (0x0800 in big endian is 0x0008 on little endian)
    if (eth->h_proto != 0x0008) {
        return XDP_PASS;
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    unsigned int src_ip = iph->saddr;

    unsigned char *value = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (value) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
