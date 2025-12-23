/* xdp/wolfsentry_xdp_filter.c
 *
 * wolfSentry XDP packet filter.
 * Compiled with: clang -O2 -target bpf -c wolfsentry_xdp_filter.c -o wolfsentry_xdp_filter.o
 *
 * Copyright (C) 2024 wolfSSL Inc.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "wolfsentry_xdp_common.h"

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

/* BPF map: IPv4 blocklist
 * Key: __u32 (IPv4 address in network byte order)
 * Value: struct ws_xdp_block_entry
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, WS_XDP_BLOCKLIST_MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct ws_xdp_block_entry);
} ws_blocklist SEC(".maps");

/* BPF map: Statistics (per-CPU for performance)
 * Key: __u32 (always 0 for global stats)
 * Value: struct ws_xdp_stats
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ws_xdp_stats);
} ws_stats SEC(".maps");

/* Helper: Parse IPv4 header and extract source IP */
static __always_inline int parse_ipv4(void *data, void *data_end, __u32 *src_ip)
{
    struct ethhdr *eth = data;
    struct iphdr *ip;

    /* Bounds check: Ethernet header */
    if ((void *)(eth + 1) > data_end)
        return -1;

    /* Check for IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    /* Bounds check: IP header */
    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    /* Extract source IP (already in network byte order) */
    *src_ip = ip->saddr;
    return 0;
}

/* Main XDP program entry point */
SEC("xdp")
int wolfsentry_xdp_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 src_ip;
    __u32 stats_key = WS_XDP_STATS_KEY_GLOBAL;
    struct ws_xdp_stats *stats;
    struct ws_xdp_block_entry *entry;
    __u64 now_ns;

    /* Get stats pointer */
    stats = bpf_map_lookup_elem(&ws_stats, &stats_key);
    if (stats)
        stats->packets_total++;

    /* Parse packet, extract source IP */
    if (parse_ipv4(data, data_end, &src_ip) < 0) {
        /* Not IPv4, pass through */
        if (stats)
            stats->packets_passed++;
        return XDP_PASS;
    }

    /* Lookup source IP in blocklist */
    entry = bpf_map_lookup_elem(&ws_blocklist, &src_ip);
    if (!entry) {
        /* Not in blocklist, pass through */
        if (stats)
            stats->packets_passed++;
        return XDP_PASS;
    }

    /* Check if entry has expired */
    if (!(entry->flags & WS_XDP_FLAG_PERMANENT)) {
        now_ns = bpf_ktime_get_ns();
        if (entry->blocked_until_ns != 0 && now_ns > entry->blocked_until_ns) {
            /* Entry expired, pass through */
            if (stats)
                stats->packets_expired++;
            return XDP_PASS;
        }
    }

    /* Block the packet */
    __sync_fetch_and_add(&entry->drop_count, 1);
    if (stats)
        stats->packets_dropped++;

    return XDP_DROP;
}

/* License declaration required for BPF */
char _license[] SEC("license") = "GPL";
