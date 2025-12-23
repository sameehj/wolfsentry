/* xdp/wolfsentry_xdp_common.h
 *
 * Shared definitions for wolfSentry XDP integration.
 * Used by both the XDP BPF program and userspace wolfSentry.
 *
 * Copyright (C) 2024 wolfSSL Inc.
 */

#ifndef WOLFSENTRY_XDP_COMMON_H
#define WOLFSENTRY_XDP_COMMON_H

/* IMPORTANT:
 * Shared between BPF (kernel, via vmlinux.h) and userspace (libbpf).
 * Avoid libc headers in BPF builds.
 */
#ifdef __BPF__
/* BPF side: vmlinux.h already provides kernel types. */
#else
#include <linux/types.h>
#endif

/* Map names - must match between BPF program and userspace */
#define WS_XDP_MAP_BLOCKLIST    "ws_blocklist"
#define WS_XDP_MAP_STATS        "ws_stats"

/* Maximum entries in blocklist map */
#define WS_XDP_BLOCKLIST_MAX_ENTRIES    10000

/* IPv4 blocklist entry value */
struct ws_xdp_block_entry {
    __u64 blocked_until_ns;   /* Nanoseconds since epoch, 0 = permanent */
    __u64 drop_count;         /* Packets dropped from this IP */
    __u32 flags;              /* Reserved for future use */
    __u32 _pad;
};

/* Statistics counters (per-CPU for performance) */
struct ws_xdp_stats {
    __u64 packets_total;      /* Total packets seen */
    __u64 packets_passed;     /* Packets passed to stack */
    __u64 packets_dropped;    /* Packets dropped (blocklist hit) */
    __u64 packets_expired;    /* Drops skipped (entry expired) */
};

/* Stats map key */
#define WS_XDP_STATS_KEY_GLOBAL  0

/* Action flags for block entry */
#define WS_XDP_FLAG_PERMANENT    (1U << 0)  /* Never expires */
#define WS_XDP_FLAG_LOG          (1U << 1)  /* Log drops (future) */

#endif /* WOLFSENTRY_XDP_COMMON_H */
