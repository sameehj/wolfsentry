/* wolfsentry/wolfsentry_xdp.h
 *
 * wolfSentry XDP Integration API
 *
 * Copyright (C) 2024 wolfSSL Inc.
 */

#ifndef WOLFSENTRY_XDP_H
#define WOLFSENTRY_XDP_H

#include <stdint.h>
#include <wolfsentry/wolfsentry.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Build-time feature flag */
#ifdef WOLFSENTRY_HAVE_XDP

/* XDP context handle (opaque) */
struct wolfsentry_xdp_context;

/* XDP initialization flags */
typedef enum {
    WOLFSENTRY_XDP_FLAG_NONE          = 0,
    WOLFSENTRY_XDP_FLAG_SKB_MODE      = (1U << 0),  /* Force generic/SKB mode */
    WOLFSENTRY_XDP_FLAG_DRV_MODE      = (1U << 1),  /* Force native/driver mode */
    WOLFSENTRY_XDP_FLAG_HW_MODE       = (1U << 2),  /* Force hardware offload */
    WOLFSENTRY_XDP_FLAG_UPDATE_IF_SET = (1U << 3)   /* Replace existing program */
} wolfsentry_xdp_flags_t;

/* XDP statistics */
struct wolfsentry_xdp_stats {
    uint64_t packets_total;
    uint64_t packets_passed;
    uint64_t packets_dropped;
    uint64_t packets_expired;
    uint64_t blocklist_entries;
};

/*
 * Initialize XDP subsystem and attach to interface.
 *
 * @param wolfsentry   wolfSentry context
 * @param ifname       Network interface name (e.g., "eth0")
 * @param xdp_prog_path Path to compiled XDP program (.o file)
 * @param flags        Initialization flags
 * @param xdp_ctx_out  Output: XDP context handle
 *
 * @return WOLFSENTRY_SUCCESS on success, error code otherwise.
 *
 * Note: Requires CAP_NET_ADMIN capability.
 */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_xdp_init(
    struct wolfsentry_context *wolfsentry,
    const char *ifname,
    const char *xdp_prog_path,
    wolfsentry_xdp_flags_t flags,
    struct wolfsentry_xdp_context **xdp_ctx_out);

/*
 * Shutdown XDP subsystem and detach from interface.
 *
 * @param xdp_ctx  XDP context from wolfsentry_xdp_init()
 *
 * @return WOLFSENTRY_SUCCESS on success, error code otherwise.
 */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_xdp_shutdown(
    struct wolfsentry_xdp_context *xdp_ctx);

/*
 * Sync wolfSentry state to XDP maps.
 *
 * Projects penalty-boxed routes to the XDP blocklist map.
 * Call this after configuration changes or periodically.
 *
 * @param wolfsentry  wolfSentry context
 * @param xdp_ctx     XDP context
 *
 * @return WOLFSENTRY_SUCCESS on success, error code otherwise.
 */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_xdp_sync(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_xdp_context *xdp_ctx);

/*
 * Add a single IP to the XDP blocklist.
 *
 * @param xdp_ctx          XDP context
 * @param ipv4_addr        IPv4 address (network byte order)
 * @param block_duration_s Block duration in seconds (0 = permanent)
 *
 * @return WOLFSENTRY_SUCCESS on success, error code otherwise.
 */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_xdp_block_ip(
    struct wolfsentry_xdp_context *xdp_ctx,
    uint32_t ipv4_addr,
    uint32_t block_duration_s);

/*
 * Remove a single IP from the XDP blocklist.
 *
 * @param xdp_ctx    XDP context
 * @param ipv4_addr  IPv4 address (network byte order)
 *
 * @return WOLFSENTRY_SUCCESS on success, error code otherwise.
 */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_xdp_unblock_ip(
    struct wolfsentry_xdp_context *xdp_ctx,
    uint32_t ipv4_addr);

/*
 * Get XDP statistics.
 *
 * @param xdp_ctx   XDP context
 * @param stats_out Output: statistics structure
 *
 * @return WOLFSENTRY_SUCCESS on success, error code otherwise.
 */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_xdp_get_stats(
    struct wolfsentry_xdp_context *xdp_ctx,
    struct wolfsentry_xdp_stats *stats_out);

/*
 * Register XDP sync callback with wolfSentry.
 *
 * When registered, wolfSentry automatically calls wolfsentry_xdp_sync()
 * whenever routes are inserted, deleted, or penalty-box status changes.
 *
 * @param wolfsentry  wolfSentry context
 * @param xdp_ctx     XDP context
 *
 * @return WOLFSENTRY_SUCCESS on success, error code otherwise.
 */
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_xdp_register_auto_sync(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_xdp_context *xdp_ctx);

/*
 * Check if XDP is supported and available on this system.
 *
 * @return 1 if XDP is available, 0 otherwise.
 */
WOLFSENTRY_API int wolfsentry_xdp_is_available(void);

#else /* !WOLFSENTRY_HAVE_XDP */

/* Stub implementations when XDP is disabled */
#define wolfsentry_xdp_is_available() 0

#endif /* WOLFSENTRY_HAVE_XDP */

#ifdef __cplusplus
}
#endif

#endif /* WOLFSENTRY_XDP_H */
