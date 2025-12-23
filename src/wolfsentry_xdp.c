/* src/wolfsentry_xdp.c
 *
 * wolfSentry XDP Integration Implementation
 *
 * Copyright (C) 2024 wolfSSL Inc.
 */

#include "wolfsentry/wolfsentry.h"
#include "wolfsentry/wolfsentry_xdp.h"

#ifdef WOLFSENTRY_HAVE_XDP

#include "wolfsentry_internal.h"

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_WOLFSENTRY_XDP_C

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <net/if.h>
#include <limits.h>

#ifndef __linux__

WOLFSENTRY_API int wolfsentry_xdp_is_available(void)
{
    return 0;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_xdp_init(
    struct wolfsentry_context *wolfsentry,
    const char *ifname,
    const char *xdp_prog_path,
    wolfsentry_xdp_flags_t flags,
    struct wolfsentry_xdp_context **xdp_ctx_out)
{
    (void)wolfsentry;
    (void)ifname;
    (void)xdp_prog_path;
    (void)flags;
    (void)xdp_ctx_out;
    return WOLFSENTRY_ERROR_ENCODE(IMPLEMENTATION_MISSING);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_xdp_shutdown(
    struct wolfsentry_xdp_context *xdp_ctx)
{
    (void)xdp_ctx;
    return WOLFSENTRY_ERROR_ENCODE(IMPLEMENTATION_MISSING);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_xdp_sync(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_xdp_context *xdp_ctx)
{
    (void)wolfsentry;
    (void)xdp_ctx;
    return WOLFSENTRY_ERROR_ENCODE(IMPLEMENTATION_MISSING);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_xdp_block_ip(
    struct wolfsentry_xdp_context *xdp_ctx,
    uint32_t ipv4_addr,
    uint32_t block_duration_s)
{
    (void)xdp_ctx;
    (void)ipv4_addr;
    (void)block_duration_s;
    return WOLFSENTRY_ERROR_ENCODE(IMPLEMENTATION_MISSING);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_xdp_unblock_ip(
    struct wolfsentry_xdp_context *xdp_ctx,
    uint32_t ipv4_addr)
{
    (void)xdp_ctx;
    (void)ipv4_addr;
    return WOLFSENTRY_ERROR_ENCODE(IMPLEMENTATION_MISSING);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_xdp_get_stats(
    struct wolfsentry_xdp_context *xdp_ctx,
    struct wolfsentry_xdp_stats *stats_out)
{
    (void)xdp_ctx;
    (void)stats_out;
    return WOLFSENTRY_ERROR_ENCODE(IMPLEMENTATION_MISSING);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_xdp_register_auto_sync(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_xdp_context *xdp_ctx)
{
    (void)wolfsentry;
    (void)xdp_ctx;
    return WOLFSENTRY_ERROR_ENCODE(IMPLEMENTATION_MISSING);
}

#else /* __linux__ */

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>

#include "xdp/wolfsentry_xdp_common.h"

struct bpf_xdp_attach_opts;

#ifndef LIBBPF_MAJOR_VERSION
#define WOLFSENTRY_LIBBPF_HAS_XDP_ATTACH 0
#elif (LIBBPF_MAJOR_VERSION > 0) || (LIBBPF_MAJOR_VERSION == 0 && LIBBPF_MINOR_VERSION >= 7)
#define WOLFSENTRY_LIBBPF_HAS_XDP_ATTACH 1
#else
#define WOLFSENTRY_LIBBPF_HAS_XDP_ATTACH 0
#endif

#if !WOLFSENTRY_LIBBPF_HAS_XDP_ATTACH
static inline int bpf_xdp_attach(int ifindex, int prog_fd, uint32_t flags,
    const struct bpf_xdp_attach_opts *opts)
{
    (void)opts;
    return bpf_set_link_xdp_fd(ifindex, prog_fd, flags);
}

static inline int bpf_xdp_detach(int ifindex, uint32_t flags,
    const struct bpf_xdp_attach_opts *opts)
{
    (void)opts;
    return bpf_set_link_xdp_fd(ifindex, -1, flags);
}
#endif

/* Internal XDP context structure */
struct wolfsentry_xdp_context {
    struct wolfsentry_context *wolfsentry;  /* Back-reference */
    struct bpf_object *bpf_obj;             /* Loaded BPF object */
    int prog_fd;                            /* XDP program FD */
    int blocklist_fd;                       /* Blocklist map FD */
    int stats_fd;                           /* Stats map FD */
    int ifindex;                            /* Attached interface index */
    char ifname[IF_NAMESIZE];               /* Interface name */
    uint32_t xdp_flags;                     /* XDP attach flags */
};

/* Helper: Get current time in nanoseconds */
static uint64_t get_time_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

WOLFSENTRY_API int wolfsentry_xdp_is_available(void)
{
    if (access("/sys/fs/bpf", F_OK) == 0)
        return 1;
    if (errno == EACCES)
        return 1;
    return 0;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_xdp_init(
    struct wolfsentry_context *wolfsentry,
    const char *ifname,
    const char *xdp_prog_path,
    wolfsentry_xdp_flags_t flags,
    struct wolfsentry_xdp_context **xdp_ctx_out)
{
    struct wolfsentry_thread_context *thread = NULL;
    struct wolfsentry_xdp_context *ctx;
    struct bpf_program *prog;
    unsigned int ifindex_u;

    if (!wolfsentry || !ifname || !xdp_prog_path || !xdp_ctx_out)
        return WOLFSENTRY_ERROR_ENCODE(INVALID_ARG);

    ctx = WOLFSENTRY_MALLOC(sizeof(*ctx));
    if (!ctx)
        return WOLFSENTRY_ERROR_ENCODE(SYS_RESOURCE_FAILED);
    memset(ctx, 0, sizeof(*ctx));

    ctx->wolfsentry = wolfsentry;
    strncpy(ctx->ifname, ifname, sizeof(ctx->ifname) - 1);
    ctx->ifname[sizeof(ctx->ifname) - 1] = '\0';

    ifindex_u = if_nametoindex(ifname);
    if (ifindex_u == 0) {
        WOLFSENTRY_FREE(ctx);
        return WOLFSENTRY_ERROR_ENCODE(ITEM_NOT_FOUND);
    }
    if (ifindex_u > INT_MAX) {
        WOLFSENTRY_FREE(ctx);
        return WOLFSENTRY_ERROR_ENCODE(NUMERIC_ARG_TOO_BIG);
    }
    ctx->ifindex = (int)ifindex_u;

    ctx->bpf_obj = bpf_object__open_file(xdp_prog_path, NULL);
    if (libbpf_get_error(ctx->bpf_obj)) {
        WOLFSENTRY_FREE(ctx);
        return WOLFSENTRY_ERROR_ENCODE(CONFIG_INVALID_VALUE);
    }

    if (bpf_object__load(ctx->bpf_obj) != 0) {
        bpf_object__close(ctx->bpf_obj);
        WOLFSENTRY_FREE(ctx);
        return WOLFSENTRY_ERROR_ENCODE(SYS_OP_FAILED);
    }

    prog = bpf_object__find_program_by_name(ctx->bpf_obj, "wolfsentry_xdp_filter");
    if (!prog) {
        bpf_object__close(ctx->bpf_obj);
        WOLFSENTRY_FREE(ctx);
        return WOLFSENTRY_ERROR_ENCODE(ITEM_NOT_FOUND);
    }
    ctx->prog_fd = bpf_program__fd(prog);

    ctx->blocklist_fd = bpf_object__find_map_fd_by_name(ctx->bpf_obj, WS_XDP_MAP_BLOCKLIST);
    ctx->stats_fd = bpf_object__find_map_fd_by_name(ctx->bpf_obj, WS_XDP_MAP_STATS);
    if (ctx->blocklist_fd < 0 || ctx->stats_fd < 0) {
        bpf_object__close(ctx->bpf_obj);
        WOLFSENTRY_FREE(ctx);
        return WOLFSENTRY_ERROR_ENCODE(ITEM_NOT_FOUND);
    }

    ctx->xdp_flags = 0;
    if (flags & WOLFSENTRY_XDP_FLAG_SKB_MODE)
        ctx->xdp_flags |= XDP_FLAGS_SKB_MODE;
    else if (flags & WOLFSENTRY_XDP_FLAG_DRV_MODE)
        ctx->xdp_flags |= XDP_FLAGS_DRV_MODE;
    else if (flags & WOLFSENTRY_XDP_FLAG_HW_MODE)
        ctx->xdp_flags |= XDP_FLAGS_HW_MODE;

    if (!(flags & WOLFSENTRY_XDP_FLAG_UPDATE_IF_SET))
        ctx->xdp_flags |= XDP_FLAGS_UPDATE_IF_NOEXIST;

    if (bpf_xdp_attach(ctx->ifindex, ctx->prog_fd, ctx->xdp_flags, NULL) != 0) {
        bpf_object__close(ctx->bpf_obj);
        WOLFSENTRY_FREE(ctx);
        return WOLFSENTRY_ERROR_ENCODE(SYS_OP_FAILED);
    }

    *xdp_ctx_out = ctx;
    return WOLFSENTRY_SUCCESS_ENCODE(OK);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_xdp_shutdown(
    struct wolfsentry_xdp_context *xdp_ctx)
{
    struct wolfsentry_thread_context *thread = NULL;
    struct wolfsentry_context *wolfsentry;

    if (!xdp_ctx)
        return WOLFSENTRY_ERROR_ENCODE(INVALID_ARG);

    bpf_xdp_detach(xdp_ctx->ifindex, xdp_ctx->xdp_flags, NULL);

    if (xdp_ctx->bpf_obj)
        bpf_object__close(xdp_ctx->bpf_obj);

    wolfsentry = xdp_ctx->wolfsentry;
    if (wolfsentry)
        WOLFSENTRY_FREE(xdp_ctx);
    else
        free(xdp_ctx);
    return WOLFSENTRY_SUCCESS_ENCODE(OK);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_xdp_block_ip(
    struct wolfsentry_xdp_context *xdp_ctx,
    uint32_t ipv4_addr,
    uint32_t block_duration_s)
{
    struct ws_xdp_block_entry entry;

    if (!xdp_ctx)
        return WOLFSENTRY_ERROR_ENCODE(INVALID_ARG);

    memset(&entry, 0, sizeof(entry));
    if (block_duration_s == 0) {
        entry.flags = WS_XDP_FLAG_PERMANENT;
        entry.blocked_until_ns = 0;
    } else {
        entry.blocked_until_ns = get_time_ns() +
            ((uint64_t)block_duration_s * 1000000000ULL);
    }

    if (bpf_map_update_elem(xdp_ctx->blocklist_fd, &ipv4_addr, &entry, BPF_ANY) != 0)
        return WOLFSENTRY_ERROR_ENCODE(SYS_OP_FAILED);

    return WOLFSENTRY_SUCCESS_ENCODE(OK);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_xdp_unblock_ip(
    struct wolfsentry_xdp_context *xdp_ctx,
    uint32_t ipv4_addr)
{
    if (!xdp_ctx)
        return WOLFSENTRY_ERROR_ENCODE(INVALID_ARG);

    if (bpf_map_delete_elem(xdp_ctx->blocklist_fd, &ipv4_addr) != 0 && errno != ENOENT)
        return WOLFSENTRY_ERROR_ENCODE(SYS_OP_FAILED);

    return WOLFSENTRY_SUCCESS_ENCODE(OK);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_xdp_get_stats(
    struct wolfsentry_xdp_context *xdp_ctx,
    struct wolfsentry_xdp_stats *stats_out)
{
    struct ws_xdp_stats *percpu_stats;
    uint32_t key = WS_XDP_STATS_KEY_GLOBAL;
    uint32_t map_key;
    uint32_t next_key;
    int num_cpus;
    int i;

    if (!xdp_ctx || !stats_out)
        return WOLFSENTRY_ERROR_ENCODE(INVALID_ARG);

    memset(stats_out, 0, sizeof(*stats_out));

    num_cpus = libbpf_num_possible_cpus();
    if (num_cpus <= 0)
        return WOLFSENTRY_ERROR_ENCODE(SYS_OP_FAILED);

    percpu_stats = calloc((size_t)num_cpus, sizeof(*percpu_stats));
    if (!percpu_stats)
        return WOLFSENTRY_ERROR_ENCODE(SYS_RESOURCE_FAILED);

    if (bpf_map_lookup_elem(xdp_ctx->stats_fd, &key, percpu_stats) != 0) {
        free(percpu_stats);
        return WOLFSENTRY_ERROR_ENCODE(SYS_OP_FAILED);
    }

    for (i = 0; i < num_cpus; i++) {
        stats_out->packets_total += percpu_stats[i].packets_total;
        stats_out->packets_passed += percpu_stats[i].packets_passed;
        stats_out->packets_dropped += percpu_stats[i].packets_dropped;
        stats_out->packets_expired += percpu_stats[i].packets_expired;
    }
    free(percpu_stats);

    if (bpf_map_get_next_key(xdp_ctx->blocklist_fd, NULL, &map_key) == 0) {
        for (;;) {
            stats_out->blocklist_entries++;
            if (bpf_map_get_next_key(xdp_ctx->blocklist_fd, &map_key, &next_key) != 0)
                break;
            map_key = next_key;
        }
    }

    return WOLFSENTRY_SUCCESS_ENCODE(OK);
}

static wolfsentry_errcode_t xdp_sync_route_callback(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_route *route,
    void *xdp_ctx_void)
{
    struct wolfsentry_thread_context *thread = NULL;
    struct wolfsentry_xdp_context *xdp_ctx = xdp_ctx_void;
    struct wolfsentry_route_exports exports;
    struct ws_xdp_block_entry entry;
    uint32_t ipv4_addr;
    int ret;

    ret = wolfsentry_route_export(WOLFSENTRY_CONTEXT_ARGS_OUT, route, &exports);
    if (ret < 0)
        return ret;

    if (exports.sa_family != WOLFSENTRY_AF_INET)
        return WOLFSENTRY_SUCCESS_ENCODE(OK);

    if (!(exports.flags & WOLFSENTRY_ROUTE_FLAG_PENALTYBOXED))
        return WOLFSENTRY_SUCCESS_ENCODE(OK);

    if (exports.remote.addr_len != 32 || exports.remote_address == NULL)
        return WOLFSENTRY_SUCCESS_ENCODE(OK);

    memcpy(&ipv4_addr, exports.remote_address, sizeof(ipv4_addr));

    memset(&entry, 0, sizeof(entry));
    entry.flags = WS_XDP_FLAG_PERMANENT;
    entry.blocked_until_ns = 0;

    if (bpf_map_update_elem(xdp_ctx->blocklist_fd, &ipv4_addr, &entry, BPF_ANY) != 0)
        return WOLFSENTRY_ERROR_ENCODE(SYS_OP_FAILED);

    return WOLFSENTRY_SUCCESS_ENCODE(OK);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_xdp_sync(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_xdp_context *xdp_ctx)
{
    struct wolfsentry_thread_context *thread = NULL;
    struct wolfsentry_cursor *cursor = NULL;
    struct wolfsentry_route *route = NULL;
    uint32_t map_key;
    int ret;

    if (!wolfsentry || !xdp_ctx)
        return WOLFSENTRY_ERROR_ENCODE(INVALID_ARG);

    if (!wolfsentry->routes)
        return WOLFSENTRY_ERROR_ENCODE(ITEM_NOT_FOUND);

    if (bpf_map_get_next_key(xdp_ctx->blocklist_fd, NULL, &map_key) == 0) {
        for (;;) {
            bpf_map_delete_elem(xdp_ctx->blocklist_fd, &map_key);
            if (bpf_map_get_next_key(xdp_ctx->blocklist_fd, NULL, &map_key) != 0)
                break;
        }
    }

    WOLFSENTRY_SHARED_OR_RETURN();
    ret = wolfsentry_route_table_iterate_start(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        wolfsentry->routes,
        &cursor);
    if (ret < 0) {
        WOLFSENTRY_UNLOCK_FOR_RETURN();
        return ret;
    }

    for (ret = wolfsentry_route_table_iterate_current(wolfsentry->routes, cursor, &route);
         ret >= 0;
         ret = wolfsentry_route_table_iterate_next(wolfsentry->routes, cursor, &route)) {
        ret = xdp_sync_route_callback(wolfsentry, route, xdp_ctx);
        if (ret < 0)
            break;
    }

    if (ret < 0 && WOLFSENTRY_ERROR_CODE_IS(ret, ITEM_NOT_FOUND))
        ret = WOLFSENTRY_SUCCESS_ENCODE(OK);

    {
        int end_ret = wolfsentry_route_table_iterate_end(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            wolfsentry->routes,
            &cursor);
        if (ret >= 0 && end_ret < 0)
            ret = end_ret;
    }

    WOLFSENTRY_UNLOCK_FOR_RETURN();
    return ret;
}

static wolfsentry_errcode_t xdp_auto_sync_action(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const struct wolfsentry_action *action,
    void *handler_arg,
    void *caller_arg,
    const struct wolfsentry_event *trigger_event,
    wolfsentry_action_type_t action_type,
    const struct wolfsentry_route *trigger_route,
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *rule_route,
    wolfsentry_action_res_t *action_results)
{
    struct wolfsentry_xdp_context *xdp_ctx = handler_arg;

#ifdef WOLFSENTRY_THREADSAFE
    (void)thread;
#endif
    (void)action;
    (void)caller_arg;
    (void)trigger_event;
    (void)action_type;
    (void)trigger_route;
    (void)route_table;
    (void)rule_route;
    (void)action_results;

    return wolfsentry_xdp_sync(wolfsentry, xdp_ctx);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_xdp_register_auto_sync(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_xdp_context *xdp_ctx)
{
    struct wolfsentry_thread_context *thread = NULL;
    wolfsentry_errcode_t ret;

    if (!wolfsentry || !xdp_ctx)
        return WOLFSENTRY_ERROR_ENCODE(INVALID_ARG);

    ret = wolfsentry_action_insert(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        "xdp-sync",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        WOLFSENTRY_ACTION_FLAG_NONE,
        xdp_auto_sync_action,
        xdp_ctx,
        NULL);
    if (ret < 0)
        return ret;

    return WOLFSENTRY_SUCCESS_ENCODE(OK);
}

#endif /* __linux__ */

#endif /* WOLFSENTRY_HAVE_XDP */
