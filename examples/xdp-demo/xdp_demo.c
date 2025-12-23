/* examples/xdp-demo/xdp_demo.c
 *
 * wolfSentry XDP Demo Application
 *
 * Usage: sudo ./xdp_demo <interface> <config.json>
 *
 * Copyright (C) 2024 wolfSSL Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <inttypes.h>

#include <wolfsentry/wolfsentry.h>
#include <wolfsentry/wolfsentry_errcodes.h>
#include <wolfsentry/wolfsentry_json.h>
#include <wolfsentry/wolfsentry_xdp.h>

static volatile int running = 1;

static void signal_handler(int sig)
{
    (void)sig;
    running = 0;
}

static void print_stats(struct wolfsentry_xdp_context *xdp_ctx)
{
    struct wolfsentry_xdp_stats stats;
    wolfsentry_errcode_t ret;

    ret = wolfsentry_xdp_get_stats(xdp_ctx, &stats);
    if (ret < 0) {
        fprintf(stderr, "Failed to get stats\n");
        return;
    }

    printf("\r[XDP Stats] Total: %" PRIu64 " | Passed: %" PRIu64 " | Dropped: %" PRIu64 " | "
           "Expired: %" PRIu64 " | Blocked IPs: %" PRIu64 "   ",
           stats.packets_total,
           stats.packets_passed,
           stats.packets_dropped,
           stats.packets_expired,
           stats.blocklist_entries);
    fflush(stdout);
}

int main(int argc, char *argv[])
{
    struct wolfsentry_context *wolfsentry = NULL;
    struct wolfsentry_xdp_context *xdp_ctx = NULL;
    wolfsentry_errcode_t ret;
    const char *ifname;
    const char *config_path;
    const char *xdp_obj_path;
    FILE *config_file;
    char *config_buf = NULL;
    long config_size;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <interface> <config.json>\n", argv[0]);
        fprintf(stderr, "Example: %s eth0 demo_config.json\n", argv[0]);
        return 1;
    }

    ifname = argv[1];
    config_path = argv[2];

    if (geteuid() != 0) {
        fprintf(stderr, "Error: Must run as root or with CAP_NET_ADMIN\n");
        return 1;
    }

    if (!wolfsentry_xdp_is_available()) {
        fprintf(stderr, "Error: XDP not available on this system\n");
        return 1;
    }

    printf("wolfSentry XDP Demo\n");
    printf("Interface: %s\n", ifname);
    printf("Config: %s\n\n", config_path);

    ret = wolfsentry_init(
        wolfsentry_build_settings,
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(NULL, NULL),
        NULL,
        &wolfsentry);
    if (ret < 0) {
        fprintf(stderr, "wolfsentry_init failed: %d\n", ret);
        return 1;
    }

    config_file = fopen(config_path, "r");
    if (!config_file) {
        fprintf(stderr, "Failed to open config file: %s\n", config_path);
        goto cleanup;
    }

    if (fseek(config_file, 0, SEEK_END) != 0) {
        fclose(config_file);
        fprintf(stderr, "Failed to read config file\n");
        goto cleanup;
    }
    config_size = ftell(config_file);
    if (config_size < 0) {
        fclose(config_file);
        fprintf(stderr, "Failed to read config file size\n");
        goto cleanup;
    }
    if (fseek(config_file, 0, SEEK_SET) != 0) {
        fclose(config_file);
        fprintf(stderr, "Failed to rewind config file\n");
        goto cleanup;
    }

    config_buf = malloc((size_t)config_size + 1);
    if (!config_buf) {
        fclose(config_file);
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }

    if (fread(config_buf, 1, (size_t)config_size, config_file) != (size_t)config_size) {
        fclose(config_file);
        fprintf(stderr, "Failed to read config file\n");
        goto cleanup;
    }
    config_buf[config_size] = '\0';
    fclose(config_file);

    ret = wolfsentry_config_json_oneshot(
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(wolfsentry, NULL),
        (const unsigned char *)config_buf,
        (size_t)config_size,
        WOLFSENTRY_CONFIG_LOAD_FLAG_NONE,
        NULL,
        0);
    free(config_buf);
    config_buf = NULL;

    if (ret < 0) {
        fprintf(stderr, "Failed to load config: %d\n", ret);
#ifdef WOLFSENTRY_ERROR_STRINGS
        fprintf(stderr, "wolfSentry error: " WOLFSENTRY_ERROR_FMT "\n",
            WOLFSENTRY_ERROR_FMT_ARGS(ret));
#endif
        goto cleanup;
    }

    printf("Configuration loaded successfully\n");

    xdp_obj_path = getenv("WOLFSENTRY_XDP_OBJ");
    if (!xdp_obj_path || xdp_obj_path[0] == '\0') {
        if (access("xdp/wolfsentry_xdp_filter.o", R_OK) == 0)
            xdp_obj_path = "xdp/wolfsentry_xdp_filter.o";
        else if (access("../../xdp/wolfsentry_xdp_filter.o", R_OK) == 0)
            xdp_obj_path = "../../xdp/wolfsentry_xdp_filter.o";
        else
            xdp_obj_path = "../../xdp/wolfsentry_xdp_filter.o";
    }

    ret = wolfsentry_xdp_init(
        wolfsentry,
        ifname,
        xdp_obj_path,
        WOLFSENTRY_XDP_FLAG_NONE,
        &xdp_ctx);
    if (ret < 0) {
        fprintf(stderr, "wolfsentry_xdp_init failed: %d\n", ret);
        fprintf(stderr, "Hint: Ensure XDP program is compiled and interface exists\n");
        goto cleanup;
    }

    printf("XDP program attached to %s\n", ifname);

    ret = wolfsentry_xdp_sync(wolfsentry, xdp_ctx);
    if (ret < 0) {
        fprintf(stderr, "wolfsentry_xdp_sync failed: %d\n", ret);
        goto cleanup;
    }

    printf("State synchronized to XDP\n");

    ret = wolfsentry_xdp_register_auto_sync(wolfsentry, xdp_ctx);
    if (ret < 0) {
        fprintf(stderr, "Warning: Auto-sync registration failed: %d\n", ret);
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("\nRunning... Press Ctrl+C to exit\n\n");

    while (running) {
        print_stats(xdp_ctx);
        sleep(1);
    }

    printf("\n\nShutting down...\n");

cleanup:
    if (config_buf) {
        free(config_buf);
    }
    if (xdp_ctx) {
        wolfsentry_xdp_shutdown(xdp_ctx);
        printf("XDP detached\n");
    }

    if (wolfsentry) {
        wolfsentry_shutdown(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(&wolfsentry, NULL));
    }

    return 0;
}
