#!/bin/sh
set -e

VMLINUX_BTF="/sys/kernel/btf/vmlinux"
VMLINUX_H="vmlinux.h"

if [ -f "$VMLINUX_H" ]; then
    exit 0
fi

if [ ! -f "$VMLINUX_BTF" ]; then
    echo "Error: BTF not available at $VMLINUX_BTF"
    echo "This kernel does not support BTF."
    exit 1
fi

if ! command -v bpftool >/dev/null 2>&1; then
    echo "Error: bpftool not found."
    echo "Install with: sudo apt install linux-tools-common linux-tools-$(uname -r)"
    exit 1
fi

echo "Generating vmlinux.h from BTF..."
bpftool btf dump file "$VMLINUX_BTF" format c > "$VMLINUX_H"
