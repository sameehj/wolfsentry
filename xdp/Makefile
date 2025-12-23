# xdp/Makefile
#
# Build wolfSentry XDP BPF program
#
# Requirements:
#   - clang (10+)
#   - llvm
#   - libbpf-dev
#   - linux-headers

CLANG ?= clang
ARCH := x86

VMLINUX_H := vmlinux.h
BPF_OBJ := wolfsentry_xdp_filter.o

BPF_CFLAGS = -target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-O2 -g -Wall \
	-I.

.PHONY: all clean

all: $(BPF_OBJ)

$(VMLINUX_H):
	./gen_vmlinux.sh

$(BPF_OBJ): wolfsentry_xdp_filter.c wolfsentry_xdp_common.h $(VMLINUX_H)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f *.o $(VMLINUX_H)
