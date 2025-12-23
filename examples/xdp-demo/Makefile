CC ?= gcc
AR ?= ar

WOLFSENTRY_PATH ?= ../..
XDP_PATH ?= ../../xdp
WOLFSENTRY_LIB ?= $(WOLFSENTRY_PATH)/libwolfsentry.a

CFLAGS ?= -O2 -g
CFLAGS += -D_GNU_SOURCE
CFLAGS += -Wall -Wextra -Wpedantic -std=c99
CFLAGS += -I.
CFLAGS += -I$(WOLFSENTRY_PATH)
CFLAGS += -I$(WOLFSENTRY_PATH)/wolfsentry
CFLAGS += -DWOLFSENTRY_HAVE_XDP

LDFLAGS ?=
LDFLAGS += -lbpf -lelf -lz -pthread

TARGET := xdp_demo

APP_SRCS := xdp_demo.c
APP_OBJS := $(APP_SRCS:.c=.o)

.PHONY: all clean xdp

all: xdp $(TARGET)

$(TARGET): $(APP_OBJS) $(WOLFSENTRY_LIB)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

$(APP_OBJS): %.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(WOLFSENTRY_LIB):
	$(MAKE) -C $(WOLFSENTRY_PATH) libwolfsentry.a HAVE_XDP=1

xdp:
	$(MAKE) -C $(XDP_PATH)

clean:
	$(RM) $(APP_OBJS) $(TARGET)
	$(MAKE) -C $(XDP_PATH) clean
