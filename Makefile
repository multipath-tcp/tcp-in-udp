# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025 Matthieu Baerts <matttbe@kernel.org>
# Copyright (C) 2025-2026 Chester A. Unal <chester.a.unal@arinc9.com>

CC = clang
TARGET ?= bpf
CFLAGS := $(CFLAGS) -O2 -Wall

ifeq ($(DEBUG),1)
	CFLAGS += -g
endif

ifeq ($(BPF_PRINTK_UNSUPPORTED),1)
	CFLAGS += -DBPF_PRINTK_UNSUPPORTED
endif

all: tcp_in_udp_tc.o
.PHONY: all

%.o: %.c
	${CC} ${CFLAGS} -target $(TARGET) -c $^ -o $@ -MJ compile_commands.json

install: tcp_in_udp_tc.o
	install -D tcp_in_udp_tc.o $(DESTDIR)/usr/lib/bpf/tcp_in_udp_tc.o
.PHONY: install

uninstall:
	rm -f $(DESTDIR)/usr/lib/bpf/tcp_in_udp_tc.o
.PHONY: uninstall

clean:
	rm -f *.o
