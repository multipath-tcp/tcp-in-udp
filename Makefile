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

clean:
	rm -f *.o
