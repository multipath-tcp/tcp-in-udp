CC = clang
TARGET ?= bpfel
CFLAGS = -O2 -Wall -target $(TARGET) # -Werror

ifeq ($(DEBUG),1)
	CFLAGS += -g
endif

ifeq ($(BPF_PRINTK_UNSUPPORTED),1)
	CFLAGS += -DBPF_PRINTK_UNSUPPORTED
endif

all: tcp_in_udp_tc.o
.PHONY: all

%.o: %.c
	${CC} ${CFLAGS} -c $^ -o $@ -MJ compile_commands.json

clean:
	rm -f *.o
