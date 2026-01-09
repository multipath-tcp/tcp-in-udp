CFLAGS = -O2 -Wall -target bpf # -Werror
CC = clang

ifeq ($(DEBUG),1)
	CFLAGS += -g
endif

all: tcp_in_udp_tc.o
.PHONY: all

%.o: %.c
	${CC} ${CFLAGS} -c $^ -o $@ -MJ compile_commands.json

clean:
	rm -f *.o
