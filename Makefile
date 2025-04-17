CFLAGS = -O2 -g -Wall -target bpf # -Werror
CC = clang

all: tcp_in_udp_tc.o
.PHONY: all

%.o: %.c
	${CC} ${CFLAGS} -c $^ -o $@ -MJ compile_commands.json

clean:
	rm -f *.o
