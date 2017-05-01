CC ?= cc

all:
	${CC} -O2 -Wall -Werror ${CFLAGS} sigtrace.c -o sigtrace

debug:
	${CC} -g -O0 -Wall -Werror ${CFLAGS} sigtrace.c -o sigtrace

clean:
	rm sigtrace
