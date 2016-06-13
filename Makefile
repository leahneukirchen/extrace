CFLAGS=-g -O2 -Wall -Wno-switch -Wextra -Wwrite-strings -pedantic -ansi

all: extrace pwait

cap: extrace
	sudo setcap cap_net_admin+ep extrace cap_net_admin+ep pwait

clean:
	rm -f extrace pwait
