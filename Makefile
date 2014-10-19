CFLAGS=-Wall -pedantic -ansi

all: extrace pwait

cap: extrace
	sudo setcap cap_net_admin+ep extrace cap_net_admin+ep pwait

clean:
	rm -f extrace pwait
