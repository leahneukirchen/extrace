CFLAGS=-Wall -pedantic -ansi

all: extrace

cap: extrace
	sudo setcap cap_net_admin+ep extrace

clean:
	rm -f extrace
