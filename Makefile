ALL=extrace pwait

CFLAGS?=-g -O2 -Wall -Wno-switch -Wextra -Wwrite-strings -pedantic -ansi

DESTDIR=
PREFIX?=/usr/local
BINDIR=$(PREFIX)/bin
MANDIR=$(PREFIX)/share/man

all: $(ALL)

README: extrace.1 pwait.1
	mandoc -Tutf8 $^ | col -bx >$@

cap: $(ALL)
	sudo setcap cap_net_admin+ep extrace cap_net_admin+ep pwait

clean: FRC
	rm -f $(ALL)

install: FRC all
	mkdir -p $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man1
	install -m0755 $(ALL) $(DESTDIR)$(BINDIR)
	install -m0644 $(ALL:=.1) $(DESTDIR)$(MANDIR)/man1

FRC:
