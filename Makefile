.PHONY: clean install

LDLIBS=-lpcap
INSTALL=install

prefix=/usr
exec_prefix=$(prefix)
bindir=$(exec_prefix)/bin

salus-pcap:

clean:
	rm -f salus-pcap

install: salus-pcap
	$(INSTALL) -m 755 -D salus-pcap $(DESTDIR)$(bindir)/salus-pcap
