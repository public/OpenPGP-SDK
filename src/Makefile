# $Id$

CFLAGS=-Wall -Werror -g
LDFLAGS=-g

all: .depend packet-dump

packet-dump: packet-dump.o packet-parse.o
	$(CC) $(LDFLAGS) -o packet-dump packet-dump.o packet-parse.o -lcrypto

clean:
	rm -f packet-dump packet-dump.o packet-parse.o .depend

.depend: *.[ch]
	$(CC) -E -MM *.[ch] > .depend
