# $Id$

CFLAGS=-Wall -Werror -g
LDFLAGS=-g

all: .depend packet-dump verify

packet-dump: packet-dump.o packet-parse.o util.o
	$(CC) $(LDFLAGS) -o packet-dump packet-dump.o packet-parse.o \
		util.o -lcrypto

verify: verify.o accumulate.o packet-parse.o util.o
	$(CC) $(LDFLAGS) -o verify verify.o accumulate.o packet-parse.o \
		util.o -lcrypto
clean:
	rm -f packet-dump packet-dump.o packet-parse.o .depend

.depend: *.[ch]
	$(CC) -E -MM *.[ch] > .depend
