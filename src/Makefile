# $Id$

CFLAGS=-Wall -Werror -g
LDFLAGS=-g

all: .depend packet-dump

packet-dump: packet-dump.o packet-parse.o validate.o
	$(CC) $(LDFLAGS) -o packet-dump packet-dump.o packet-parse.o \
		validate.o -lcrypto

clean:
	rm -f packet-dump packet-dump.o packet-parse.o .depend

.depend: *.[ch]
	$(CC) -E -MM *.[ch] > .depend
