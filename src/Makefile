# $Id$

CFLAGS=-Wall -Werror -g
LDFLAGS=-g

all: .depend packet-dump verify

libops.a: packet-parse.o util.o openssl_crypto.o accumulate.o build.o \
	memory.o fingerprint.o hash.o keyring.o signature.o
	ar rc libops.a $>

packet-dump: packet-dump.o libops.a
	$(CC) $(LDFLAGS) -o packet-dump packet-dump.o libops.a -lcrypto

verify: verify.o libops.a
	$(CC) $(LDFLAGS) -o verify verify.o libops.a -lcrypto
clean:
	rm -f packet-dump packet-dump.o packet-parse.o .depend

.depend: *.[ch]
	$(CC) -E -MM *.[ch] > .depend
