# $Id$

#DM_FLAGS=-DDMALLOC -I/usr/local/include
DM_FLAGS= -I/usr/local/include
#DM_LIB=/usr/local/lib/libdmalloc.a
DM_LIB=

CFLAGS=-Wall -Werror -g $(DM_FLAGS)
LDFLAGS=-g
LIBS=-lz $(DM_LIB)
#LIBS=/home/ben/software/unpacked/zlib-1.2.2/libz.a $(DM_LIB)

all: .depend packet-dump verify

LIBOBJS = packet-parse.o util.o openssl_crypto.o accumulate.o build.o \
	memory.o fingerprint.o hash.o keyring.o signature.o compress.o

libops.a: $(LIBOBJS)
	ar rc libops.a $(LIBOBJS)

packet-dump: packet-dump.o libops.a
	$(CC) $(LDFLAGS) -o packet-dump packet-dump.o libops.a -lcrypto \
		$(LIBS)

verify: verify.o libops.a
	$(CC) $(LDFLAGS) -o verify verify.o libops.a -lcrypto $(LIBS)

tags:
	rm -f TAGS
	find . -name '*.[ch]' | xargs etags -a

clean:
	rm -f packet-dump verify *.o .depend
	rm -f libops.a TAGS

.depend: *.[ch]
	$(CC) -E -MM *.[ch] > .depend

include .depend
