#
# $Id$
#

# order of build is important
#
SUBDIRS=src examples

CONFIGURE=$(PWD)/configure

default: Makefiles build

Makefiles:
	@for d in $(SUBDIRS); do \
	(cd $$d; make CONFIGURE=$(CONFIGURE) Makefile); \
	done

all:
	@for d in $(SUBDIRS); do \
	(cd $$d; make all); \
	done

clean:
	@for d in $(SUBDIRS); do \
	(cd $$d; make clean); \
	done

