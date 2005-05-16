#
# $Id$
#

# order of build of subdirs is important
#
SUBDIRS=src examples

CONFIGURE=$(PWD)/configure

default: Makefiles all

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

