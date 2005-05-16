#
# $Id$
#

# order of build of subdirs is important
#
SUBDIRS=src examples

all: default include/configure.h

default:
	@for d in $(SUBDIRS); do \
	(cd $$d; echo "+++ make in $$d"; make; echo "--- $$d"); \
	done

include/configure.h: include/configure.h.template configure
	echo re-run configure

force_depend:
	@for d in $(SUBDIRS); do \
	(cd $$d; echo "+++ make force_depend in $$d"; make force_depend ; echo "--- $$d"); \
	done

clean:
	@for d in $(SUBDIRS); do \
	(cd $$d; echo "+++ make clean in $$d"; make clean; echo "--- $$d"); \
	done

