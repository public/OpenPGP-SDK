all: top

top:
	cd ../.. && make

headers: packet-show-cast.h

packet-show-cast.h: packet-show.cast ../../util/caster.pl
	../../util/caster.pl packet-show.cast packet-show-cast.h
