# registry mkfile
</$objtype/mkfile

TARG =	\
	registry\
	regquery\

HFILES = dns.h /$objtype/lib/libndb.a

BIN=/$objtype/bin/ndb

</sys/src/cmd/mkmany

$O.registry: registry.$O reglookup.$O
	$LD -o $target $prereq

