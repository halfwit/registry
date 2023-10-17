# registry mkfile
</$objtype/mkfile

TARG=\
	drop\
	publish\
	query\
	svcfs

LIB=libservice.a

HFILES=include/service.h

BIN=/$objtype/bin/svc

$LIB:
	cd libservice
	mk

</sys/src/cmd/mkmany
