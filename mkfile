# registry mkfile
</$objtype/mkfile

TARG=\
	drop\
	publish\
	query\
	svcfs\
	monitor

LIB=libservice/libservice.a$O

HFILES=libservice/service.h

BIN=/$objtype/bin/svc

$LIB:
	cd libservice
	mk

</sys/src/cmd/mkmany
