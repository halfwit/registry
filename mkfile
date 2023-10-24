# registry mkfile
</$objtype/mkfile

TARG=\
	drop\
	publish\
	query\
	monitor\

DIRS=\
	aux\



LIB=lib.$O.a

HFILES=service.h

BIN=/$objtype/bin/svc

UPDATE=\
	mkfile\
	$HFILES\
	${TARG:%=%.c}\

</sys/src/cmd/mkmany

$LIB:
	cd libservice
	mk

all:V:	all.dirs

install:V:	install.dirs 

update:V:
	update $UPDATEFLAGS $UPDATE
	for (i in libservice $DIRS) @{
		cd $i
		mk 'UPDATEFLAGS='$"UPDATEFLAGS update
	}

&.libservice:V:
	cd libservice
	mk $stem

&.dirs:V:
	for (i in $DIRS) @{
		cd $i
		mk $stem
	}


all.dirs:V: $LIB

clean.dirs:V: clean.libservice

nuke.dirs:V: nuke.libservice

clean:V:
	mk clean.dirs
	rm -f *[$OS] *.[$OS].a [$OS].* TARG

nuke:V:
	mk nuke.dirs
	rm -f *[$OS] *.[$OS].a [$OS].* TARG *.acid

$O.%: $LIB
