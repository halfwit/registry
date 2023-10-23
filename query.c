#include <u.h>
#include <libc.h>
#include "service.h"

static void
usage(void)
{
	fprint(2, "usage: %s [-s svcfs] [-d authdom] query [attr value...]\n", argv0);
	exits("usage");
}

void
search(int fd, char *query, char **argv, int argc)
{
	Service *s, *svcs;

	svcs = svcquery(fd, query, argv, argc);
	for(s = svcs; s; s = s->next){
		print("service=%s address=%s authdom=%s\n", s->name, s->address, s->authdom);
		switch(s->status){
		case Sok:
			print("\tstatus=ok\n");
			break;
		case Sdown:
			print("\tstatus=down\n");
			break;
		case Sreg:
			print("\tstatus=registered\n");
			break;
		}
		print("\tdescription=\'%s\'\n", s->description);
		print("\tuptime=%T\n", s->uptime);
		if(s->next != nil)
			print("\n");
	}
	svcfree(svcs);
}

void
main(int argc, char *argv[])
{
	char *svcfs;
	char *authdom;
	int fd;

	svcfs = nil;
	authdom = nil;
	ARGBEGIN{
	case 's':
		svcfs = EARGF(usage());
		break;
	case 'a':
		authdom = EARGF(usage());
		break;
	default:
		usage();
		break;
	}ARGEND
	argv0 = "svcfs";

	if(argc == 0)
		usage();
	fmtinstall('T', svctimefmt);
	if((fd = svcdial(svcfs, authdom)) < 0)
		exits("error");
	search(fd, argv[0], argv+1, argc-1);
	close(fd);
	exits(0);
}
