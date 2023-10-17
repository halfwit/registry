#include <u.h>
#include <libc.h>
#include "include/service.h"

static void
usage(void)
{
	fprint(2, "usage: %s [-s svcfs] [-d authdom] query [attr value]\n", argv0);
	exits("usage");
}

void
search(int fd, char *query, char **argv, int argc)
{
	Ndbtuple *t, *tt;

	tt = svcquery(fd, query, argv, argc);
	for(t = tt; t; t = t->entry)
		print("%s=%s ", t->attr, t->val);
	print("\n");
	ndbfree(tt);
}

void
main(int argc, char *argv[])
{
	char *svcfs, *attr, *value;
	char *authdom;
	int fd;

	svcfs = nil;
	authdom = nil;
	attr = nil;
	value = nil;
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

	if((fd = svcdial(svcfs, authdom)) < 0)
		exits("error");
	search(fd, argv[0], argv+1, argc-1);
	close(fd);
	// Print out our query
	exits(0);
Error:
	fprint(2, "Error with query: %r\n");
	close(fd);
	exits("error");
}
