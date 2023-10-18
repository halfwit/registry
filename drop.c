#include <u.h>
#include <libc.h>
#include "libservice/service.h"

static void
usage(void)
{
	fprint(2, "usage: %s [-s svcfs] [-d authdom] svcname\n", argv0);
	exits("usage");
}

void
main(int argc, char *argv[])
{
	char *svcfs, *authdom;
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
	if(argc != 1)
		usage();
    	if(strlen(argv[0]) > NAMELEN){
		fprint(2, "Service name too large: %r\n");
		exits("namelen");
	}
	fd = svcdial(svcfs, authdom);
	if(mount(fd, -1, "/mnt/services/", MREPL, "") < 0)
		goto Error;
	if(remove(smprint("/mnt/services/%s", argv[0])) < 0)
		goto Error;
	close(fd);
	unmount(0, "/mnt/services");
	exits(0);
Error:
	fprint(2, "Error removing service: %r\n");
	close(fd);
	exits("error");
}
