#include <u.h>
#include <libc.h>
#include <service.h>
#include <ndb.h>

static void
usage(void)
{
	fprint(2, "usage: %s [-s svcfs] [-d authdom] query\n", argv0);
	exits("usage");
}

void
main(int argc, char *argv[])
{
	char *svcfs;
    char *authdom;
    Ndbtuple *t;
    int fd;

	ARGBEGIN{
	case 's':
		svcfs = EARGF(usage());
		break;
    case 'a':
        authdom = EARGF(usage());
	default:
		usage();
		break;
	}ARGEND
	argv0 = "svcfs";

	if(argc != 1)
		usage();

    fd = svcdial(svcfs, authdom);
    if(svcquery(fd, argv[1], &t) < 0){
        fprint(2, "error in querying registry\n");
        exits("error");
    }
	// Print out our query
    exits(0);
}
