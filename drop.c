#include <u.h>
#include <libc.h>
#include <service.h>

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

    if(strlen(argv[0]) > NAMELEN){
        fprint(2, "Service name too large: %r\n");
        exits("namelen");
    }

    fd = svcdial(svcfs, authdom);
    if(mount(fd, -1, "/mnt/services", MAFTER, "") < 0)
        goto Error;
    if(remove(sprintf("/mnt/services/%s", argv[1])) < 0)
        goto Error;
    close(fd);
    unmount("", "/mnt/services");
    exits(0);
Error:
    fprint(2, "Error removing service: %r\n");
    close(fd);
    exits("error");
}
