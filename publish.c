#include <u.h>
#include <libc.h>
#include <service.h>

static void
usage(void)
{
	fprint(2, "usage: %s [-s svcfs] [-d authdom] svcname addr [attr value]\n", argv0);
	exits("usage");
}

void
main(int argc, char *argv[])
{
	char *svcfs, *authdom, *ap;
    int i, fd, sfd;

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

	if(argc < 2)
		usage();

    if(strlen(argv[0]) > NAMELEN){
        fprint(2, "Service name too large\n");
        exits("namelen");
    }
    if(strlen(argv[0]) > MAXADDR){
        fprint(2, "Address too long\n");
        exits("address");
    }
    sfd = svcdial(svcfs, authdom);
    if(mount(sfd, -1, "/mnt/services", MREPL, "/") == -1){
        fprint(2, "Error mounting svcfs\n");
        exits("error");
    }

    /* If create fails, try to continue to update values */
    snprint(ap, sizeof ap, "/mnt/services/%s", argv[0]);
    if((fd = create(ap, OREAD, DMDIR|0700)) >= 0)
		close(fd);
    snprint(ap, sizeof ap, "/mnt/services/%s/address", argv[0]);
    if((fd = open(ap, OWRITE)) < 0)
        goto Error;
	if(write(fd, argv[1], MAXADDR) <= 0)
        goto Error;

    /* Description, authdom */
    for(i = 2; i < argc + 1; i++){
        if(strcmp(argv[i], "description") == 0){
            snprint(ap, sizeof ap, "/mnt/services/%s/description", argv[0]);
            if((fd = open(ap, OWRITE|OTRUNC)) < 0)
                goto Error;
            if(write(fd, argv[i+1], MAXDESC) <= 0)
                goto Error;
        } /*else if(strcmp(argv[i], "authdom") == 0){
            snprint(ap, sizeof ap, "/mnt/services/%s/authdom", argv[0]);
            if((fd = open(ap, OWRITE|OTRUNC)) < 0)
                goto Error;
            if(write(fd, argv[i+1], MAXADDR) <= 0)
                goto Error;
        }*/
        i++;
    }
    unmount("", "/mnt/services");
    exits(0);
Error:
    fprint(2, "Error publishing service: %r\n");
    close(sfd);
    exits("error");
}
