#include <u.h>
#include <libc.h>
#include "libservice/service.h"

static void
usage(void)
{
	fprint(2, "usage: %s [-s svcfs] [-d authdom] [-p] svcname addr [attr value]\n", argv0);
	exits("usage");
}

void
main(int argc, char *argv[])
{
	char *svcfs, *authdom, ap[NAMELEN];
    	int i, fd, sfd, persist;

	svcfs = nil;
	authdom = nil;
	persist = 0;
	ARGBEGIN{
	case 's':
		svcfs = EARGF(usage());
		break;
    	case 'a':
        	authdom = EARGF(usage());
		break;
	case 'p':
		persist++;
		break;
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
	if((sfd = svcdial(svcfs, authdom)) < 0){
		fprint(2, "Error dialing svcfs: %r\n");
		exits("error");
	}
	if(mount(sfd, -1, "/mnt/services", MREPL|MCREATE, "/") < 0){
		fprint(2, "Error mounting svcfs: %r\n");
        	exits("error");
	}
	/* If create fails, try to continue to update values */
	sprint(ap, "/mnt/services/%s", argv[0]);
	fd = create(ap, OWRITE, DMDIR|0777);
	if(fd < 0)
		goto Error;
	sprint(ap, "/mnt/services/%s/address", argv[0]);
	if((fd = open(ap, OWRITE)) < 0)
		goto Error;
	if(write(fd, argv[1], strlen(argv[1])) < 0)
		goto Error;
	if(persist == 1){
		/* Touch persist */
		sprint(ap, "/mnt/services/%s/persist", argv[0]);
		if((fd = create(ap, OWRITE, 0660)) < 0)
			goto Error;
		close(fd);
	}
	/* Description, authdom */
	if(argc == 2){
		unmount("", "/mnt/services");
		exits(0);
	}
	/* Janky */
	for(i = 2; i < argc; i++){
		if(strcmp("description", argv[i]) == 0){
			sprint(ap, "/mnt/services/%s/description", argv[0]);
			if((fd = open(ap, OWRITE|OTRUNC)) < 0)
				goto Error;
			if(write(fd, argv[i+1], strlen(argv[i+1])) < 0)
				goto Error;
			close(fd);
		} else if (strcmp(argv[i], "authdom") == 0){
			sprint(ap, "/mnt/services/%s/authdom", argv[0]);
			if((fd = open(ap, OWRITE|OTRUNC)) < 0)
				goto Error;
			if(write(fd, argv[i+1], strlen(argv[i+1])) <= 0)
				goto Error;
			close(fd);
		}
		i++;
	}
	unmount("", "/mnt/services");
	exits(0);
Error:
	fprint(2, "Error publishing service: %r\n");
	close(sfd);
	exits("error");
}
